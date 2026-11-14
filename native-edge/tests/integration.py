#!/usr/bin/env python3
"""Real nginx workers, background config scans and immutable in-memory updates."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import datetime
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import tempfile
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def certificate(directory, label, hosts):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hosts[0])])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(hours=1)).not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(h) for h in hosts]), critical=False)
        .sign(key, hashes.SHA256()))
    chain = cert.public_bytes(serialization.Encoding.PEM)
    private = key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
    (directory/(label+'.crt')).write_bytes(chain)
    path=directory/(label+'.key');path.write_bytes(private);path.chmod(0o600)
    return cert.fingerprint(hashes.SHA256()).hex(),chain,private


class Origin(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def do_GET(self):
        if self.path.startswith('/slow'):
            time.sleep(1.2)
        body=(self.server.label+':'+self.path).encode()
        self.send_response(200)
        self.send_header('Content-Length',str(len(body)))
        self.send_header('Cache-Control','public,max-age=60')
        self.send_header('ETag','"native-test-object"')
        self.end_headers()
        self.wfile.write(body)

    def log_message(self,*args):
        pass


class OriginServer(http.server.ThreadingHTTPServer):
    request_queue_size = 128
    daemon_threads = True


class Review:
    def __init__(self,root,prefix):
        self.root,self.prefix=root,prefix
        self.nginx=prefix/'sbin/nginx'
        self.http,self.tls=port(),port()
        self.socket=root/'control.sock'
        self.process,self.log=None,None
        self.origins,self.checks=[],[]
        for label in ('a','b'):
            server=OriginServer(('127.0.0.1',0),Origin)
            server.label=label;self.origins.append(server)
            threading.Thread(target=server.serve_forever,daemon=True).start()
        self.cert_a,_,_=certificate(root,'site',['www.example.com','alias.example.com'])
        self.cert_b,self.chain_b,self.key_b=certificate(root,'rotated',['www.example.com','alias.example.com'])
        (root/'html').mkdir();(root/'html/asset.txt').write_text('native-static')
        self.source=root/'sites.conf'
        self.set_source(self.sites())

    def check(self,name,value):
        if not value:raise AssertionError(name)
        self.checks.append(name);print('PASS '+name,flush=True)

    def sites(self,origin=0,enabled='on',alias=True,extra='',cache='off'):
        return f'''sites {{
site alpha {{
    host www.example.com;
    {'host alias.example.com;' if alias else ''}
    enabled {enabled};
    upstream http://127.0.0.1:{self.origins[origin].server_port};
    cache {cache};
    tier 3 1000;
    certificate {self.root}/site.crt;
    certificate_key {self.root}/site.key;
    prefix /api/ {{ upstream http://127.0.0.1:{self.origins[1].server_port}; cache off; }}
    prefix /api/special/ {{ upstream http://127.0.0.1:{self.origins[0].server_port}; cache off; }}
}}
site static {{ host static.example.com; root {self.root}/html; cache off; }}
{extra}
}}
'''

    def set_source(self,content,atomic=True):
        if atomic:
            staging=self.root/'sites.next';staging.write_text(content);staging.replace(self.source)
        else:self.source.write_text(content)

    def config(self):
        user='user root root;' if os.geteuid()==0 else ''
        return f'''load_module {self.prefix}/modules/ngx_http_scdn_config_module.so;
load_module {self.prefix}/modules/ngx_http_scdn_edge_module.so;
{user}
worker_processes 2;
thread_pool scdn_config_reader threads=1 max_queue=2;
pid {self.root}/nginx.pid;
error_log {self.root}/error.log warn;
events {{ worker_connections 256; }}
http {{
    access_log off;
    scdn_config_zone configurations 128k;
    scdn_config_watch {self.source};
    scdn_config_interval 100ms;
    scdn_config_settle 300ms;
    scdn_edge_zone counters 2m;
    proxy_cache_path {self.root}/cache1 keys_zone=l1:1m;
    proxy_cache_path {self.root}/cache2 keys_zone=l2:1m;
    server {{ listen unix:{self.socket};
        location = /status {{ scdn_config_status; }}
        location = /metrics {{ scdn_edge_metrics; }}
    }}
    server {{
        listen 127.0.0.1:{self.http}; listen 127.0.0.1:{self.tls} ssl;
        server_name _;
        ssl_certificate {self.root}/rotated.crt;
        ssl_certificate_key {self.root}/rotated.key;
        ssl_session_cache off; ssl_session_tickets off;
        scdn_edge on; scdn_edge_tls on;
        add_header X-Site $scdn_edge_site always;
        add_header X-Revision $scdn_edge_revision always;
        add_header X-Layer $scdn_edge_cache always;
        add_header X-Cache $upstream_cache_status always;
        location / {{ root $scdn_edge_root; disable_symlinks on; }}
        location @scdn_edge_proxy {{
            proxy_pass $scdn_edge_upstream;
            proxy_cache $scdn_edge_cache;
            proxy_cache_key "$scdn_edge_revision|$host|$request_uri";
            proxy_cache_valid 200 1m;
            proxy_connect_timeout 1s; proxy_read_timeout 4s;
        }}
    }}
}}
'''

    def request(self,path='/asset',host='www.example.com',tls=False,connection=None):
        fingerprint=None
        own=connection is None
        if own:
            connection=http.client.HTTPConnection('127.0.0.1',self.tls if tls else self.http,timeout=4)
            if tls:
                raw=socket.create_connection(('127.0.0.1',self.tls),timeout=4)
                connection.sock=ssl._create_unverified_context().wrap_socket(raw,server_hostname=host)
                fingerprint=hashlib.sha256(connection.sock.getpeercert(binary_form=True)).hexdigest()
        try:
            connection.request('GET',path,headers={'Host':host})
            response=connection.getresponse()
            return response.status,dict(response.getheaders()),response.read(),fingerprint
        finally:
            if own:connection.close()

    def control(self,path='/status'):
        connection=http.client.HTTPConnection('localhost',timeout=3)
        connection.sock=socket.socket(socket.AF_UNIX);connection.sock.settimeout(3)
        connection.sock.connect(str(self.socket))
        try:
            connection.request('GET',path)
            response=connection.getresponse();body=response.read()
            if response.status!=200:raise AssertionError((response.status,body))
            return json.loads(body) if path=='/status' else body.decode()
        finally:connection.close()

    def until(self,fn,description,timeout=10):
        end=time.monotonic()+timeout
        while time.monotonic()<end:
            if self.process and self.process.poll() is not None:raise AssertionError('nginx exited')
            try:
                value=fn()
                if value:return value
            except (OSError,http.client.HTTPException,KeyError):pass
            time.sleep(0.05)
        raise AssertionError('deadline: '+description)

    def workers(self):
        text=Path(f'/proc/{self.process.pid}/task/{self.process.pid}/children').read_text()
        return {int(pid) for pid in text.split()
                if Path(f'/proc/{pid}/cmdline').exists()
                and b'nginx: worker process' in Path(f'/proc/{pid}/cmdline').read_bytes()}

    def generation(self):return self.control()['generation']

    def wait_change(self,previous):
        return self.until(lambda:self.control()['generation']>previous,'configuration switch')

    def run(self):
        path=self.root/'nginx.conf';path.write_text(self.config())
        valid=self.sites()
        invalid={
            'missing outer commit boundary':valid.rsplit('}',1)[0],
            'unknown site field':valid.replace('cache off;', 'waf on;',1),
            'duplicate host':valid.replace('host alias.example.com;', 'host www.example.com;'),
            'invalid upstream':valid.replace('http://127.0.0.1:', 'https://127.0.0.1:'),
            'invalid private key path':valid.replace('/site.key;', '/missing.key;'),
            'duplicate site ID':valid.replace('site static {','site alpha {'),
            'empty initial configuration':'sites { }',
        }
        for name,content in invalid.items():
            self.set_source(content)
            checked=subprocess.run([str(self.nginx),'-t','-p',str(self.root)+'/', '-c',str(path)],capture_output=True,text=True)
            self.check('bootstrap rejects '+name,checked.returncode==1
                       and 'ERROR: AddressSanitizer' not in checked.stderr
                       and 'runtime error:' not in checked.stderr)
        for cut in range(1,len(valid)-2,31):
            self.set_source(valid[:cut])
            checked=subprocess.run([str(self.nginx),'-t','-p',str(self.root)+'/', '-c',str(path)],capture_output=True,text=True)
            if (checked.returncode!=1 or 'ERROR: AddressSanitizer' in checked.stderr
                    or 'runtime error:' in checked.stderr):
                raise AssertionError(('truncated parser input',cut,checked.returncode,checked.stderr))
        self.check('truncated snapshot corpus is rejected without crashes',True)
        self.set_source(valid)
        result=subprocess.run([str(self.nginx),'-t','-p',str(self.root)+'/', '-c',str(path)],capture_output=True,text=True)
        self.check('native nginx configuration validates',result.returncode==0)
        if result.returncode:raise AssertionError(result.stderr)
        self.log=(self.root/'stdout.log').open('wb')
        self.process=subprocess.Popen([str(self.nginx),'-p',str(self.root)+'/', '-c',str(path),'-g','daemon off;'],stdout=self.log,stderr=self.log)
        self.until(lambda:self.control(),'startup')
        initial_workers=self.workers()
        self.check('two real workers started',len(initial_workers)==2)
        self.check('HTTP route resolves from the watched source',self.request()[2]==b'a:/asset')
        self.check('alias host resolves',self.request(host='alias.example.com')[0]==200)
        self.check('unknown host is rejected',self.request(host='unknown.example.com')[0]==403)
        self.check('static files use native nginx',self.request('/asset.txt',host='static.example.com')[2]==b'native-static')
        self.check('longest prefix is selected',self.request('/api/special/item')[2]==b'a:/api/special/item')
        self.check('other prefix selects the other upstream',self.request('/api/item')[2]==b'b:/api/item')
        self.check('query and URI are preserved',self.request('/api/item?a=1')[2]==b'b:/api/item?a=1')
        self.check('TLS uses preloaded site certificate',self.request(tls=True)[3]==self.cert_a)
        try:
            self.request(tls=True,host='unknown.example.com');rejected=False
        except (ssl.SSLError,OSError,http.client.HTTPException):rejected=True
        self.check('unknown SNI is rejected',rejected)
        self.check('SQL-shaped input is proxied without a bundled WAF',self.request('/asset?union=select')[0]==200)
        with ThreadPoolExecutor(max_workers=8) as pool:
            statuses=list(pool.map(lambda _:self.request()[0],range(24)))
        self.check('module imposes no request rate limit',all(status==200 for status in statuses))
        connection=http.client.HTTPConnection('127.0.0.1',self.tls,timeout=4)
        raw=socket.create_connection(('127.0.0.1',self.tls),timeout=4)
        connection.sock=ssl._create_unverified_context().wrap_socket(raw,server_hostname='www.example.com')
        self.request(connection=connection)
        try:
            with ThreadPoolExecutor(max_workers=1) as pool:
                pending=pool.submit(self.request,'/slow')
                time.sleep(0.15)
                before=self.generation();self.set_source(self.sites(origin=1));self.wait_change(before)
                self.check('in-flight request keeps the old route',pending.result()[2]==b'a:/slow')
            self.check('new requests use the new route',self.request()[2]==b'b:/asset')
            self.check('existing TLS connection survives the update',self.request(connection=connection)[2]==b'b:/asset')
        finally:connection.close()
        self.check('route update keeps worker PIDs',self.workers()==initial_workers)
        previous=self.control();self.set_source('sites { site broken { host www.example.com;',atomic=False)
        self.until(lambda:self.control()['last_error'],'invalid candidate status')
        self.check('half-written source preserves applied revision',self.control()['revision']==previous['revision'])
        self.check('requests continue during parse errors',self.request()[2]==b'b:/asset')
        self.set_source(self.sites(origin=1));self.until(lambda:not self.control()['last_error'],'source repair')
        before=self.generation();self.set_source(self.sites(origin=1,alias=False));self.wait_change(before)
        self.check('removed host is rejected without worker reload',self.request(host='alias.example.com')[0]==403)
        before=self.generation();self.set_source(self.sites(origin=1,enabled='off',alias=False));self.wait_change(before)
        self.check('disabled site rejects HTTP requests',self.request()[0]==403)
        try:self.request(tls=True);rejected=False
        except (ssl.SSLError,OSError,http.client.HTTPException):rejected=True
        self.check('disabled site rejects new TLS handshakes',rejected)
        before=self.generation();self.set_source(self.sites());self.wait_change(before)
        original_chain=(self.root/'site.crt').read_bytes()
        (self.root/'site.crt').write_bytes(original_chain+b'\n-----BEGIN ' b'CERTIFICATE-----\npartial-chain')
        self.until(lambda:self.control()['last_error']=='certificate_validation_failed','truncated certificate chain')
        self.check('partial certificate chain preserves the serving certificate',self.request(tls=True)[3]==self.cert_a)
        (self.root/'site.crt').write_bytes(original_chain)
        self.until(lambda:not self.control()['last_error'],'certificate chain repair')
        before=self.generation();(self.root/'site.crt').write_bytes(self.chain_b)
        self.until(lambda:self.control()['last_error']=='certificate_validation_failed','mismatched certificate')
        self.check('mismatched certificate preserves serving certificate',self.request(tls=True)[3]==self.cert_a)
        (self.root/'site.key').write_bytes(self.key_b);self.wait_change(before)
        self.check('same-path certificate rotation updates TLS',self.request(tls=True)[3]==self.cert_b)
        self.check('certificate rotation keeps worker PIDs',self.workers()==initial_workers)
        before=self.generation()
        extra=f'site added {{ host added.example.com; upstream http://127.0.0.1:{self.origins[1].server_port}; }}'
        self.set_source(self.sites(extra=extra));self.wait_change(before)
        self.check('adding a site requires no worker reload',self.request(host='added.example.com')[2]==b'b:/asset')
        before=self.generation();self.set_source(self.sites());self.wait_change(before)
        self.check('deleting a site removes its host',self.request(host='added.example.com')[0]==403)
        control=http.client.HTTPConnection('localhost',timeout=3)
        control.sock=socket.socket(socket.AF_UNIX);control.sock.settimeout(3);control.sock.connect(str(self.socket))
        control.request('GET','/status');response=control.getresponse();live=json.loads(response.read())
        paused=next(pid for pid in initial_workers if pid!=live['worker_pid'])
        os.kill(paused,signal.SIGSTOP)
        try:
            self.set_source(self.sites(origin=1));time.sleep(0.9)
            control.request('GET','/status');response=control.getresponse();current=json.loads(response.read())
            self.check('candidate waits for every worker to prepare',current['generation']==live['generation'])
        finally:os.kill(paused,signal.SIGCONT);control.close()
        self.wait_change(live['generation'])
        self.check('candidate commits when the paused worker returns',self.request()[2]==b'b:/asset')
        previous=self.control();self.set_source('sites { }')
        self.until(lambda:self.control()['last_error']=='empty_configuration','empty protection')
        self.check('empty source retains previous generation',self.control()['revision']==previous['revision'])
        self.set_source(self.sites(cache='l1'));self.wait_change(previous['generation'])
        self.request('/cached')
        cached=self.request('/cached')
        self.check('cache layer is selected natively',cached[1].get('X-Layer')=='l1' and cached[1].get('X-Cache')=='HIT')
        before=self.generation();self.set_source(self.sites(cache='auto'));self.wait_change(before)
        layers=[self.request('/hot')[1].get('X-Layer') for _ in range(4)]
        self.check('heat-based cache choice is enabled on demand',layers[:2]==['l2','l2'] and layers[-1]=='l1')
        previous=self.control();real=self.root/'source.real';self.source.rename(real);self.source.symlink_to(real)
        self.until(lambda:self.control()['last_error']=='configuration_unavailable','symlink rejection')
        self.check('symlink source is rejected',self.control()['revision']==previous['revision'])
        self.source.unlink();real.rename(self.source)
        self.until(lambda:not self.control()['last_error'],'source path recovery')
        pid=next(iter(initial_workers));os.kill(pid,signal.SIGKILL)
        self.until(lambda:len(self.workers())==2 and pid not in self.workers(),'worker respawn')
        before=self.generation();self.set_source(self.sites(origin=1));self.wait_change(before)
        self.check('respawned worker joins the current generation',self.request()[2]==b'b:/asset')
        metrics=self.control('/metrics')
        self.check('native per-site metrics are exported','scdn_edge_requests_total{site="alpha"}' in metrics)
        self.check('metrics do not expose WAF or limiter implementation','waf' not in metrics and 'limit' not in metrics)
        original=self.source.read_bytes();before=self.generation();time.sleep(0.7)
        self.check('unchanged bytes do not create a generation',self.generation()==before)
        self.check('native modules never write or compile the site source',self.source.read_bytes()==original
                   and not list(self.root.rglob('*.ljbc')))
        return self.checks

    def close(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:self.process.wait(timeout=8)
            except subprocess.TimeoutExpired:self.process.kill();self.process.wait(timeout=5)
        if self.log:self.log.close()
        for server in self.origins:server.shutdown();server.server_close()


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--prefix',required=True,type=Path)
    parser.add_argument('--report',type=Path)
    args=parser.parse_args()
    prefix=args.prefix/'nginx' if (args.prefix/'nginx/sbin/nginx').exists() else args.prefix
    with tempfile.TemporaryDirectory(prefix='scdn-hot-test-') as directory:
        review=Review(Path(directory),prefix.resolve())
        try:
            checks=review.run()
            if args.report:
                args.report.parent.mkdir(parents=True,exist_ok=True)
                args.report.write_text(json.dumps(dict(passed=len(checks),checks=checks),indent=2)+'\n')
            print(f'{len(checks)} native configuration/edge checks passed',flush=True)
        except Exception:
            if (review.root/'error.log').exists():print((review.root/'error.log').read_text(errors='replace')[-6000:],flush=True)
            raise
        finally:review.close()


if __name__=='__main__':main()
