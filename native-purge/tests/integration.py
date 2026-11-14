#!/usr/bin/env python3
"""Real cache HIT/MISS, Vary, concurrent fills and durable invalidation tests."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import http.client
import http.server
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import tempfile
import threading
import time


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class Origin(http.server.BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'

    def do_GET(self):
        with self.server.guard:
            version=self.server.version
            self.server.calls+=1
        if self.path.startswith('/slow'):
            self.server.slow_started.set()
            self.server.slow_release.wait(5)
        variant=self.headers.get('Accept-Language','none')
        body=(f'v{version}:{variant}:'+self.path).encode()
        if self.path.startswith('/bench') or self.path.startswith('/baseline'):
            body=(f'v{version}:'.encode()+b'x'*getattr(self.server,'bench_bytes',16384))
        self.send_response(200)
        self.send_header('Content-Length',str(len(body)))
        self.send_header('Cache-Control','public,max-age=600')
        self.send_header('ETag',f'"v{version}-{variant}"')
        if self.path.startswith('/vary'):
            self.send_header('Vary','Accept-Language')
        self.end_headers()
        try:self.wfile.write(body)
        except (BrokenPipeError,ConnectionResetError):pass

    def log_message(self,*args):pass


class OriginServer(http.server.ThreadingHTTPServer):
    request_queue_size=256
    daemon_threads=True


class Review:
    def __init__(self,root,prefix):
        self.root,self.prefix=root,prefix
        self.nginx=prefix/'sbin/nginx'
        self.http,self.second=port(),port()
        self.control_socket=root/'control.sock'
        self.journal=root/'epochs.log'
        self.token=secrets.token_urlsafe(32)
        token=root/'control.token';token.write_text(self.token+'\n');token.chmod(0o600)
        self.process,self.log=None,None
        self.checks=[]
        self.origin=OriginServer(('127.0.0.1',0),Origin)
        self.origin.guard=threading.Lock();self.origin.version=1;self.origin.calls=0
        self.origin.slow_started=threading.Event();self.origin.slow_release=threading.Event()
        threading.Thread(target=self.origin.serve_forever,daemon=True).start()
        self.path=root/'nginx.conf'

    def check(self,name,condition):
        if not condition:raise AssertionError(name)
        self.checks.append(name);print('PASS '+name,flush=True)

    def config(self,allow_all=True):
        user='user root root;' if os.geteuid()==0 else ''
        business='''
        location / {
            scdn_purge_key "$http_x_scope" "$request_uri";
            proxy_cache_key $scdn_purge_key;
            proxy_pass http://127.0.0.1:ORIGIN;
            proxy_cache CACHE;
            proxy_cache_valid 200 10m;
            proxy_cache_lock on;
            proxy_cache_lock_timeout 2s;
            proxy_cache_lock_age 10s;
            add_header X-Cache $upstream_cache_status always;
            add_header X-Worker $pid always;
        }
'''.replace('ORIGIN',str(self.origin.server_port))
        return f'''load_module {self.prefix}/modules/ngx_http_scdn_purge_module.so;
{user}
worker_processes 2;
thread_pool scdn_cache_purge threads=2 max_queue=128;
pid {self.root}/nginx.pid;
error_log {self.root}/error.log warn;
events {{ worker_connections 1024; }}
http {{
    access_log off;
    keepalive_timeout 10s;
    client_body_timeout 3s;
    client_max_body_size 1m;
    client_body_buffer_size 1m;
    scdn_purge_zone epochs 8m;
    scdn_purge_journal {self.journal};
    scdn_purge_token_file {self.root}/control.token;
    scdn_purge_cache_entries 1024;
    scdn_purge_checkpoint 64k;
    scdn_purge_allow_all {'on' if allow_all else 'off'};
    proxy_cache_path {self.root}/cache1 levels=1:2 keys_zone=l1:4m inactive=1h;
    proxy_cache_path {self.root}/cache2 levels=1:2 keys_zone=l2:4m inactive=1h;
    proxy_buffer_size 16k;
    proxy_buffers 8 16k;
    server {{ listen unix:{self.control_socket};
        location = /purge {{ scdn_purge_api; }}
        location = /status {{ scdn_purge_status; }}
    }}
    server {{ listen 127.0.0.1:{self.http};
        {business.replace('CACHE','l1')}
        location /baseline/ {{
            proxy_pass http://127.0.0.1:{self.origin.server_port};
            proxy_cache l1;
            proxy_cache_key "$http_x_scope|$request_uri";
            proxy_cache_valid 200 10m;
            add_header X-Cache $upstream_cache_status always;
        }}
        location /revisioned/ {{
            scdn_purge_key "$http_x_scope" "$http_x_revision|$request_uri" "$request_uri";
            proxy_pass http://127.0.0.1:{self.origin.server_port};
            proxy_cache l1;proxy_cache_key $scdn_purge_key;proxy_cache_valid 200 10m;
            add_header X-Cache $upstream_cache_status always;
        }}
    }}
    server {{ listen 127.0.0.1:{self.second}; {business.replace('CACHE','l2')} }}
}}
'''

    def start(self,allow_all=True):
        self.path.write_text(self.config(allow_all))
        checked=subprocess.run([str(self.nginx),'-t','-p',str(self.root)+'/', '-c',str(self.path)],capture_output=True,text=True)
        if checked.returncode:raise AssertionError(checked.stderr)
        self.log=(self.root/'stdout.log').open('ab')
        self.process=subprocess.Popen([str(self.nginx),'-p',str(self.root)+'/', '-c',str(self.path),'-g','daemon off;'],stdout=self.log,stderr=self.log)
        self.until(lambda:self.status()['ok'],'startup')

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:self.process.wait(timeout=8)
            except subprocess.TimeoutExpired:self.process.kill();self.process.wait(timeout=5)
        if self.log:self.log.close();self.log=None

    def until(self,fn,description,seconds=10):
        end=time.monotonic()+seconds
        while time.monotonic()<end:
            if self.process and self.process.poll() is not None:raise AssertionError('nginx exited')
            try:
                value=fn()
                if value:return value
            except (OSError,http.client.HTTPException):pass
            time.sleep(0.02)
        raise AssertionError('deadline: '+description)

    def request(self,key='/asset',scope='one',second=False,language=None,connection=None,revision='a'):
        own=connection is None
        if own:connection=http.client.HTTPConnection('127.0.0.1',self.second if second else self.http,timeout=6)
        headers={'X-Scope':scope,'X-Revision':revision}
        if language:headers['Accept-Language']=language
        try:
            connection.request('GET',key,headers=headers)
            response=connection.getresponse()
            return response.status,dict(response.getheaders()),response.read()
        finally:
            if own:connection.close()

    def control(self,mode=None,scope='one',keys=None,path='/purge',method=None,token=True,extra=None):
        connection=http.client.HTTPConnection('localhost',timeout=10)
        connection.sock=socket.socket(socket.AF_UNIX);connection.sock.settimeout(10)
        connection.sock.connect(str(self.control_socket))
        headers={'Content-Type':'text/plain'}
        if token:headers['Authorization']='Bearer '+self.token
        if mode:headers['X-SCDN-Purge-Mode']=mode
        if scope is not None:headers['X-SCDN-Purge-Scope']=scope
        if extra:headers.update(extra)
        body=('\n'.join(keys)+'\n').encode() if keys is not None else b''
        try:
            connection.request(method or ('GET' if path=='/status' else 'POST'),path,body=body,headers=headers)
            response=connection.getresponse();raw=response.read()
            return response.status,json.loads(raw)
        finally:connection.close()

    def status(self):return self.control(path='/status')[1]

    def version(self,n):
        with self.origin.guard:self.origin.version=n

    def workers(self):
        children=Path(f'/proc/{self.process.pid}/task/{self.process.pid}/children').read_text().split()
        return {int(pid) for pid in children if Path(f'/proc/{pid}/cmdline').exists()
                and b'nginx: worker process' in Path(f'/proc/{pid}/cmdline').read_bytes()}

    def fill(self,key,scope='one',second=False,language=None):
        end=time.monotonic()+3
        while True:
            value=self.request(key,scope,second,language)
            if value[1].get('X-Cache')=='HIT':return value
            if time.monotonic()>=end:raise AssertionError(('expected HIT',key,value))
            time.sleep(0.005)

    def run(self):
        self.start()
        self.check('native module starts without core cache patches',self.status()['sequence']==0)
        checked=subprocess.run([str(self.nginx),'-t','-p',str(self.root)+'/', '-c',str(self.path)],capture_output=True,text=True)
        self.check('configuration checking is allowed while the owner is live',checked.returncode==0)
        duplicate=subprocess.run([str(self.nginx),'-p',str(self.root)+'/', '-c',str(self.path),'-g','daemon off;'],capture_output=True,text=True,timeout=5)
        self.check('a second nginx master cannot share the same journal',duplicate.returncode!=0 and 'already owned' in duplicate.stderr)
        self.check('control requires authentication',self.control('exact',keys=['/asset'],token=False)[0]==401)
        self.check('invalid token is rejected',self.control('exact',keys=['/asset'],extra={'Authorization':'Bearer invalid'})[0]==401)
        self.check('unsupported method cannot mutate state',self.control('exact',keys=[],method='GET')[0]==405)
        self.check('scope is required',self.control('exact',scope=None,keys=['/asset'])[0]==400)
        self.check('unknown mode is rejected',self.control('regex',keys=['/.*'])[0]==400)
        self.check('empty exact batch is rejected',self.control('exact')[0]==400)
        self.check('empty key cannot become a prefix flush',self.control('prefix',keys=[''])[0]==400)
        self.check('invalid content type is rejected',self.control('exact',keys=['/asset'],extra={'Content-Type':'application/json'})[0]==415)
        self.check('control query strings are rejected',self.control('exact',keys=['/asset'],path='/purge?x=1')[0]==400)
        self.check('batch count is bounded',self.control('exact',keys=[f'/large/{i}' for i in range(257)])[0]==400)
        self.check('complete key length is bounded',self.control('exact',keys=['/'+('x'*4096)])[0]==400)
        nodes=self.status()['metadata_nodes']
        failed,_=self.control('prefix',scope='reservation-test',keys=[f'/limit/{i}/' for i in range(129)])
        self.check('failed batch releases all preflight metadata reservations',failed==507 and self.status()['metadata_nodes']==nodes)
        rollback_copy=self.journal.read_bytes()
        self.fill('/exact');self.fill('/exact?x=1');self.fill('/exact',scope='two');self.fill('/exact',second=True)
        self.version(2)
        code,ack=self.control('exact',keys=['/exact'])
        self.check('exact purge acknowledges durable version fencing',code==200 and ack['durable'] and not ack['physical_deleted'])
        fresh=self.fill('/exact')
        self.check('purged key refills with new content',fresh[2].startswith(b'v2:'))
        self.check('same base key in another cache zone is invalidated',self.fill('/exact',second=True)[2].startswith(b'v2:'))
        self.check('query variant is not accidentally purged',self.request('/exact?x=1')[2].startswith(b'v1:'))
        self.check('same key in another scope is not purged',self.request('/exact',scope='two')[2].startswith(b'v1:'))
        self.fill('/literal%2Fpath');self.fill('/literal/path')
        self.control('exact',keys=['/literal%2Fpath'])
        self.version(20)
        self.check('purge compares complete encoded bytes without URL over-normalization',
                   self.fill('/literal%2Fpath')[2].startswith(b'v20:')
                   and self.request('/literal/path')[2].startswith(b'v2:'))
        self.version(2)
        longest='/'+('k'*4095)
        self.fill(longest);self.version(21)
        self.check('maximum supported key is invalidated precisely',self.control('exact',keys=[longest])[0]==200
                   and self.fill(longest)[2].startswith(b'v21:'))
        self.version(2)
        for revision in ('a','b'):
            self.request('/revisioned/item',revision=revision);self.request('/revisioned/item',revision=revision)
        self.version(22);self.control('exact',keys=['/revisioned/item'])
        self.check('logical resource purge covers every configuration revision',
                   all(self.request('/revisioned/item',revision=revision)[2].startswith(b'v22:') for revision in ('a','b')))
        self.version(2)
        collision_a='/collision/b97186618aa1434e'
        collision_b='/collision/2f6843fd71907689'
        self.fill(collision_a);self.fill(collision_b);self.version(23)
        self.control('exact',keys=[collision_a])
        self.check('CRC32 index collision cannot purge an unrelated complete key',
                   self.fill(collision_a)[2].startswith(b'v23:')
                   and self.request(collision_b)[2].startswith(b'v2:'))
        self.version(2)
        self.fill('/vary',language='en');self.fill('/vary',language='fr')
        self.version(3);self.control('exact',keys=['/vary'])
        self.check('Vary English response cannot resurrect',self.fill('/vary',language='en')[2].startswith(b'v3:en:'))
        self.check('all Vary variants follow the new base generation',self.fill('/vary',language='fr')[2].startswith(b'v3:fr:'))
        for key in ('/prefix/a','/prefix/b','/prefix-other'):
            self.fill(key)
        self.version(4);code,_=self.control('prefix',keys=['/prefix/'])
        self.check('prefix operation succeeds',code==200)
        self.check('prefix invalidates matching resources',all(self.fill(k)[2].startswith(b'v4:') for k in ('/prefix/a','/prefix/b')))
        self.check('prefix does not overmatch adjacent names',self.request('/prefix-other')[2].startswith(b'v3:'))
        self.fill('/scope',scope='one');self.fill('/scope',scope='two')
        self.version(5);code,_=self.control('scope')
        self.check('whole-site scope flush succeeds',code==200 and self.fill('/scope')[2].startswith(b'v5:'))
        self.check('whole-site flush preserves other sites',self.request('/scope',scope='two')[2].startswith(b'v4:'))
        for key in ('/batch/a','/batch/b','/batch/c'):self.fill(key)
        self.version(6);code,ack=self.control('exact',keys=['/batch/a','/batch/b'])
        self.check('batch shares one durable commit',code==200 and ack['operations']==2)
        self.check('batch invalidates every selected key',all(self.fill(k)[2].startswith(b'v6:') for k in ('/batch/a','/batch/b')))
        self.check('batch preserves unselected keys',self.request('/batch/c')[2].startswith(b'v5:'))
        self.origin.slow_release.clear();self.origin.slow_started.clear()
        with ThreadPoolExecutor(max_workers=2) as pool:
            pending=pool.submit(self.request,'/slow-fill')
            self.check('old upstream fill is in flight',self.origin.slow_started.wait(3))
            code,_=self.control('exact',keys=['/slow-fill']);self.version(7)
            self.origin.slow_release.set();old=pending.result()
        self.check('in-flight reader may finish its original version',old[2].startswith(b'v6:'))
        self.check('late old fill cannot poison a post-purge request',code==200 and self.fill('/slow-fill')[2].startswith(b'v7:'))
        self.fill('/persistent');self.version(8);self.control('exact',keys=['/persistent'])
        self.check('new persistent generation fills',self.fill('/persistent')[2].startswith(b'v8:'))
        before=self.status()['sequence'];self.stop();self.start()
        self.check('restart restores the durable generation',self.status()['sequence']==before)
        self.check('restart cannot expose pre-purge disk cache',self.request('/persistent')[2].startswith(b'v8:'))
        old_workers=self.workers()
        reload=subprocess.run([str(self.nginx),'-p',str(self.root)+'/', '-c',str(self.path),'-s','reload'],capture_output=True,text=True)
        if reload.returncode:print(reload.stderr.replace(self.token,'[redacted]'),flush=True)
        self.check('graceful reload accepts the same state identity',reload.returncode==0)
        self.until(lambda:len(self.workers())==2 and self.workers().isdisjoint(old_workers),'new worker generation')
        self.check('graceful reload retains committed invalidation',self.status()['sequence']==before
                   and self.request('/persistent')[2].startswith(b'v8:'))
        self.stop()
        with self.journal.open('ab') as file:file.write(b'partial')
        self.start()
        self.check('incomplete journal tail is safely discarded',self.status()['sequence']==before)
        self.fill('/concurrent')
        with ThreadPoolExecutor(max_workers=16) as pool:
            outcomes=list(pool.map(lambda i:self.control('exact',keys=[f'/jobs/{i}',f'/jobs/{i}?x=1']),range(48)))
        sequences=[ack['sequence'] for status,ack in outcomes if status==200]
        self.check('concurrent batches all commit',len(sequences)==48)
        self.check('concurrent writers have distinct ordered sequences',len(set(sequences))==48)
        self.check('unrelated purge load preserves hot cache',self.request('/concurrent')[1].get('X-Cache')=='HIT')
        with ThreadPoolExecutor(max_workers=12) as pool:
            for version in range(30,38):
                self.version(version)
                if self.control('exact',keys=['/race-hot'])[0]!=200:raise AssertionError('race purge')
                responses=list(pool.map(lambda _:self.request('/race-hot'),range(24)))
                if not all(result[2].startswith(f'v{version}:'.encode()) for result in responses):
                    raise AssertionError('stale post-ack response')
        self.check('concurrent post-ack requests always observe the current generation',True)
        self.version(9);code,_=self.control('all',scope='x'*300)
        self.check('global operation ignores scope header without corrupting the journal',code==200)
        self.check('explicit all-scope flush fences every site',self.fill('/scope',scope='two')[2].startswith(b'v9:'))
        self.check('all flush safely releases superseded metadata',self.status()['metadata_nodes']==0)
        for i in range(128):
            status,_=self.control('prefix',scope='bounded',keys=[f'/p/{i}/'])
            if status!=200:raise AssertionError(('prefix setup',i,status))
        self.check('prefix metadata capacity is bounded',self.control('prefix',scope='bounded',keys=['/overflow/'])[0]==507)
        self.control('scope',scope='bounded')
        self.check('site purge reclaims covered prefix metadata without flushing other sites',
                   self.control('prefix',scope='bounded',keys=['/after-site-reset/'])[0]==200)
        self.control('all',scope=None)
        self.check('explicit global flush recovers bounded metadata capacity',self.control('prefix',scope='bounded',keys=['/after-reset/'])[0]==200)
        long_keys=['/checkpoint/'+str(i)+'/'+('x'*700) for i in range(128)]
        for _ in range(3):
            code,_=self.control('exact',scope='checkpoint',keys=long_keys)
            if code!=200:raise AssertionError('checkpoint input')
        self.check('durable journal is checkpointed in the background',self.status()['checkpoints']>0)
        seq=self.status()['sequence'];self.stop();self.start()
        self.check('checkpoint restores the complete committed sequence',self.status()['sequence']==seq)
        latest=self.journal.read_bytes()
        replacement=self.root/'rollback.log';replacement.write_bytes(rollback_copy);replacement.chmod(0o600)
        replacement.replace(self.journal)
        self.check('live journal rollback is refused',self.control('exact',keys=['/rollback'])[0]==503)
        replacement.write_bytes(latest);replacement.chmod(0o600);replacement.replace(self.journal)
        self.check('valid journal restoration permits new commits',self.control('exact',keys=['/repaired'])[0]==200)
        connection=socket.socket(socket.AF_UNIX);connection.connect(str(self.control_socket))
        body=b'/disconnect\n'
        message=(f'POST /purge HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {self.token}\r\n'
                 f'X-SCDN-Purge-Mode: exact\r\nX-SCDN-Purge-Scope: one\r\nContent-Type: text/plain\r\n'
                 f'Content-Length: {len(body)}\r\n\r\n').encode()+body
        connection.sendall(message);connection.close();time.sleep(0.1)
        self.check('client disconnect cannot invalidate the job lifetime',self.control('exact',keys=['/after-disconnect'])[0]==200)
        self.check('old inaccessible cache files are left to nginx storage management',bool(list((self.root/'cache1').rglob('*'))))
        self.stop();good=self.journal.read_bytes();damaged=bytearray(good);damaged[-1]^=1;self.journal.write_bytes(damaged)
        failed=subprocess.run([str(self.nginx),'-t','-p',str(self.root)+'/', '-c',str(self.path)],capture_output=True,text=True)
        self.check('complete-record corruption is rejected rather than silently reset',failed.returncode!=0 and 'journal validation failed' in failed.stderr)
        self.journal.write_bytes(good);self.start(allow_all=False)
        self.check('global flush can be disabled independently',self.control('all',scope=None)[0]==403)
        self.check('module never logs the control token',self.token not in (self.root/'error.log').read_text(errors='replace'))
        self.check('journal and stable lock are private files',(self.journal.stat().st_mode&0o077)==0
                   and (Path(str(self.journal)+'.lock').stat().st_mode&0o077)==0)
        return self.checks

    def close(self):
        self.origin.slow_release.set();self.stop();self.origin.shutdown();self.origin.server_close()


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--prefix',required=True,type=Path)
    parser.add_argument('--report',type=Path)
    args=parser.parse_args()
    prefix=args.prefix/'nginx' if (args.prefix/'nginx/sbin/nginx').exists() else args.prefix
    with tempfile.TemporaryDirectory(prefix='scdn-purge-test-') as directory:
        review=Review(Path(directory),prefix.resolve())
        try:
            checks=review.run()
            if args.report:
                args.report.parent.mkdir(parents=True,exist_ok=True)
                args.report.write_text(json.dumps(dict(passed=len(checks),checks=checks),indent=2)+'\n')
            print(f'{len(checks)} native purge checks passed',flush=True)
        except Exception:
            if (review.root/'error.log').exists():print((review.root/'error.log').read_text(errors='replace')[-5000:],flush=True)
            raise
        finally:review.close()


if __name__=='__main__':main()
