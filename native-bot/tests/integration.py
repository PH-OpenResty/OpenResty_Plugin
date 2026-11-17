#!/usr/bin/env python3
"""Real Bot enforcement, trusted identity, profile redirects and standalone use."""
import argparse
import http.client
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import tempfile
import time

ROOT=Path(__file__).resolve().parents[2]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
fixture=module('bot_api_fixture',ROOT/'native-api/tests/integration.py')
catalog=module('bot_catalog',ROOT/'native-bot/tools/build_catalog.py')


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--prefix',type=Path,required=True)
    parser.add_argument('--report',type=Path,required=True);parser.add_argument('--static',action='store_true')
    args=parser.parse_args()
    directories=ROOT/'docs/security-seeds'
    entries=catalog.load(directories/'bot-catalog.seed.json')
    ranges=catalog.load(directories/'bot-ip-ranges.seed.json')
    custom=[{'id':'custom-block','site_id':'plain','ua':[{'type':'token','value':'ExampleBlockedBot'}],
             'ip_cidrs':['203.0.113.0/24','2001:db8:100::/48']},
            {'id':'observe-rule','site_id':'plain','action':'observe','ua':[{'type':'token','value':'ObserveBot'}]},
            {'id':'exact-rule','ua':[{'type':'exact','value':'Literal Probe'}]},
            {'id':'prefix-rule','ua':[{'type':'prefix','value':'PrefixProbe'}]},
            {'id':'literal-rule','ua':[{'type':'contains','value':'QuotedProbe";scdn_bot off;$literal\\tail'}]},
            {'id':'stale-rule','action':'continue','ua':[{'type':'token','value':'StaleBot'}],'ip_cidrs':['192.0.2.0/24']}]
    compiled,_=catalog.compile_policy(entries,ranges,custom=custom)
    text=compiled.decode().replace('scdn_bot_feed stale-rule manual 0 86400;','scdn_bot_feed stale-rule published 1 86400;')
    text=text.replace('scdn_bot_feed googlebot seed 0 86400;',f'scdn_bot_feed googlebot published {int(time.time())} 86400;')
    google=next(row for row in ranges['sources'] if row['id']=='google-common')
    google_ip=str(next(ipaddress.ip_network(p) for p in google['prefixes'] if ':' not in p).network_address+1)
    checks=[]
    def check(name,value):
        assert value,name
        checks.append(name)
    class Review(fixture.Review):
        def config(self):
            (self.root/'bots.conf').write_text(text)
            configuration=super().config().replace('scdn_api_zone api_counters 64k;',
                f'''scdn_api_zone api_counters 64k;
 scdn_bot_zone bot_counters 64k;
 scdn_bot_trusted_proxy 127.0.0.1/32;
 scdn_bot_trusted_proxy 10.0.0.0/8;
 include {self.root}/bots.conf;''')
            configuration=configuration.replace('location = /metrics { scdn_api_metrics; }',
                'location = /metrics { scdn_api_metrics; } location = /bot-status { scdn_bot_status; }')
            configuration=configuration.replace(f'listen 127.0.0.1:{self.http};',f'listen 127.0.0.1:{self.http}; listen [::1]:{self.http};')
            realip='set_real_ip_from 127.0.0.1; real_ip_header X-Clinet-IP;' if self.has_realip else ''
            configuration=configuration.replace('  scdn_edge on;', '  '+realip+'\n  scdn_edge on;')
            return configuration.replace('  scdn_edge on;','''  scdn_edge on;
  scdn_bot on;
  location /observe/ { scdn_bot_mode observe; }
  location /off/ { scdn_bot off; }
  location = /private { deny all; }
  location = /basic-private { auth_basic "fixture"; auth_basic_user_file /tmp/scdn-nonexistent-test-password-file; }
  add_header X-Bot $scdn_bot_id always;
  add_header X-Bot-Source $scdn_bot_source always;
  add_header X-Bot-Action $scdn_bot_action always;
  add_header X-Bot-Match $scdn_bot_match always;
  add_header X-Bot-IP $scdn_bot_client_ip always;
  add_header X-Bot-Identity $scdn_bot_identity always;''')
    with tempfile.TemporaryDirectory(prefix='native-bot-') as directory:
        review=Review(Path(directory),args.prefix,args.static)
        review.has_realip='--with-http_realip_module' in subprocess.run([str(review.nginx),'-V'],capture_output=True,text=True).stderr
        try:
            review.start()
            def request(ua='Mozilla/5.0',ip='198.51.100.10',path='/opaque',host='www.example.test'):
                return review.request(path,headers={'User-Agent':ua,'X-Forwarded-For':ip},host=host)
            for ua,ip,blocked in [('Mozilla/5.0','198.51.100.10',False),('ExampleBlockedBot/1','198.51.100.10',True),
                    ('Mozilla/5.0','203.0.113.45',True),('ExampleBlockedBot/1','203.0.113.45',True)]:
                status,headers,_=request(ua,ip)
                check('UA/IP OR '+ua+ip,status==(403 if blocked else 200))
                if blocked:check('deny reports matching rule '+str(len(checks)),headers.get('x-bot')=='custom-block')
            status,headers,_=request('Mozilla/5.0','2001:db8:100:42::1')
            check('IPv6 CIDR blocks browser UA',status==403 and headers.get('x-bot-match')=='ip')
            check('IPv6 CIDR boundary excludes adjacent prefix',request(ip='2001:db8:101::1')[0]==200)
            check('IPv4 mapped IPv6 normalized',request(ip='::ffff:203.0.113.45')[0]==403)
            for ua in ('CensysInspect/1.1','cEnSySiNsPeCt/1.1','FofaBot/1.0'):
                check('scanner declared UA denied '+ua,request(ua)[0]==403)
            status,headers,_=request(ip='66.132.159.18')
            check('published Censys network denied with browser UA',status==403 and headers.get('x-bot')=='censys' and headers.get('x-bot-match')=='ip')
            check('security denial is not cacheable',headers.get('cache-control')=='no-store')
            check('scanner token boundary avoids substring false positive',request('NotCensysInspectClient/1')[0]==200)
            status,headers,_=request('Googlebot/2.1',google_ip)
            check('Google claimed UA and current feed address',status==200 and headers.get('x-bot')=='googlebot' and headers.get('x-bot-source')=='ip_match')
            check('verified source does not bypass access policy',request('Googlebot/2.1',google_ip,'/private')[0]==403)
            check('ordinary request also retains original location ACL',request(path='/private')[0]==403)
            check('verified source does not bypass HTTP authentication',request('Googlebot/2.1',google_ip,'/basic-private')[0]==401)
            status,headers,_=request('Googlebot/2.1')
            check('source mismatch recorded without inventing identity',status==200 and headers.get('x-bot-source')=='ip_mismatch')
            status,headers,_=request('Baiduspider/2.0')
            check('engine without official IP retains UA path',status==200 and headers.get('x-bot')=='baiduspider' and headers.get('x-bot-source')=='ua_only')
            status,headers,_=request('StaleBot/1','192.0.2.10')
            check('stale data is distinguished from current source',status==200 and headers.get('x-bot-source')=='stale')
            check('exact UA rule matches complete literal',request('Literal Probe')[0]==403 and request('Other Literal Probe')[0]==200)
            check('prefix UA rule matches only beginning',request('PrefixProbe/1')[0]==403 and request('Other PrefixProbe/1')[0]==200)
            check('configuration metacharacters remain literal UA data',request('QuotedProbe";scdn_bot off;$literal\\tail')[0]==403)
            status,headers,_=request('ObserveBot/1')
            check('observe rule keeps origin access',status==200 and headers.get('x-bot-action')=='observe')
            status,headers,_=request('ExampleBlockedBot/1',path='/observe/check')
            check('observe survives named profile redirection',status==200 and headers.get('x-bot-action')=='would_deny')
            status,headers,_=request('ExampleBlockedBot/1',path='/off/check')
            check('explicit off survives named profile redirection',status==200 and headers.get('x-bot')=='disabled')
            check('site scoped rule does not expand to other tenant',request('ExampleBlockedBot/1',host='tls.example.test')[0]==200)
            status,headers,_=request(ip='66.132.159.1, 198.51.100.20, 10.0.0.8')
            check('trusted chain stops at first untrusted client',status==200 and headers.get('x-bot-ip')=='198.51.100.20' and headers.get('x-bot-identity')=='trusted_xff')
            connection=http.client.HTTPConnection('127.0.0.1',review.http,source_address=('127.0.0.2',0),timeout=5)
            connection.request('GET','/opaque',headers={'Host':'www.example.test','User-Agent':'Mozilla/5.0','X-Forwarded-For':'66.132.159.1'})
            response=connection.getresponse();headers=dict((k.lower(),v) for k,v in response.getheaders());response.read();connection.close()
            check('untrusted peer cannot choose XFF identity',response.status==200 and headers.get('x-bot-ip')=='127.0.0.2' and headers.get('x-bot-identity')=='direct')
            connection=http.client.HTTPConnection('::1',review.http,timeout=5)
            connection.request('GET','/opaque',headers={'Host':'www.example.test','User-Agent':'Mozilla/5.0','X-Forwarded-For':'66.132.159.1'})
            response=connection.getresponse();headers=dict((k.lower(),v) for k,v in response.getheaders());response.read();connection.close()
            check('real IPv6 peer is retained and forged XFF ignored',response.status==200 and headers.get('x-bot-ip')=='::1' and headers.get('x-bot-identity')=='direct')
            status,headers,_=review.request('/opaque',headers={'User-Agent':'Mozilla/5.0','X-Clinet-IP':'66.132.159.1'})
            check(('core realip rewrite' if review.has_realip else 'custom client header')+' does not replace socket ownership',status==200 and headers.get('x-bot-ip')=='127.0.0.1')
            check('long UA is rejected without truncation bypass',request('a'*3000+' CensysInspect/1')[0]==431)
            for header in ('User-Agent','X-Forwarded-For'):
                connection=http.client.HTTPConnection('127.0.0.1',review.http,timeout=5)
                connection.putrequest('GET','/opaque',skip_host=True);connection.putheader('Host','www.example.test')
                connection.putheader(header,'Mozilla/5.0' if header=='User-Agent' else '198.51.100.1')
                connection.putheader(header,'CensysInspect/1' if header=='User-Agent' else '203.0.113.1')
                connection.endheaders();response=connection.getresponse();response.read();connection.close()
                check('ambiguous duplicate header rejected '+header,response.status==400)
            connection=http.client.HTTPConnection('127.0.0.1',review.http,timeout=3)
            connection.putrequest('POST','/v1/images/edits',skip_host=True)
            for key,value in {'Host':'www.example.test','User-Agent':'CensysInspect/1','Content-Length':'65536','Content-Type':'multipart/form-data; boundary=fixture'}.items():connection.putheader(key,value)
            connection.endheaders();started=time.monotonic();response=connection.getresponse();response.read();connection.close()
            check('denied upload stops before body consumption',response.status==403 and time.monotonic()-started<2)
            def status():
                connection=http.client.HTTPConnection('localhost',timeout=3)
                connection.sock=socket.socket(socket.AF_UNIX);connection.sock.settimeout(3)
                connection.sock.connect(str(review.socket));connection.request('GET','/bot-status')
                response=connection.getresponse();body=response.read();headers=dict((k.lower(),v) for k,v in response.getheaders());connection.close()
                return response.status,headers,json.loads(body)
            _,_,before=status()
            request('Baiduspider/2.0')
            status_code,headers,after=status()
            check('one decision across internal phase reentry',sum(after['actions'])-sum(before['actions'])==1)
            check('shared status is explicit and uncached',status_code==200 and headers.get('cache-control')=='no-store' and after['patterns']>40)
            context=ssl.create_default_context(cafile=str(review.root/'origin.crt'));context.set_alpn_protocols(['h2'])
            sock=context.wrap_socket(socket.create_connection(('127.0.0.1',review.tls),timeout=5),server_hostname='model.example.test')
            client=fixture.H2Connection(config=fixture.H2Configuration(client_side=True,header_encoding='utf-8'));client.initiate_connection()
            results={}
            for stream,ua,ip in [(1,'Googlebot/2.1',google_ip),(3,'CensysInspect/1','198.51.100.1'),(5,'Mozilla/5.0','203.0.113.5')]:
                client.send_headers(stream,[(':method','GET'),(':scheme','https'),(':authority','www.example.test'),(':path','/opaque'),('user-agent',ua),('x-forwarded-for',ip)],end_stream=True)
                results[stream]={'headers':{},'done':False}
            sock.sendall(client.data_to_send())
            while not all(row['done'] for row in results.values()):
                incoming=sock.recv(65536)
                assert incoming,'HTTP/2 ended early'
                for event in client.receive_data(incoming):
                    if isinstance(event,fixture.ResponseReceived):results[event.stream_id]['headers']=dict(event.headers)
                    elif isinstance(event,fixture.DataReceived):client.acknowledge_received_data(event.flow_controlled_length,event.stream_id)
                    elif isinstance(event,fixture.StreamEnded):results[event.stream_id]['done']=True
                outgoing=client.data_to_send()
                if outgoing:sock.sendall(outgoing)
            sock.close()
            check('HTTP/2 multiplexing enforces each request independently',[results[i]['headers'][':status'] for i in (1,3,5)]==['200','403','403'])
            check('HTTP/2 client identities do not cross streams',[results[i]['headers'].get('x-bot') for i in (1,3,5)]==['googlebot','censys','custom-block'])
        except Exception:
            for filename in ('error.log','process.log'):
                path=review.root/filename
                if path.exists():print(filename+'\n'+path.read_text(errors='replace')[-5000:])
            raise
        finally:review.close()
        # Standalone module has no Edge/Config/API dependency.
        base,_=catalog.compile_policy(entries,ranges)
        (Path(directory)/'standalone-bots.conf').write_bytes(base)
        port=fixture.unused_port();root=Path(directory);(root/'asset').write_text('standalone')
        load='' if args.static else f'load_module {review.prefix}/modules/ngx_http_scdn_bot_module.so;'
        user='user root root;' if os.geteuid()==0 else ''
        conf=root/'standalone.conf';conf.write_text(f'''{load}
{user}
daemon off; master_process off;
pid {root}/standalone.pid;
error_log {root}/standalone.log warn;
events {{ worker_connections 64; }}
http {{ include {root}/standalone-bots.conf; server {{ listen 127.0.0.1:{port}; scdn_bot on; location / {{ root {root}; }} }} }}''')
        process=subprocess.Popen([str(review.nginx),'-p',str(root)+'/', '-c',str(conf)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            for _ in range(50):
                try:
                    connection=http.client.HTTPConnection('127.0.0.1',port,timeout=.3)
                    connection.request('GET','/asset',headers={'User-Agent':'CensysInspect/1'});response=connection.getresponse();response.read();connection.close()
                    check('standalone scanner rejection',response.status==403);break
                except OSError:time.sleep(.05)
            else:raise AssertionError('standalone did not start')
            connection=http.client.HTTPConnection('127.0.0.1',port,timeout=3)
            connection.request('GET','/asset',headers={'User-Agent':'Baiduspider/2.0'});response=connection.getresponse();body=response.read();connection.close()
            check('standalone UA-only search retains ordinary content',response.status==200 and body==b'standalone')
        finally:
            if process.poll() is None:process.send_signal(signal.SIGQUIT)
            process.wait(timeout=5)
    result={'passed':True,'check_count':len(checks),'checks':checks,'real_vendor_api_calls':0,'production_modified':False}
    args.report.parent.mkdir(parents=True,exist_ok=True);args.report.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'passed':True,'check_count':len(checks)}))


if __name__=='__main__':main()
