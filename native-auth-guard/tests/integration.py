#!/usr/bin/env python3
"""Real C guard plus the Go application adapter; no real accounts or mail."""
import argparse
import concurrent.futures
import hashlib
import hmac
import http.client
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('auth_api_fixture',ROOT/'native-api/tests/integration.py')
fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--prefix',type=Path,required=True)
    parser.add_argument('--backend',type=Path,required=True);parser.add_argument('--report',type=Path,required=True)
    parser.add_argument('--static',action='store_true');args=parser.parse_args();checks=[];last={}
    def check(name,value):
        assert value,(name,last)
        checks.append(name)
    with tempfile.TemporaryDirectory(prefix='native-auth-guard-') as directory:
        root=Path(directory);control=root/'auth.sock';port=fixture.unused_port();admin=os.urandom(32)
        admin_file=root/'admin.key';admin_file.write_bytes(admin);admin_file.chmod(0o600)
        realms=[];backend_realms=[]
        for identifier,adapter in [('sub','sub2api'),('new','newapi')]:
            key=os.urandom(32);key_file=root/(identifier+'.key');key_file.write_bytes(key);key_file.chmod(0o600)
            policy={'adapter':adapter,'revision':identifier+'-v1','registration_enabled':True,'email_verify_enabled':True,
                    'strict_email':True,'precreate_required':True,'allowed_domains':['example.com','*.enterprise.example'],
                    'denied_domains':['temporary.example'],'email_alias_restriction':False}
            realms.append({'id':identifier,'key_file':str(key_file),'checked_at':int(time.time()),'max_age':3600,**policy,
                'limits':{'per_minute':600,'burst':100,'registration_rejections':3,'distinct_subjects':3,'window_seconds':60,'ban_seconds':2,'login_failures':3,'cooldown_seconds':2}})
            backend_realms.append({'id':identifier,'key_file':str(key_file),'policy':policy})
        policy_path=root/'auth.json';policy_path.write_text(json.dumps({'version':1,'node_id':'edge-a','realms':realms,'trusted_proxies':['127.0.0.1/32'],
            'password_file':str(ROOT/'docs/security-seeds/weak-passwords.sha256'),'admin_key_file':str(admin_file),'max_entries':4096,'max_inflight':32}))
        backend_config=root/'backend.json';backend_config.write_text(json.dumps({'address':f'127.0.0.1:{port}',
            'password_file':str(ROOT/'docs/security-seeds/weak-passwords.sha256'),'control':str(control),'realms':backend_realms}))
        class Review(fixture.Review):
            def config(self):
                text=super().config().replace('scdn_api_zone api_counters 64k;',f'''scdn_api_zone api_counters 64k;
 scdn_auth_policy {policy_path}; scdn_auth_zone authentication 8m;
 server {{ listen unix:{control}; scdn_auth_guard off; location = / {{ scdn_auth_control; }} location = /status {{ scdn_auth_status; }} }}''')
                text=text.replace(f'server 127.0.0.1:{self.origins[0].server_port}; keepalive 16;',f'server 127.0.0.1:{port}; keepalive 16;')
                text=text.replace('proxy_read_timeout 3s;','proxy_read_timeout 25s;')
                return text.replace('  scdn_edge on;','''  scdn_edge on;
  scdn_auth_guard sub;
  location /api/user/ { scdn_auth_guard new; }
  location /api/oauth/ { scdn_auth_guard new; }
  location = /api/verification { scdn_auth_guard new; }
  location = /api/reset_password { scdn_auth_guard new; }
  location /off/ { scdn_auth_guard off; }''')
        review=Review(root,args.prefix,args.static)
        backend_log=(root/'backend.log').open('w')
        backend=subprocess.Popen([str(args.backend),'-config',str(backend_config)],stdout=backend_log,stderr=subprocess.STDOUT)
        def stats():
            connection=http.client.HTTPConnection('127.0.0.1',port,timeout=3);connection.request('GET','/__fixture/stats');response=connection.getresponse();data=response.read();connection.close();return json.loads(data)
        def status():
            connection=http.client.HTTPConnection('localhost',timeout=3);connection.sock=socket.socket(socket.AF_UNIX)
            connection.sock.settimeout(3);connection.sock.connect(str(control));connection.request('GET','/status');response=connection.getresponse();data=response.read();connection.close();return json.loads(data)
        def post(path,payload,ip='198.51.100.10',headers=None,host='www.example.test',chunked=False):
            data=payload if isinstance(payload,bytes) else json.dumps(payload).encode()
            result=review.request(path,'POST',data,{'Content-Type':'application/json','X-Forwarded-For':ip,**(headers or {})},host=host,chunked=chunked)
            last.update(path=path,status=result[0],body=result[2].decode(errors='replace'))
            return result
        try:
            for _ in range(600):
                try:stats();break
                except OSError:
                    if backend.poll() is not None:raise AssertionError('Go fixture exited')
                    time.sleep(.05)
            else:
                backend.send_signal(signal.SIGQUIT);backend.wait(timeout=5)
                raise AssertionError('Go fixture did not start')
            policy_spec=importlib.util.spec_from_file_location('auth_policy_snapshot',ROOT/'native-auth-guard/tools/snapshot_policy.py')
            policy_tool=importlib.util.module_from_spec(policy_spec);policy_spec.loader.exec_module(policy_tool)
            exported=policy_tool.snapshot({'version':1,'node_id':'edge-a','password_file':str(ROOT/'docs/security-seeds/weak-passwords.sha256'),
                'realms':[{'id':item['id'],'adapter':item['policy']['adapter'],'key_file':item['key_file'],'exporter_url':f"http://127.0.0.1:{port}/__fixture/policy/{item['id']}"} for item in backend_realms]})
            check('dedicated exporter interoperates with fresh signed policy snapshot',len(exported['realms'])==2 and exported['realms'][0]['revision']=='sub-v1')
            check('minimal snapshot carries no root credential or key bytes','key' not in exported and admin.hex() not in json.dumps(exported))
            review.start()
            for prefix,verify in [('/api/v1/auth','verify_code'),('/api/user','verification_code')]:
                good={'email':'person@example.com','username':'person','password':'a-unique-fixture-password',verify:'verified'}
                before=stats()
                code,headers,body=post(prefix+'/register',{**good,'password':'123456'},ip='198.51.100.11')
                check(prefix+' weak password rejected before backend',code==400 and 'WEAK_PASSWORD' in body.decode() and stats()['seen']==before['seen'] and stats()['created']==before['created'])
                code,_,_=post(prefix+'/register',{**good,'email':'person@'+'temporary.example'},ip='198.51.100.12')
                check(prefix+' unsupported email rejected before backend',code==403 and stats()['created']==before['created'])
                code,_,_=post(prefix+'/register',{**good,verify:'wrong'},ip='198.51.100.13')
                check(prefix+' unverified mailbox creates no account',code==400 and stats()['created']==before['created'])
                code,headers,body=post(prefix+'/register',good,ip='198.51.100.14')
                check(prefix+' verified create reaches actual Go guard and gate',code==200 and stats()['created']==before['created']+1 and status()['precreated']>0)
                check(prefix+' private feedback does not reach client',not any(name.startswith('x-scdn-auth-') for name in headers))
                check(prefix+' auth response is uncached','no-store' in headers.get('cache-control',''))
                code,_,body=post(prefix+'/login',{'email':'legacy@example.com','username':'legacy','password':'123456'},ip='198.51.100.15')
                check(prefix+' existing weak password can still authenticate',code==200 and json.loads(body)['success'])
            code,_,_=post('/api/user/login',{'username':'encrypted','password_encrypted':'fixture-encrypted-valid'},ip='198.51.100.16')
            check('encrypted login preserved without edge decryption',code==200)
            before=stats()['created']
            for index in range(3):post('/api/v1/auth/register',{'email':f'person{index}@unsupported.example','password':'a-unique-fixture-password','verify_code':'verified'},ip='198.51.100.20')
            code,_,_=post('/api/v1/auth/register',{'email':'normal@example.com','password':'a-unique-fixture-password','verify_code':'verified'},ip='198.51.100.20')
            check('abnormal multi-email registration blocks IP before creation',code==403 and stats()['created']==before)
            time.sleep(1.0);post('/api/v1/auth/login',{'email':'legacy@example.com','password':'123456'},ip='198.51.100.20');time.sleep(1.2)
            code,_,_=post('/api/v1/auth/register',{'email':'normal@example.com','password':'a-unique-fixture-password','verify_code':'verified'},ip='198.51.100.20')
            check('blocked retries do not extend original IP deadline',code==200)
            for index in range(3):post('/api/v1/auth/login',{'email':'cooldown@example.com','password':'incorrect'},ip='198.51.100.21')
            before=stats()['seen'];code,_,_=post('/api/v1/auth/login',{'email':'cooldown@example.com','password':'123456'},ip='198.51.100.21')
            check('confirmed password failures cool down only the combination',code==429 and stats()['seen']==before)
            for simulate in ('dependency','limited','factor','forged'):
                for _ in range(4):post('/api/v1/auth/login',{'email':simulate+'@example.com','password':'a-unique-fixture-password','simulate':simulate},ip='198.51.100.22')
                code,_,_=post('/api/v1/auth/login',{'email':simulate+'@example.com','password':'123456'},ip='198.51.100.22')
                check(simulate+' is not password-failure evidence',code==200)
            check('invalid or absent feedback is observable',status()['feedback_bad']>0)
            before=stats()['seen']
            for body in (b'{"email":"one@example.com","Email":"two@example.com","password":"a-unique-fixture-password"}',
                         b'{"email":"one@example.com","password":"a-unique-fixture-password","password":"123456"}'):
                check('duplicate credential input rejected '+str(len(checks)),post('/api/v1/auth/register',body,ip='198.51.100.23')[0]==400)
            check('duplicate fields never reach backend',stats()['seen']==before)
            payload={'email':'fragment@example.com','password':'a-unique-fixture-password','verify_code':'verified'}
            raw=json.dumps(payload).encode();code,_,_=review.request('/api/v1/auth/register','POST',(raw[:13],raw[13:]),{'Content-Type':'application/json','X-Forwarded-For':'198.51.100.24'},chunked=True)
            check('bounded chunked JSON preserves Go body MAC and creates once',code==200)
            code,_,_=post('/api/v1/auth/register',b'{"email":"large@example.com","padding":"'+b'x'*17000+b'"}',ip='198.51.100.25')
            check('auth body budget is enforced independently of AI body limits',code==413)
            before=stats()['created'];code,_,_=post('/api/v1/auth/register',payload,ip='198.51.100.26',headers={'X-SCDN-Auth-Request':'forged'})
            check('client cannot replace internal admission metadata',code==200 and stats()['created']==before+1)
            with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
                results=list(pool.map(lambda i:post('/api/v1/auth/login',{'email':f'held{i}@example.com','password':'incorrect','simulate':'hold'},ip='198.51.100.30')[0],range(12)))
            check('concurrent guesses cannot all pass before failures arrive',results.count(401)<=4 and any(code in (429,503) for code in results))
            before=stats()['created']
            for path in ('/api/v1/auth/oauth/google/create-account','/api/oauth/fixture'):
                code,_,_=post(path,{'email':'oauth@example.com','simulate':'oauth-create','verify_code':'verified'},ip='198.51.100.40')
                check(path+' retains live attempt through OAuth create gate',code==200)
            check('OAuth ownership fixtures create exactly twice',stats()['created']==before+2)
            code,_,_=post('/api/v1/auth/register',{'email':' PERSON@EXAMPLE.COM ','password':'a-unique-fixture-password','verify_code':'verified'},ip='198.51.100.41')
            check('mailbox normalization agrees at edge and backend',code==200)
            for domain in ('enterprise.example','team.enterprise.example'):
                code,_,_=post('/api/v1/auth/register',{'email':'person@'+domain,'password':'a-unique-fixture-password','verify_code':'verified'},ip='198.51.100.42')
                check('upstream wildcard accepts '+domain,code==200)
            code,_,_=post('/api/v1/auth/register',{'email':'person@'+'enterprise.example.attacker.example','password':'a-unique-fixture-password','verify_code':'verified'},ip='198.51.100.42')
            check('domain suffix does not accept appended attacker domain',code==403)
            code,_,_=post('/api/v1/auth/register',{'email':'person@example.com','password':'123456 ','verify_code':'verified'},ip='198.51.100.43')
            check('weak-password lookup does not trim or fold the password',code==200)
            for extra in (b'"pass\\u0077ord":"123456"', '"paſſword":"123456"'.encode()):
                raw=b'{"email":"encoded@example.com","password":"a-unique-fixture-password",'+extra+b'}'
                check('Go-folded duplicate credential never reaches backend '+str(len(checks)),post('/api/v1/auth/register',raw,ip='198.51.100.44')[0]==400)
            before=stats()['seen']
            code,_,_=post('/api/v1/auth/login',{'email':'legacy@example.com','password':'123456'},headers={'Content-Encoding':'gzip'},ip='198.51.100.45')
            check('compressed credentials are rejected without backend work',code==415 and stats()['seen']==before)
            for i in range(3):post('/api/user/login',{'username':'same-user','email':f'irrelevant{i}@example.com','password':'incorrect'},ip='198.51.100.46')
            code,_,_=post('/api/user/login',{'username':'same-user','email':'different@example.com','password':'123456'},ip='198.51.100.46')
            check('extra email cannot evade NewAPI username cooldown',code==429)
            for i in range(3):post('/api/v1/auth/login/2fa',{'temp_token':'fixture-session','email':f'irrelevant{i}@example.com','simulate':'factor-invalid'},ip='198.51.100.47')
            code,_,_=post('/api/v1/auth/login/2fa',{'temp_token':'fixture-session','email':'different@example.com','simulate':'factor-invalid'},ip='198.51.100.47')
            check('factor budget follows opaque session instead of extra email',code==429)
            code,_,_=post('/api/user/login',{'username':'same-user','password':'123456'},ip='198.51.100.48')
            check('combination cooldown does not lock account at other IPs',code==200)
            for i in range(3):post('/api/v1/auth/register',{'email':f'rejected{i}@unsupported.example','password':'a-unique-fixture-password'},ip='198.51.100.49')
            code,_,_=post('/api/user/register',{'email':'normal@example.com','password':'a-unique-fixture-password','verification_code':'verified'},ip='198.51.100.49')
            check('registration IP ban is isolated by configured realm',code==200)
            before=stats()['created']
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                pending=pool.submit(post,'/api/v1/auth/register',{'email':'held-create@example.com','password':'a-unique-fixture-password','verify_code':'verified','simulate':'hold'},'198.51.100.51')
                deadline=time.monotonic()+1
                while not stats()['active'] and time.monotonic()<deadline:time.sleep(.01)
                for i in range(9):post('/api/v1/auth/register',{'email':f'bad{i}@unsupported.example','password':'a-unique-fixture-password'},ip='198.51.100.51')
                check('pre-create gate catches IP ban raised during upstream verification',pending.result()[0]==403 and stats()['created']==before)
            body=json.dumps({'realm':'sub','operation':'unban','ip':'198.51.100.49','time':int(time.time())}).encode()
            connection=http.client.HTTPConnection('localhost',timeout=3);connection.sock=socket.socket(socket.AF_UNIX);connection.sock.settimeout(3);connection.sock.connect(str(control))
            connection.request('POST','/',body,{'X-SCDN-Auth-Control':hmac.new(admin,b'admin:'+body,hashlib.sha256).hexdigest()})
            response=connection.getresponse();data=response.read();connection.close()
            check('separate administrator key can clear local IP risk',response.status==200 and json.loads(data)['reason']=='ALLOWED')
            code,_,_=post('/api/v1/auth/register',{'email':'normal@example.com','password':'a-unique-fixture-password','verify_code':'verified'},ip='198.51.100.49')
            check('manual unban takes effect before fixed ban expiry',code==200)
            deadline=time.monotonic()+4
            while status()['active'] and time.monotonic()<deadline:time.sleep(.05)
            check('all reservations released exactly once',status()['active']==0)
            check('ordinary non-auth traffic stays available',review.request('/asset')[0]==200)
            check('early rejection never reinterprets a credential body as request line','client sent invalid method' not in (root/'error.log').read_text())
            # A slow upstream must not retain scarce attempts indefinitely.
            connection=http.client.HTTPConnection('127.0.0.1',review.http,timeout=20)
            started=time.monotonic();connection.request('POST','/api/v1/auth/login',json.dumps({'email':'slow@example.com','password':'incorrect','simulate':'timeout'}),{'Host':'www.example.test','Content-Type':'application/json','X-Forwarded-For':'198.51.100.50'})
            response=connection.getresponse();response.read();connection.close()
            check('15 second deadline cancels slow authentication upstream',response.status==504 and 13<=time.monotonic()-started<19)
            check('deadline releases reservation',status()['active']==0)
            connection=http.client.HTTPConnection('127.0.0.1',review.http,timeout=3)
            connection.request('POST','/api/v1/auth/login',json.dumps({'email':'crash@example.com','password':'incorrect','simulate':'timeout'}),{'Host':'www.example.test','Content-Type':'application/json','X-Forwarded-For':'198.51.100.52'})
            deadline=time.monotonic()+2
            while not status()['active'] and time.monotonic()<deadline:time.sleep(.01)
            check('live attempt exists before worker fault',status()['active']==1)
            children=Path(f'/proc/{review.process.pid}/task/{review.process.pid}/children').read_text().split()
            worker=next(int(pid) for pid in children if b'worker process' in Path('/proc/'+pid+'/cmdline').read_bytes())
            os.kill(worker,signal.SIGKILL);connection.close()
            deadline=time.monotonic()+19
            while time.monotonic()<deadline:
                try:
                    if status()['active']==0:break
                except OSError:pass
                time.sleep(.05)
            check('replacement worker sweeps crashed worker reservation',status()['active']==0)
            check('worker replacement serves new logins',post('/api/v1/auth/login',{'email':'legacy@example.com','password':'123456'},ip='198.51.100.53')[0]==200)
            review.process.send_signal(signal.SIGQUIT);review.process.wait(timeout=5)
            check('periodic sweep permits bounded graceful worker shutdown',review.process.returncode==0)
            standalone=root/'standalone';standalone.mkdir();(standalone/'logs').mkdir()
            standalone_port=fixture.unused_port()
            module_dir=args.prefix/('nginx/modules' if (args.prefix/'nginx/sbin/nginx').exists() else 'modules')
            load='' if args.static else f'load_module {module_dir}/ngx_http_scdn_auth_guard_module.so;'
            proxy=f'location / {{ proxy_pass http://127.0.0.1:{port}; proxy_http_version 1.1; proxy_next_upstream off; proxy_read_timeout 25s; }}'
            configuration=f'''{load}
worker_processes 2; pid {standalone}/nginx.pid; error_log {standalone}/error.log info;
events {{ worker_connections 128; }}
http {{ access_log off; scdn_auth_policy {policy_path}; scdn_auth_zone standalone_auth 8m;
 server {{ listen unix:{control}; location = / {{ scdn_auth_control; }} location = /status {{ scdn_auth_status; }} }}
 server {{ listen 127.0.0.1:{standalone_port}; server_name enforce.example.test; scdn_auth_guard sub; {proxy} }}
 server {{ listen 127.0.0.1:{standalone_port}; server_name observe.example.test; scdn_auth_guard sub; scdn_auth_mode observe; {proxy} }}
}}'''
            conf=standalone/'nginx.conf';conf.write_text(configuration)
            process=subprocess.Popen([str(review.nginx),'-p',str(standalone),'-c',str(conf),'-g','daemon off;'],stdout=backend_log,stderr=backend_log)
            saved_port=review.http;review.http=standalone_port
            try:
                deadline=time.monotonic()+5
                while time.monotonic()<deadline:
                    try:status();break
                    except OSError:
                        if process.poll() is not None:raise AssertionError('standalone Auth Guard startup failed')
                        time.sleep(.02)
                before=stats()['created'];payload={'email':'standalone@example.com','password':'a-unique-fixture-password','verify_code':'verified'}
                check('Auth Guard independently reads body and gates actual creation',post('/api/v1/auth/register',payload,ip='198.51.100.60',host='enforce.example.test')[0]==200 and stats()['created']==before+1)
                with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
                    results=list(pool.map(lambda i:post('/api/v1/auth/login',{'email':f'parallel{i}@example.com','password':'incorrect','simulate':'hold'},ip='198.51.100.61',host='enforce.example.test')[0],range(12)))
                check('two independent workers share one IP concurrency budget',results.count(401)<=4 and any(code in (429,503) for code in results))
                for i in range(3):post('/api/v1/auth/register',{'email':f'reject{i}@unsupported.example','password':'a-unique-fixture-password'},ip='198.51.100.62',host='enforce.example.test')
                check('standalone enforce applies the shared IP block',post('/api/v1/auth/register',payload,ip='198.51.100.62',host='enforce.example.test')[0]==403)
                check('observe attempt passes dynamic IP block at pre-create',post('/api/v1/auth/register',payload,ip='198.51.100.62',host='observe.example.test')[0]==200)
                check('observe never bypasses actual mailbox ownership',post('/api/v1/auth/register',{**payload,'verify_code':'wrong'},ip='198.51.100.63',host='observe.example.test')[0]==400)
            finally:
                review.http=saved_port
                if process.poll() is None:process.send_signal(signal.SIGQUIT)
                process.wait(timeout=5)
                check('standalone sweep also allows two-worker graceful exit',process.returncode==0)
        except Exception:
            for name in ('error.log','process.log','backend.log','standalone/error.log'):
                path=root/name
                if path.exists():print(name+'\n'+path.read_text(errors='replace')[-6000:])
            raise
        finally:
            review.close()
            if backend.poll() is None:backend.terminate()
            backend.wait(timeout=5);backend_log.close()
    result={'passed':True,'check_count':len(checks),'checks':checks,'real_accounts':0,'mail_delivery':False,'production_modified':False,'durable_ip_bans':False}
    args.report.parent.mkdir(parents=True,exist_ok=True);args.report.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'passed':True,'check_count':len(checks)}))


if __name__=='__main__':main()
