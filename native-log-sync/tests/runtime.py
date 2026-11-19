#!/usr/bin/env python3
"""A standalone native module sends real Nginx JSON logs from two workers."""
import argparse
import http.client
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time

from core import Backend
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tests'))
from nginx_process import unused_listen_port


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--prefix',type=Path,required=True)
    parser.add_argument('--static',action='store_true');parser.add_argument('--report',type=Path,required=True)
    args=parser.parse_args();prefix=args.prefix/'nginx' if (args.prefix/'nginx/sbin/nginx').exists() else args.prefix
    binary=prefix/'sbin/nginx';checks=[];backend=Backend()
    threading.Thread(target=backend.serve_forever,daemon=True).start()
    def check(name,value):assert value,name;checks.append(name)
    with tempfile.TemporaryDirectory(prefix='scdn-log-runtime-') as directory:
        root=Path(directory);(root/'logs').mkdir();state=root/'state';state.mkdir(mode=0o700)
        config={'node':'test-node','state_dir':str(state),'line_bytes':262144,'batch_bytes':4*1024*1024,
            'sources':[{'id':'access','kind':'access','paths':[str(root/'access.jsonl')]}],
            'sinks':[{'id':'es','type':'elasticsearch','endpoint':f'http://127.0.0.1:{backend.server_port}','allow_http':True}],
            'telemetry':{'interval_ms':100,'pid_file':str(root/'nginx.pid'),'cache_path':str(root),
                'rotate_bytes':65536,'spool_bytes':4*1024*1024}}
        (root/'sender.json').write_text(json.dumps(config));port=unused_listen_port()
        load='' if args.static else f'load_module {prefix}/modules/ngx_http_scdn_log_sync_module.so;'
        nginx=f'''{load}
{'user root root;' if os.geteuid()==0 else ''}
worker_processes 2; pid {root}/nginx.pid;
error_log {root}/error.log notice;
events {{ worker_connections 128; }}
http {{ scdn_log_sync_config {root}/sender.json; scdn_log_sync_interval 20ms;
 log_format json escape=json '{{"time":"$time_iso8601","request_id":"$request_id","client_ip":"$remote_addr","host":"$host","uri":"$uri","status":$status,"bytes":$body_bytes_sent,"rt":$request_time,"site_id":"fixture"}}';
 access_log {root}/access.jsonl json;
 server {{ listen 127.0.0.1:{port};
  location = /status {{ access_log off; scdn_log_sync_status; }}
  location / {{ return 200 "fixture"; }}
 }}
}}'''
        path=root/'nginx.conf';path.write_text(nginx)
        result=subprocess.run([str(binary),'-t','-p',str(root),'-c',str(path)],capture_output=True,text=True)
        check('new module config validates standalone',result.returncode==0)
        output=(root/'process.log').open('wb')
        process=subprocess.Popen([str(binary),'-p',str(root),'-c',str(path),'-g','daemon off;'],stdout=output,stderr=output)
        def request(path='/status'):
            connection=http.client.HTTPConnection('127.0.0.1',port,timeout=3)
            connection.request('GET',path,headers={'Host':'fixture.example.test'})
            response=connection.getresponse();data=response.read();status=response.status;connection.close()
            return status,data
        try:
            deadline=time.monotonic()+10
            while time.monotonic()<deadline:
                try:
                    status,data=request()
                    if status==200 and json.loads(data)['running']==1:break
                except OSError:pass
                time.sleep(.05)
            check('native sender status responds while the worker event loop runs',json.loads(data)['running']==1)
            for i in range(24):check('business request '+str(i),request('/event-'+str(i))[0]==200)
            deadline=time.monotonic()+12
            while time.monotonic()<deadline:
                access=[e for e in backend.ids.values() if e['kind']=='access']
                samples=[e for e in backend.ids.values() if e['kind']=='metrics']
                if len(access)==24 and len(samples)>=2:break
                time.sleep(.05)
            check('two workers deliver each real access record with a stable identity',len(access)==24)
            check('metrics share the direct delivery pipeline',len(samples)>=2)
            check('the actual Nginx TCP socket count is available',any(e['fields']['connections']['nginx_tcp_sockets'] is not None for e in samples))
            backend.slow=True
            started=time.monotonic();request('/backend-slow')
            check('slow database I/O does not block Nginx business requests',time.monotonic()-started<.5)
            backend.slow=False
            process.send_signal(signal.SIGHUP)
            time.sleep(.5)
            for i in range(4):request('/after-reload-'+str(i))
            deadline=time.monotonic()+10
            while time.monotonic()<deadline:
                access=[e for e in backend.ids.values() if e['kind']=='access']
                if len(access)>=29:break
                time.sleep(.05)
            check('graceful reload retains durable cursors and continues new requests',len(access)==29)
        finally:
            process.send_signal(signal.SIGQUIT)
            try:process.wait(timeout=10)
            except subprocess.TimeoutExpired:process.kill();process.wait();raise
            output.close()
        check('all background sender threads allow graceful exit',process.returncode==0)
    backend.shutdown();backend.server_close()
    args.report.parent.mkdir(parents=True,exist_ok=True)
    args.report.write_text(json.dumps({'passed':True,'check_count':len(checks),'checks':checks,
        'linkage':'static' if args.static else 'dynamic','real_vendor_data':False},indent=2)+'\n')
    print(json.dumps({'passed':True,'check_count':len(checks)}))


if __name__=='__main__':main()
