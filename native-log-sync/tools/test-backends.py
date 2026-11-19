#!/usr/bin/env python3
"""Create isolated loopback-only backend containers and remove them afterward."""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--build',type=Path,required=True);parser.add_argument('--report',type=Path,required=True)
    args=parser.parse_args();name='scdn-log-'+uuid.uuid4().hex[:12]
    def port():
        s=socket.socket();s.bind(('127.0.0.1',0));value=s.getsockname()[1];s.close();return value
    es_port,ch_port,tcp_port,transport_port,interserver_port=[port() for _ in range(5)]
    containers=[]
    def docker(*cmd):return subprocess.run(['docker',*cmd],capture_output=True,text=True)
    with tempfile.TemporaryDirectory(prefix='scdn-log-backends-') as directory:
        root=Path(directory);config=root/'clickhouse.xml'
        config.write_text(f'<clickhouse><listen_host replace="replace">127.0.0.1</listen_host><http_port>{ch_port}</http_port><tcp_port>{tcp_port}</tcp_port><interserver_http_port>{interserver_port}</interserver_http_port><max_server_memory_usage>1073741824</max_server_memory_usage><max_thread_pool_size>256</max_thread_pool_size><background_schedule_pool_size>16</background_schedule_pool_size><background_buffer_flush_schedule_pool_size>4</background_buffer_flush_schedule_pool_size><background_message_broker_schedule_pool_size>4</background_message_broker_schedule_pool_size><background_distributed_schedule_pool_size>4</background_distributed_schedule_pool_size></clickhouse>')
        try:
            specifications=[(name+'-ch',['--env','CLICKHOUSE_SKIP_USER_SETUP=1','-v',str(config)+':/etc/clickhouse-server/config.d/scdn-test.xml:ro',
                'clickhouse/clickhouse-server:25.8-alpine@sha256:87e0a5b72f5465b18eacca7c76850e7ff551c9795c50e451f5646299e5e24146']),
                (name+'-es',['--env','discovery.type=single-node','--env','xpack.security.enabled=false','--env','xpack.ml.enabled=false',
                '--env','node.store.allow_mmap=false','--env','network.host=127.0.0.1','--env','http.port='+str(es_port),
                '--env','transport.port='+str(transport_port),'--env','ES_JAVA_OPTS=-Xms512m -Xmx512m',
                'docker.elastic.co/elasticsearch/elasticsearch:8.17.4@sha256:413d8df69823e9f41f6008f025fcbaf31a5849ab9c74894731d7ded65543cd56'])]
            for container,options in specifications:
                containers.append(container)
                result=docker('run','-d','--network','host','--name',container,*options)
                assert result.returncode==0,result.stderr[-2000:]
            urls=[f'http://127.0.0.1:{es_port}',f'http://127.0.0.1:{ch_port}/?query=SELECT%201']
            deadline=time.monotonic()+120;ready=False
            while time.monotonic()<deadline:
                ready=True
                for url in urls:
                    try:
                        with urllib.request.urlopen(url,timeout=2) as response:assert response.status==200
                    except Exception:ready=False
                if ready:break
                time.sleep(.5)
            assert ready,'temporary backend startup timed out'
            script=Path(__file__).resolve().parents[1]/'tests/backends.py'
            result=subprocess.run([sys.executable,str(script),'--build',str(args.build),'--report',str(args.report),
                '--es',f'http://127.0.0.1:{es_port}','--ch',f'http://127.0.0.1:{ch_port}'])
            assert result.returncode==0,'backend compatibility suite failed'
        finally:
            for container in containers:docker('rm','-f',container)

if __name__=='__main__':main()
