#!/usr/bin/env python3
"""Reproduce an HTTP-ready first worker while a real second worker is gated."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor,TimeoutError
import http.client
import json
import os
from pathlib import Path
import socket
import signal
import subprocess
import tempfile
import time

from nginx_process import (assert_clean_startup,dump_runtime_logs,
                           runtime_log_offsets,wait_for_workers,worker_pids)


def run(root,nginx):
    checks=[]

    def check(name,condition):
        if not condition:raise AssertionError(name)
        checks.append(name);print('PASS '+name,flush=True)

    helper=root/'worker-startup-delay.so'
    subprocess.run(['cc','-shared','-fPIC','-std=c99','-Wall','-Wextra','-Werror',
                    str(Path(__file__).with_name('worker-startup-delay.c')),
                    '-ldl','-o',str(helper)],capture_output=True,text=True,check=True)
    runtime=subprocess.run([str(nginx),'-V'],capture_output=True,text=True,check=True).stderr
    env=dict(os.environ)
    preload=str(helper)
    if '-fsanitize=address' in runtime:
        asan=subprocess.check_output(['cc','-print-file-name=libasan.so'],text=True).strip()
        preload=asan+':'+preload
    env['LD_PRELOAD']=preload
    gate=root/'release-worker';waiting=root/'release-worker.waiting'
    env['SCDN_TEST_WORKER_GATE']=str(gate)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    config=root/'nginx.conf'
    user='user root root;' if os.geteuid()==0 else ''
    config.write_text(f'''{user}
worker_processes 2;
pid {root}/nginx.pid;
error_log {root}/error.log warn;
events {{ worker_connections 64; }}
http {{ access_log off;
    server {{ listen 127.0.0.1:{port}; location / {{ return 204; }} }}
}}
''')
    with (root/'stdout.log').open('wb') as log:
        offsets=runtime_log_offsets(root)
        process=subprocess.Popen([str(nginx),'-p',str(root)+'/', '-c',str(config),
                                  '-g','daemon off;'],stdout=log,stderr=log,env=env)
        try:
            deadline=time.monotonic()+10
            while True:
                if process.poll() is not None:raise AssertionError('nginx exited before gated startup')
                if waiting.exists():
                    connection=http.client.HTTPConnection('127.0.0.1',port,timeout=1)
                    try:
                        connection.request('GET','/')
                        response=connection.getresponse();response.read()
                        if response.status==204:break
                    except (OSError,http.client.HTTPException):pass
                    finally:connection.close()
                if time.monotonic()>=deadline:raise AssertionError('first worker readiness deadline')
                time.sleep(0.01)
            first=worker_pids(process.pid)
            check('HTTP readiness does not imply both workers initialized',len(first)==1)
            try:
                wait_for_workers(process,timeout=0.1)
            except AssertionError as error:
                check('a missing worker fails with a bounded startup deadline',
                      'expected 2, observed 1' in str(error))
            else:raise AssertionError('missing worker was accepted')
            with ThreadPoolExecutor(max_workers=1) as pool:
                pending=pool.submit(wait_for_workers,process,timeout=5)
                try:
                    pending.result(timeout=0.1)
                except TimeoutError:
                    check('startup waits while the second worker remains gated',True)
                else:raise AssertionError('startup returned a partial PID baseline')
                gate.touch()
                workers=pending.result(timeout=5)
            check('releasing the second worker produces a complete PID baseline',
                  len(workers)==2 and first.issubset(workers))
            assert_clean_startup(root,offsets)
            killed=next(iter(workers));os.kill(killed,signal.SIGKILL)
            deadline=time.monotonic()+5
            while True:
                current=worker_pids(process.pid)
                if len(current)==2 and killed not in current:break
                if time.monotonic()>=deadline:raise AssertionError('worker respawn deadline')
                time.sleep(0.01)
            try:
                assert_clean_startup(root,offsets)
            except AssertionError as error:
                check('a crash followed by respawn cannot hide a startup failure',
                      'nginx worker failed during startup' in str(error))
            else:raise AssertionError('a crashed worker was accepted as a clean startup')
            process.terminate();process.wait(timeout=8)
            try:
                wait_for_workers(process)
            except AssertionError as error:
                check('an exited master fails instead of waiting for readiness',
                      'nginx exited during worker startup' in str(error))
            else:raise AssertionError('an exited master was accepted')
        except Exception:
            dump_runtime_logs(root)
            raise
        finally:
            gate.touch()
            if process.poll() is None:
                process.terminate()
                try:process.wait(timeout=8)
                except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
    return checks


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--prefix',required=True,type=Path)
    parser.add_argument('--report',type=Path)
    args=parser.parse_args()
    prefix=args.prefix/'nginx' if (args.prefix/'nginx/sbin/nginx').exists() else args.prefix
    with tempfile.TemporaryDirectory(prefix='scdn-worker-startup-') as directory:
        checks=run(Path(directory),prefix.resolve()/'sbin/nginx')
    if args.report:
        args.report.parent.mkdir(parents=True,exist_ok=True)
        args.report.write_text(json.dumps(dict(passed=len(checks),checks=checks),indent=2)+'\n')
    print(f'{len(checks)} worker startup checks passed',flush=True)


if __name__=='__main__':main()
