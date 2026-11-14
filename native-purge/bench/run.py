#!/usr/bin/env python3
"""Same-runtime loopback measurements. Requires an optimized build and wrk."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import statistics
import subprocess
import tempfile
import threading
import time

spec=importlib.util.spec_from_file_location('purge_fixture',Path(__file__).resolve().parents[1]/'tests/integration.py')
fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)


def duration_ms(value):
    number,unit=re.fullmatch(r'([0-9.]+)(us|ms|s)',value).groups()
    return float(number)*{'us':0.001,'ms':1.0,'s':1000.0}[unit]


def worker_ticks(review):
    ticks=0
    for pid in review.workers():
        values=Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()
        ticks+=int(values[11])+int(values[12])
    return ticks


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--prefix',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--seconds',type=int,default=5)
    parser.add_argument('--runs',type=int,default=3)
    parser.add_argument('--connections',type=int,default=128)
    parser.add_argument('--threads',type=int,default=2)
    parser.add_argument('--purges-per-second',type=int,default=20)
    parser.add_argument('--body-bytes',type=int,default=16384)
    args=parser.parse_args()
    prefix=args.prefix/'nginx' if (args.prefix/'nginx/sbin/nginx').exists() else args.prefix
    with tempfile.TemporaryDirectory(prefix='scdn-purge-bench-') as directory:
        review=fixture.Review(Path(directory),prefix.resolve())
        review.origin.bench_bytes=args.body_bytes
        config=review.config
        review.config=lambda allow_all=True:config(allow_all).replace('scdn_purge_checkpoint 64k;','scdn_purge_checkpoint 64m;')
        stop=threading.Event();mutations=[]
        def mutate():
            index=0
            while not stop.is_set():
                start=time.perf_counter()
                status,_=review.control('exact',scope='other-site',keys=[f'/background/{index}'])
                mutations.append(status);index+=1
                stop.wait(max(0,1/args.purges_per_second-(time.perf_counter()-start)))
        try:
            review.start()
            runtime=subprocess.run([str(review.nginx),'-V'],capture_output=True,text=True,check=True).stderr
            if '-fsanitize' in runtime:raise AssertionError('benchmark requires an optimized build without sanitizers')
            for path in ('/baseline/hit','/bench/hit'):review.fill(path)
            measurements=[]
            for run in range(args.runs):
                scenarios=[('baseline','/baseline/hit',False),('versioned','/bench/hit',False),
                           ('versioned_with_purges','/bench/hit',True)]
                # Alternate ordinary baseline/guarded order to reduce ordering bias.
                if run%2:scenarios[0],scenarios[1]=scenarios[1],scenarios[0]
                for name,path,purging in scenarios:
                    stop.clear();thread=None
                    if purging:thread=threading.Thread(target=mutate);thread.start()
                    try:
                        cpu_before=worker_ticks(review)
                        result=subprocess.run(['wrk','--latency','-t',str(args.threads),'-c',str(args.connections),
                            '-d',f'{args.seconds}s','-H','X-Scope: one',
                            f'http://127.0.0.1:{review.http}'+path],capture_output=True,text=True,check=True)
                        cpu_after=worker_ticks(review)
                    finally:
                        stop.set()
                        if thread:thread.join()
                    text=result.stdout
                    qps=float(re.search(r'Requests/sec:\s+([0-9.]+)',text).group(1))
                    requests=int(re.search(r'(\d+) requests in',text).group(1))
                    cpu_us=(cpu_after-cpu_before)/os.sysconf('SC_CLK_TCK')*1e6/requests
                    p99=duration_ms(re.search(r'99%\s+([0-9.]+(?:us|ms|s))',text).group(1))
                    sockets=re.search(r'Socket errors: (.+)',text)
                    errors=re.search(r'Non-2xx or 3xx responses: (\d+)',text)
                    if sockets or errors:raise AssertionError(text)
                    measurements.append(dict(scenario=name,run=run+1,qps=qps,p99_ms=p99,server_cpu_us_per_request=cpu_us))
                    print(json.dumps(measurements[-1]),flush=True)
            api=[]
            for batch in (1,32,256):
                latencies=[]
                def purge(index):
                    start=time.perf_counter()
                    status,_=review.control('exact',scope='api-benchmark',keys=[f'/batch/{index}/{i}' for i in range(batch)])
                    elapsed=(time.perf_counter()-start)*1000
                    if status!=200:raise AssertionError(status)
                    return elapsed
                start=time.perf_counter()
                with ThreadPoolExecutor(max_workers=16) as pool:latencies=list(pool.map(purge,range(48)))
                elapsed=time.perf_counter()-start
                api.append(dict(batch=batch,clients=16,requests=48,requests_per_second=48/elapsed,
                                keys_per_second=48*batch/elapsed,median_ms=statistics.median(latencies),max_ms=max(latencies)))
            summary={}
            for name in ('baseline','versioned','versioned_with_purges'):
                values=[v for v in measurements if v['scenario']==name]
                summary[name]=dict(median_qps=statistics.median(v['qps'] for v in values),
                                   median_p99_ms=statistics.median(v['p99_ms'] for v in values),
                                   median_server_cpu_us=statistics.median(v['server_cpu_us_per_request'] for v in values))
            summary['versioned_qps_ratio']=summary['versioned']['median_qps']/summary['baseline']['median_qps']
            data=dict(environment=dict(os=platform.system(),machine=platform.machine(),runtime=runtime.splitlines()[:3],
                workers=2,body_bytes=args.body_bytes+3,connections=args.connections,client_threads=args.threads,
                seconds=args.seconds,runs=args.runs,purges_per_second=args.purges_per_second),
                summary=summary,measurements=measurements,api=api,
                background_purges=len(mutations),background_failures=sum(status!=200 for status in mutations),
                limitations='Same-host loopback, warm single-key HIT, client/server share CPU; not a production capacity or universal minimum-overhead proof.')
            args.output.parent.mkdir(parents=True,exist_ok=True)
            args.output.write_text(json.dumps(data,indent=2)+'\n')
            print(json.dumps(dict(summary=summary,api=api),indent=2),flush=True)
        finally:review.close()


if __name__=='__main__':main()
