#!/usr/bin/env python3
"""Same-runtime HIT comparison with actual periodic conditional GETs."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import statistics
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tests'))
from revalidate import Revalidation
from run import duration_ms, worker_ticks


class OriginBenchmark(Revalidation):
    def config(self, allow_all=True):
        config=super().config(allow_all).replace('scdn_purge_revalidate 1s;', 'scdn_purge_revalidate 2s;')
        location=f'''location /versioned/ {{
            scdn_purge_key "$http_x_scope" "$request_uri";
            proxy_pass http://127.0.0.1:{self.origin.server_port};
            proxy_cache l1;proxy_cache_key $scdn_purge_key;proxy_cache_valid 200 1d;
            add_header X-Cache $upstream_cache_status always;
        }}'''
        return config.replace('location /baseline/ {',location+'\nlocation /baseline/ {')


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--prefix',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--seconds',type=int,default=5)
    parser.add_argument('--runs',type=int,default=3)
    parser.add_argument('--connections',type=int,default=128)
    parser.add_argument('--body-bytes',type=int,default=128)
    args=parser.parse_args()
    prefix=args.prefix/'nginx' if (args.prefix/'nginx/sbin/nginx').exists() else args.prefix
    cases=[('native','/baseline/hit'),('versioned','/versioned/hit'),('revalidate','/origin/hit')]
    with tempfile.TemporaryDirectory(prefix='scdn-origin-bench-') as directory:
        review=OriginBenchmark(Path(directory),prefix.resolve())
        try:
            review.start()
            runtime=subprocess.run([str(review.nginx),'-V'],capture_output=True,text=True,check=True).stderr
            if '-fsanitize' in runtime:raise AssertionError('use an optimized build')
            for _,path in cases:
                review.set(path,payload_bytes=args.body_bytes)
                review.fill(path)
            began=time.monotonic()
            while True:
                children=Path(f'/proc/{review.process.pid}/task/{review.process.pid}/children').read_text().split()
                loading=False
                for pid in children:
                    try:loading |= b'nginx: cache loader process' in Path(f'/proc/{pid}/cmdline').read_bytes()
                    except FileNotFoundError:pass
                if not loading:break
                if time.monotonic()-began>75:raise AssertionError('cache loader deadline')
                time.sleep(0.5)
            loader_wait=time.monotonic()-began
            measurements=[]
            for run in range(args.runs):
                order=cases if run%2==0 else list(reversed(cases))
                for name,path in order:
                    # A previously idle resource beyond its SWR window must
                    # validate synchronously. Fence that warmup before timing
                    # the steady HIT + periodic background-update workload.
                    review.fresh(path,1)
                    before=len(review.records(path));cpu_before=worker_ticks(review)
                    measured=subprocess.run(['wrk','--latency','-t','2','-c',str(args.connections),
                        '-d',f'{args.seconds}s','-H','X-Scope: one',
                        f'http://127.0.0.1:{review.http}'+path],capture_output=True,text=True,check=True)
                    cpu_after=worker_ticks(review);output=measured.stdout
                    if 'Socket errors:' in output or 'Non-2xx or 3xx responses:' in output:raise AssertionError(output)
                    requests=int(re.search(r'(\d+) requests in',output).group(1))
                    records=review.records(path)[before:]
                    if name=='revalidate' and not records:raise AssertionError('no conditional requests during measurement')
                    if any(r['status']!=304 or not r['etag'] for r in records):raise AssertionError('expected conditional 304')
                    value=dict(scenario=name,run=run+1,
                        qps=float(re.search(r'Requests/sec:\s+([0-9.]+)',output).group(1)),
                        p99_ms=duration_ms(re.search(r'99%\s+([0-9.]+(?:us|ms|s))',output).group(1)),
                        worker_cpu_us_per_request=(cpu_after-cpu_before)/os.sysconf('SC_CLK_TCK')*1e6/requests,
                        conditional_304=len(records))
                    measurements.append(value);print(json.dumps(value),flush=True)
            summary={name:{field:statistics.median(v[field] for v in measurements if v['scenario']==name)
                     for field in ('qps','p99_ms','worker_cpu_us_per_request')} for name,_ in cases}
            document=dict(runtime=runtime.splitlines()[0],body_bytes=args.body_bytes+3,
                runs=args.runs,seconds=args.seconds,connections=args.connections,workers=2,
                check_interval_seconds=2,loader_wait_seconds=loader_wait,
                measurements=measurements,medians=summary,
                notes='Same-host WSL2/Alpine loopback; per-case freshness warmup; no fault injection; short-run scheduling noise; no regex or idle-burst workload.')
            args.output.write_text(json.dumps(document,indent=2)+'\n')
            print(json.dumps(summary),flush=True)
        finally:review.close()


if __name__=='__main__':main()
