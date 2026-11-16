#!/usr/bin/env python3
"""Storage correctness, I/O faults and real bounded IP workloads."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import tempfile

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--build',required=True,type=Path)
    parser.add_argument('--count',type=int,default=100000);parser.add_argument('--report',type=Path)
    args=parser.parse_args();checks=[];benchmarks=[];assertions=0
    for name in ('store-test','io-test'):
        with tempfile.TemporaryDirectory(prefix='ban-store-verify-') as temporary:
            result=subprocess.run([str(args.build/name),temporary],capture_output=True,text=True,timeout=120)
            if result.returncode:raise AssertionError(result.stdout+result.stderr)
            assertions+=int(re.search(r'CHECKS (\d+)',result.stdout)[1]);checks.extend(re.findall(r'^PASS (.*)$',result.stdout,re.M))
            print(result.stdout,end='',flush=True)
    for mode in ('memory','persistent'):
        with tempfile.TemporaryDirectory(prefix='ban-store-scale-') as temporary:
            target=Path(temporary)/'state'
            if mode=='persistent':target.mkdir(mode=0o700)
            result=subprocess.run([str(args.build/'store-bench'),str(target),mode,str(args.count)],capture_output=True,text=True,timeout=180)
            if result.returncode:raise AssertionError(result.stdout+result.stderr)
            value=json.loads(result.stdout);benchmarks.append(value)
            if mode=='memory':assert not target.exists() and value['data_syncs']==0
            else:assert (target/'ban-store.aof').exists() and value['data_syncs']>0
            checks.append(mode+' large IP workload verifies values and deletes');assertions+=1
            print('PASS '+checks[-1],flush=True)
    report=dict(passed=assertions,checks=checks,benchmarks=benchmarks,
        scope='Storage only; timing is environment dependent and is not a whole-Agent capacity claim.')
    if args.report:args.report.write_text(json.dumps(report,indent=2)+'\n')

if __name__=='__main__':main()
