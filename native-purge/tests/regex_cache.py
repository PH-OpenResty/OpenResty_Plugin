#!/usr/bin/env python3
"""Count real PCRE compiles under a supported single-scope working set."""
import argparse
import http.client
import json
from pathlib import Path
import subprocess
import tempfile

from integration import Review

def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--prefix', required=True, type=Path)
    parser.add_argument('--static', action='store_true'); parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    prefix = args.prefix/'nginx' if (args.prefix/'nginx/sbin/nginx').exists() else args.prefix
    results = []
    with tempfile.TemporaryDirectory(prefix='purge-regex-cache-') as temporary:
        root = Path(temporary); trace = root/'compiles'; helper = root/'count.so'
        subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-fPIC', '-shared',
            str(Path(__file__).with_name('count-compile.c')), '-ldl', '-o', str(helper)], check=True)
        review = Review(root, prefix, faults=False, static=args.static)
        runtime = subprocess.run([str(review.nginx), '-V'], capture_output=True, text=True, check=True).stderr
        preload = str(helper)
        if '-fsanitize=address' in runtime:
            preload = subprocess.check_output(['cc', '-print-file-name=libasan.so'], text=True).strip()+':'+preload
        review.env.update(LD_PRELOAD=preload, AUDIT_PCRE_TRACE=str(trace))
        try:
            review.start()
            for count in (65, 128):
                scope = 'regex-count-' + str(count)
                rules = ['^/unmatched-%d-%d/(?:segment|other)$' % (count,i) for i in range(count)]
                assert review.control('regex', scope, rules)[0] == 200
                c = http.client.HTTPConnection('127.0.0.1', review.http, timeout=10)
                try:
                    trace.write_bytes(b'')
                    assert review.request('/probe/0', scope, connection=c)[0] == 200
                    first = trace.stat().st_size // 4
                    trace.write_bytes(b'')
                    for i in range(1,9): assert review.request('/probe/'+str(i), scope, connection=c)[0] == 200
                    subsequent = trace.stat().st_size // 4
                    assert first == count and subsequent == 0, (count, first, subsequent)
                    results.append(dict(rules=count, first_request_compiles=first, next_eight_requests_compiles=subsequent))
                    print('PASS %d rules compile once and remain cached' % count, flush=True)
                finally: c.close()
        finally: review.close()
    if args.report: args.report.write_text(json.dumps(dict(passed=len(results), checks=results), indent=2)+'\n')

if __name__ == '__main__': main()
