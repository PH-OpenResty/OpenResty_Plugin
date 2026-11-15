#!/usr/bin/env python3
"""Real cache and upstream headers across hot site/prefix updates."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import http.client
import json
from pathlib import Path
import subprocess
import tempfile
import time

import integration as fixture
from nginx_process import assert_clean_startup, dump_runtime_logs, runtime_log_offsets, wait_for_workers


class Origin(fixture.Origin):
    def do_GET(self):
        if self.path.startswith('/slow/'):
            time.sleep(.8)
        body = json.dumps({'path': self.path,
            'policy': self.headers.get_all('X-Cache-Tag'),
            'other': self.headers.get('X-Cache-Other'),
            'client': self.headers.get('X-Clinet-IP'),
            'cookie': self.headers.get('Cookie'),
            'authorization': self.headers.get('Authorization')}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'public,max-age=60')
        self.send_header('ETag', '"header-fixture"')
        if self.path.startswith('/spoof/'):
            self.send_header('X-Cache', 'ORIGIN')
            self.send_header('X-Cache-Layer', 'ORIGIN')
        self.end_headers()
        self.wfile.write(body)


fixture.Origin = Origin


class Review(fixture.Review):
    def sites(self, **kwargs):
        return f'''sites {{ site alpha {{
            host www.example.com; upstream http://127.0.0.1:{self.origins[0].server_port};
            cache l1; cache_headers on;
            cache_request_header X-Cache-Tag "site-v1";
            cache_request_header X-Cache-Other "literal-$value";
            prefix /prefix/ {{ upstream http://127.0.0.1:{self.origins[0].server_port};
                cache l2; cache_request_header X-Cache-Tag "prefix-v1"; }}
            prefix /noheaders/ {{ upstream http://127.0.0.1:{self.origins[0].server_port};
                cache off; cache_headers off; cache_request_headers off; }}
            prefix /off/ {{ upstream http://127.0.0.1:{self.origins[0].server_port}; cache off; }}
        }} }}'''

    def config(self):
        return super().config().replace('scdn_edge on;', 'scdn_edge on; scdn_api on;').replace(
            'proxy_cache_valid 200 1m;', 'proxy_cache_valid 200 1m;\n'
            'proxy_set_header X-Clinet-IP $remote_addr;\n'
            'proxy_cache_bypass $scdn_api_skip_cache; proxy_no_cache $scdn_api_skip_cache;')

    def call(self, path='/asset', headers=()):
        connection = http.client.HTTPConnection('127.0.0.1', self.http, timeout=4)
        try:
            connection.putrequest('GET', path, skip_host=True)
            connection.putheader('Host', 'www.example.com')
            for name, value in headers:
                connection.putheader(name, value)
            connection.endheaders()
            response = connection.getresponse()
            raw = response.read()
            values = response.getheaders()
            return response.status, dict(values), json.loads(raw), values
        finally:
            connection.close()

    def run(self):
        path = self.root / 'nginx.conf'
        path.write_text(self.config())
        valid = self.sites()
        invalid = {
            'duplicate case-insensitive header': 'cache_request_header x-cache-tag duplicate;',
            'identity overwrite': 'cache_request_header X-Clinet-IP "192.0.2.20";',
            'forwarded identity overwrite': 'cache_request_header X-Forwarded-For "192.0.2.20";',
            'standard authorization overwrite': 'cache_request_header Authorization example;',
            'API key overwrite': 'cache_request_header X-API-Key example;',
            'protocol control overwrite': 'cache_request_header X-Accel-Redirect /private;',
            'newline value': 'cache_request_header X-New "bad\nvalue";',
            'oversized value': 'cache_request_header X-New "' + 'v' * 1025 + '";',
            'invalid token name': 'cache_request_header X-Bad_Name value;',
            'too many headers': ' '.join(f'cache_request_header X-More-{i} value;' for i in range(7)),
            'duplicate response flag': 'cache_headers on;',
        }
        for name, fragment in invalid.items():
            self.set_source(valid.replace('cache l1;', 'cache l1; ' + fragment, 1))
            result = subprocess.run([str(self.nginx), '-t', '-p', str(self.root) + '/', '-c', str(path)],
                                    capture_output=True, text=True)
            self.check('configuration rejects ' + name, result.returncode == 1
                       and 'runtime error:' not in result.stderr and 'AddressSanitizer' not in result.stderr)
        self.set_source(valid)
        self.log = (self.root / 'stdout.log').open('wb')
        offsets = runtime_log_offsets(self.root)
        self.process = subprocess.Popen([str(self.nginx), '-p', str(self.root) + '/', '-c', str(path),
            '-g', 'daemon off;'], stdout=self.log, stderr=self.log)
        self.until(lambda: self.control(), 'startup')
        workers = wait_for_workers(self.process)
        assert_clean_startup(self.root, offsets)
        first = self.call()
        self.check('cache policy request headers reach origin', first[2]['policy'] == ['site-v1'])
        self.check('header values are literal without variable expansion', first[2]['other'] == 'literal-$value')
        self.check('first response exposes actual MISS and l1', first[1]['X-Cache'] == 'MISS'
                   and first[1]['X-Cache-Layer'] == 'l1' and first[1]['X-Cache-Policy'] == 'l1')
        hit = self.until(lambda: v if (v := self.call())[1]['X-Cache'] == 'HIT' else None, 'cache HIT')
        self.check('cache HIT exposes active configuration revision', hit[1]['X-Cache-Revision'] == self.control()['revision'])
        overridden = self.call('/spoof/item', [('X-Cache-Tag', 'caller-a'), ('x-cache-tag', 'caller-b')])
        self.check('all caller duplicates are replaced before proxy serialization', overridden[2]['policy'] == ['site-v1'])
        self.check('origin cannot forge cache diagnostics', overridden[1]['X-Cache'] == 'MISS'
                   and overridden[1]['X-Cache-Layer'] == 'l1'
                   and sum(name.lower() == 'x-cache' for name, _ in overridden[3]) == 1)
        prefix = self.call('/prefix/item')
        self.check('prefix selects its own header list and cache layer', prefix[2]['policy'] == ['prefix-v1']
                   and prefix[2]['other'] is None and prefix[1]['X-Cache-Layer'] == 'l2')
        disabled = self.call('/noheaders/item')
        self.check('prefix can disable inherited response headers', 'X-Cache' not in disabled[1]
                   and 'X-Cache-Revision' not in disabled[1])
        self.check('prefix can disable inherited request header injection', disabled[2]['policy'] is None)
        self.check('disabled cache reports OFF rather than HIT', self.call('/off/item')[1]['X-Cache'] == 'OFF')
        for name in ('Authorization', 'Cookie'):
            private = self.call('/private/' + name, [(name, 'fixture')])
            self.check(name + ' still reaches origin unchanged', private[2][name.lower()] == 'fixture')
            self.check(name + ' is BYPASS and never reports a cache layer', private[1]['X-Cache'] == 'BYPASS'
                       and private[1]['X-Cache-Layer'] == 'off')
        self.check('connection client IP remains authoritative', self.call('/ip', [('X-Clinet-IP', '192.0.2.20')])[2]['client'] == '127.0.0.1')
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(self.call, '/slow/item')
            time.sleep(.1)
            previous = self.generation()
            self.set_source(valid.replace('site-v1', 'site-v2'))
            self.wait_change(previous)
            old = pending.result()
        self.check('in-flight request retains prior header policy and revision', old[2]['policy'] == ['site-v1']
                   and old[1]['X-Cache-Revision'] == hit[1]['X-Cache-Revision'])
        fresh = self.call()
        self.check('hot update changes headers and cache namespace together', fresh[2]['policy'] == ['site-v2']
                   and fresh[1]['X-Cache'] == 'MISS' and fresh[1]['X-Cache-Revision'] != hit[1]['X-Cache-Revision'])
        previous = self.control()
        self.set_source(valid.replace('site-v1', 'site-v3').replace('X-Cache-Other', 'X-Clinet-IP'))
        self.until(lambda: self.control()['last_error'], 'invalid hot header policy')
        self.check('invalid hot candidate preserves active header policy', self.call('/after-invalid')[2]['policy'] == ['site-v2']
                   and self.control()['revision'] == previous['revision'])
        self.set_source(valid.replace('site-v1', 'site-v2').replace('cache_headers on;', 'cache_headers off;'))
        self.wait_change(previous['generation'])
        self.check('response diagnostics can be disabled without worker reload', 'X-Cache' not in self.call('/disabled')[1])
        self.check('all valid header updates preserve worker PIDs', self.workers() == workers)
        logs = ''.join((self.root / name).read_text(errors='replace') for name in ('stdout.log', 'error.log'))
        self.check('header paths complete without sanitizer diagnostics', 'runtime error:' not in logs and 'AddressSanitizer' not in logs)
        return self.checks


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--prefix', type=Path, required=True)
    parser.add_argument('--report', type=Path)
    parser.add_argument('--static', action='store_true')
    args = parser.parse_args()
    prefix = args.prefix / 'nginx' if (args.prefix / 'nginx/sbin/nginx').exists() else args.prefix
    with tempfile.TemporaryDirectory(prefix='cache-header-test-') as directory:
        review = Review(Path(directory), prefix, args.static)
        try:
            checks = review.run()
            if args.report:
                args.report.write_text(json.dumps({'passed': len(checks), 'checks': checks}, indent=2) + '\n')
            print(f'{len(checks)} cache header checks passed', flush=True)
        except Exception:
            dump_runtime_logs(review.root)
            raise
        finally:
            review.close()


if __name__ == '__main__':
    main()
