#!/usr/bin/env python3
"""Real two-tier HTTP validation, stale windows and protocol isolation."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from email.utils import formatdate
import http.client
import json
from pathlib import Path
import tempfile
import threading
import time

from integration import Review as TierReview, Origin as TierOrigin, ROOT, fixture


class Origin(TierOrigin):
    def do_HEAD(self):
        self.respond(head=True)

    def do_GET(self):
        self.respond()

    def respond(self, head=False):
        with self.server.guard:
            state = dict(self.server.settings.get(self.path, {}))
            self.server.calls += 1
            self.server.seen.append(dict(self.headers))
        version = state.get('version', 1)
        language = self.headers.get('Accept-Language', 'none')
        tenant = self.headers.get('X-Test-Tenant', 'public')
        body = f'v{version}:{language}:{tenant}:{self.path}'.encode()
        if 'size' in state: body = b'x' * state['size']
        etag = f'"v{version}-{language}"'
        modified = formatdate(1735689600 + version, usegmt=True)
        validators = state.get('validators', 'etag')
        status = state.get('status', 200)
        if status == 200 and validators != 'none':
            if self.headers.get('If-None-Match') is not None:
                unchanged = validators == 'etag' and self.headers['If-None-Match'] == etag
            else:
                unchanged = self.headers.get('If-Modified-Since') == modified
            if unchanged: status = 304
        with self.server.guard:
            self.server.records.append(dict(path=self.path, status=status, method=self.command,
                etag=self.headers.get('If-None-Match'), modified=self.headers.get('If-Modified-Since')))
        if gate := state.get('gate'):
            gate[0].set(); gate[1].wait(10)
        if state.get('split'):
            self.wfile.write(f'HTTP/1.1 {status} Response\r\n'.encode()); self.wfile.flush()
            time.sleep(0.03)
        else: self.send_response(status)
        chunked = state.get('chunked') and status != 304
        if chunked: self.send_header('Transfer-Encoding', 'chunked')
        elif status != 304: self.send_header('Content-Length', str(len(body)))
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Accept-Ranges', 'bytes')
        if status != 304 or not state.get('omit_304_policy'):
            self.send_header('Cache-Control', state.get('cache_control', 'public,max-age=600'))
        if validators == 'etag': self.send_header('ETag', etag)
        if validators != 'none': self.send_header('Last-Modified', modified)
        if state.get('vary'): self.send_header('Vary', state['vary'])
        if state.get('cookie'): self.send_header('Set-Cookie', 'fixture=session; HttpOnly')
        if 'accel' in state: self.send_header('X-Accel-Expires', state['accel'])
        if state.get('protocol'):
            self.send_header('X-Tier-Debug', 'fixture')
            self.send_header('x-tier-token', 'origin-fixture')
            self.send_header('X-Tier-Cache', 'STALE')
        self.end_headers()
        if status != 304 and not head:
            try:
                if chunked: self.wfile.write(f'{len(body):x}\r\n'.encode() + body + b'\r\n0\r\n\r\n')
                else: self.wfile.write(body[:3] if state.get('truncate') else body)
                self.wfile.flush()
            except OSError: pass
        if state.get('truncate'): self.close_connection = True


class Review(TierReview):
    def __init__(self, root, prefix, static):
        super().__init__(root, prefix, static)
        self.origin.RequestHandlerClass = Origin
        self.origin.settings = {}; self.origin.records = []
        self.policy = ''; self.purge_keys = True

    def config(self, allow_all=True):
        base = fixture.Review.config(self, allow_all)
        templates = ROOT / 'native-tier/examples'
        front = (templates / 'front.conf').read_text()
        back = (templates / 'backend.conf').read_text()
        if self.purge_keys:
            key = 'scdn_purge_key $scdn_tier_scope $scdn_tier_key $scdn_tier_resource;\nproxy_cache_key $scdn_purge_key;'
            front = front.replace('proxy_cache_key $scdn_tier_cache_key;', key)
            back = back.replace('proxy_cache_key $scdn_tier_cache_key;', key)
        # Template TLS settings, header filters and real proxy-cache are retained.
        load = '' if self.static else f'load_module {self.prefix}/modules/ngx_http_scdn_tier_module.so;\n'
        text = load + base[:base.index(f'    server {{ listen 127.0.0.1:{self.http};')]
        text += f'''scdn_tier_zone heat 1m; scdn_tier_heat 3 2s;
        scdn_tier_socket {self.backend};
        server {{ listen unix:{self.backend};
            location = /_tier_status {{ scdn_tier_status; }}
            location / {{ scdn_tier_max_size 1k 4k; {self.policy} {back} }}
        }}
        server {{ listen 127.0.0.1:{self.http};
        '''
        for path, selector, limit in (('/', 'auto', '4k'), ('/l1/', 'l1', '4k'),
                                     ('/l2/', 'l2', '4k'), ('/off/', 'off', '4k'),
                                     ('/bounded/', 'l1', '1k'), ('/key/', 'l1', '4k'), ('/ceiling/', 'l1', '8k')):
            identity = '$http_x_test_key' if path == '/key/' else '"$http_x_revision|$host|$request_uri"'
            text += f'''location {path} {{
                scdn_tier_front {selector} http://127.0.0.1:{self.origin.server_port};
                scdn_tier_identity $host 127.0.0.1 $http_x_scope {identity} $request_uri;
                scdn_tier_max_size 1k {limit}; {self.policy} {front}
            }}'''
        return text + '\n}\n}\n'

    def state(self, path, **state):
        with self.origin.guard: self.origin.settings[path] = state

    def records(self, path):
        with self.origin.guard: return [r for r in self.origin.records if r['path'] == path]

    def get(self, path, headers=None, method='GET'):
        c = http.client.HTTPConnection('127.0.0.1', self.http, timeout=12)
        try:
            c.request(method, path, headers={'X-Scope': 'one', 'X-Revision': 'a', **(headers or {})})
            r = c.getresponse(); return r.status, dict(r.getheaders()), r.read()
        finally: c.close()

    def run(self):
        self.start()
        workers = self.workers()
        for prefix in ('/l1/', '/l2/', '/off/'):
            path = prefix + 'protocol'
            self.state(path, protocol=True)
            supplied = {'X-Tier-Debug': 'caller', 'x-tier-token': 'forged', 'X-Tier-L2-Limit': '1',
                        'X-Tier-Origin': 'invalid', 'X-Tier-Validate': '1'}
            for attempt in range(2):
                reply = self.get(path, supplied)
                self.check(f'{prefix} request {attempt + 1} strips the entire reserved response namespace',
                    reply[0] == 200 and not any(k.lower().startswith('x-tier-') for k in reply[1]))
            self.check(f'{prefix} strips reserved request fields before origin',
                all(not k.lower().startswith('x-tier-') for h in self.origin.seen for k in h))

        for size, cached in ((1024, True), (1025, False)):
            path = f'/bounded/size-{size}'
            self.state(path, size=size)
            self.get(path); self.get(path)
            self.check(f'route L2 limit admits exactly {size} bytes: {cached}',
                len(self.records(path)) == (1 if cached else 2))
        self.state('/ceiling/backend-limit', size=4097)
        self.get('/ceiling/backend-limit'); self.get('/ceiling/backend-limit')
        self.check('backend size ceiling remains authoritative', len(self.records('/ceiling/backend-limit')) == 2)

        for name, state in (('chunked', dict(chunked=True)), ('cookie', dict(cookie=True)),
                            ('vary-star', dict(vary='*')), ('no-store', dict(cache_control='no-store')),
                            ('public-error', dict(status=503)), ('public-redirect', dict(status=302))):
            path = '/l1/' + name; self.state(path, **state)
            replies = [self.get(path), self.get(path)]
            self.check(name + ' is never stored in either layer', len(self.records(path)) == 2
                       and all(r[0] == state.get('status', 200) for r in replies))
        path = '/l1/truncated'; self.state(path, truncate=True)
        for _ in range(2):
            try: self.get(path)
            except http.client.IncompleteRead: pass
        self.check('truncated bodies never become reusable cache entries', len(self.records(path)) == 2)

        for prefix in ('/l1/', '/l2/'):
            path = prefix + 'ranges'
            initial = self.get(path)
            head = self.get(path, method='HEAD')
            self.check(prefix + ' HEAD shares the cached GET without a body', head[0] == 200 and not head[2]
                and int(head[1]['Content-Length']) == len(initial[2]) and len(self.records(path)) == 1)
            partial = self.get(path, {'Range': 'bytes=2-6', 'If-Range': initial[1]['ETag']})
            self.check(prefix + ' Range returns the requested cached bytes', partial[0] == 206
                and partial[2] == initial[2][2:7] and len(self.records(path)) == 1)
            mismatch = self.get(path, {'Range': 'bytes=2-6', 'If-Range': '"old"'})
            self.check(prefix + ' If-Range mismatch returns the complete representation',
                mismatch[0] == 200 and mismatch[2] == initial[2])
            conditional = self.get(path, {'If-None-Match': initial[1]['ETag']})
            self.check(prefix + ' client conditional HIT returns 304 without an origin read',
                conditional[0] == 304 and not conditional[2] and len(self.records(path)) == 1)

        # Native expiry works even without the optional Purge revalidation hook.
        for prefix in ('/l1/', '/l2/'):
            self.state(prefix + 'native-304', cache_control='public,max-age=1')
            self.get(prefix + 'native-304'); self.get(prefix + 'native-304')
        time.sleep(2.05)
        for prefix in ('/l1/', '/l2/'):
            path = prefix + 'native-304'; reply = self.get(path)
            self.check(prefix + ' native conditional revalidation preserves the body',
                reply[0] == 200 and reply[1]['X-Cache'] == 'REVALIDATED' and self.records(path)[-1]['status'] == 304)

        self.check('HTTP boundary traffic preserves Worker processes', self.workers() == workers)
        self.stop(); self.policy = 'scdn_purge_revalidate 1s; scdn_purge_stale updating=0 error=0;'; self.start()
        for prefix in ('/l1/', '/l2/'):
            for validator in ('etag', 'modified', 'none'):
                path = prefix + 'validator-' + validator
                self.state(path, validators=validator, split=True, omit_304_policy=True)
                self.get(path); self.get(path)
        time.sleep(2.05)
        for prefix in ('/l1/', '/l2/'):
            for validator in ('etag', 'modified', 'none'):
                path = prefix + 'validator-' + validator
                reply = self.get(path); record = self.records(path)[-1]
                self.check(prefix + validator + ' refresh completes without a false 502',
                    reply[0] == 200 and reply[2].startswith(b'v1:') and record['status'] == (200 if validator == 'none' else 304))
                if validator != 'none':
                    self.check(prefix + validator + ' forwards the cached validator to origin',
                        bool(record['etag'] if validator == 'etag' else record['modified']))
                    count = len(self.records(path))
                    self.check(prefix + validator + ' renewed metadata serves the next HIT',
                        self.get(path)[1]['X-Cache'] == 'HIT' and len(self.records(path)) == count)
                self.state(path, version=2, validators=validator)
        time.sleep(2.05)
        for prefix in ('/l1/', '/l2/'):
            for validator in ('etag', 'modified', 'none'):
                path = prefix + 'validator-' + validator
                self.check(prefix + validator + ' replaces changed origin bytes', self.get(path)[2].startswith(b'v2:'))

        private_paths = []
        for prefix in ('/l1/', '/l2/'):
            for reason, state in (('no-store', {'cache_control': 'private,no-store'}),
                                  ('accel', {'accel': '0'}), ('cookie', {'cookie': True})):
                path = prefix + 'private-304-' + reason; private_paths.append((path, state))
                self.get(path); self.get(path)
        for path, state in private_paths: self.state(path, **state)
        time.sleep(2.05)
        for path, _ in private_paths:
            value = self.get(path)
            self.check(path + ' refuses to renew the formerly public representation', value[0] == 502)
            self.state(path, version=5)
            self.until(lambda: self.get(path)[2].startswith(b'v5:'), 'private object invalidation')
            self.check(path + ' recovers after fetching current public bytes', self.get(path)[2].startswith(b'v5:'))

        # Lower stale responses stay visibly stale and cannot be promoted.
        self.stop(); self.policy = 'scdn_purge_revalidate 1s; scdn_purge_stale updating=0 error=3s;'; self.start()
        paths = ['/l1/stale-bounded', '/l2/stale-bounded']
        for path in paths: self.get(path); self.get(path)
        for path in paths: self.state(path, status=503)
        time.sleep(2.05)
        for path in paths:
            value = self.get(path)
            self.check(path + ' reuses the old successful response within the stale window',
                value[0] == 200 and value[1]['X-Cache'] == 'STALE' and value[2].startswith(b'v1:'))
        time.sleep(3.05)
        for path in paths:
            self.check(path + ' stops stale reuse after its absolute deadline', self.get(path)[0] == 503)
            self.state(path, version=3)
            self.check(path + ' recovers with current origin bytes', self.get(path)[2].startswith(b'v3:'))

        self.stop(); self.policy = 'scdn_purge_revalidate 1s; scdn_purge_stale updating=4s error=0;'; self.start()
        path = '/l1/background'; self.get(path); self.get(path)
        started, release = threading.Event(), threading.Event()
        self.state(path, version=4, gate=(started, release))
        time.sleep(2.05)
        try:
            with ThreadPoolExecutor(max_workers=8) as pool:
                values = list(pool.map(lambda _: self.get(path), range(16)))
            self.check('concurrent readers receive stale data while one origin update is blocked',
                started.wait(3) and all(r[0] == 200 and r[2].startswith(b'v1:') for r in values))
            self.check('two-tier background locking starts only one origin validation', len(self.records(path)) == 2)
        finally: release.set()
        self.until(lambda: self.get(path)[2].startswith(b'v4:'), 'background promotion')
        self.check('background validation replaces the upper object', self.get(path)[2].startswith(b'v4:'))

        # Exercise the supplied standalone key, without Purge hiding a collision.
        self.stop(); self.policy = ''; self.purge_keys = False; self.start()
        first = {'X-Scope': 'tenant|part', 'X-Test-Key': 'key', 'X-Test-Tenant': 'a'}
        second = {'X-Scope': 'tenant', 'X-Test-Key': 'part|key', 'X-Test-Tenant': 'b'}
        a = self.get('/key/object', first); b = self.get('/key/object', second)
        self.check('standalone length-framed keys isolate delimiter collisions', a[2] != b[2]
            and self.get('/key/object', first)[2] == a[2] and self.get('/key/object', second)[2] == b[2]
            and len(self.records('/key/object')) == 2)
        logs = ''.join((self.root / name).read_text(errors='replace') for name in ('error.log', 'stdout.log'))
        self.check('boundary suite has no sanitizer or crashed-Worker diagnostics',
            all(s not in logs for s in ('runtime error:', 'AddressSanitizer', 'exited on signal')))
        return self.checks


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--prefix', required=True, type=Path)
    parser.add_argument('--static', action='store_true'); parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    prefix = args.prefix / 'nginx' if (args.prefix / 'nginx/sbin/nginx').exists() else args.prefix
    with tempfile.TemporaryDirectory(prefix='native-tier-boundary-') as directory:
        review = Review(Path(directory), prefix, args.static)
        try:
            checks = review.run()
            if args.report: args.report.write_text(json.dumps({'passed': len(checks), 'checks': checks}, indent=2) + '\n')
            print(f'{len(checks)} tier HTTP boundary checks passed', flush=True)
        except Exception:
            fixture.dump_runtime_logs(review.root); raise
        finally: review.close()


if __name__ == '__main__': main()
