#!/usr/bin/env python3
"""Native tier cache hierarchy, expiry, isolation, Purge and restart evidence."""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor
import http.client
import importlib.util
import json
from pathlib import Path
import socket
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('purge_fixture', ROOT / 'native-purge/tests/integration.py')
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class Origin(fixture.Origin):
    def do_GET(self):
        with self.server.guard:
            self.server.calls += 1
            version = self.server.version
            self.server.seen.append(dict(self.headers))
        language = self.headers.get('Accept-Language', 'none')
        body = (f'v{version}:{language}:' + self.path).encode()
        if '/credential-review/' in self.path:
            credential = self.headers.get('Api-Key') or self.headers.get('Proxy-Authorization') or 'anonymous'
            body += (':' + credential).encode()
        if '/large/' in self.path: body += b'x' * 2048
        if '/huge/' in self.path: body += b'x' * 8192
        status = 503 if '/failure/' in self.path else 200
        self.send_response(status)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Content-Type', 'text/plain')
        self.send_header('ETag', f'"v{version}-{language}"')
        if '/private/' in self.path or status != 200:
            self.send_header('Cache-Control', 'private,no-store')
        elif '/short/' in self.path:
            self.send_header('Cache-Control', 'public,max-age=3')
        else:
            self.send_header('Cache-Control', 'public,max-age=600')
        if '/vary/' in self.path: self.send_header('Vary', 'Accept-Language')
        self.end_headers()
        try: self.wfile.write(body)
        except OSError: pass


fixture.Origin = Origin


class Review(fixture.Review):
    def __init__(self, root, prefix, static):
        super().__init__(root, prefix, faults=False, static=static)
        self.backend = root / 'tier.sock'
        self.origin.seen = []
        self.revalidate = False
        (root / 'logs').mkdir()

    def config(self, allow_all=True):
        base = super().config(allow_all)
        template = ROOT / 'native-tier/examples'
        front = (template / 'front.conf').read_text()
        backend = (template / 'backend.conf').read_text()
        old = 'proxy_cache_key $scdn_tier_cache_key;'
        key = 'scdn_purge_key $scdn_tier_scope $scdn_tier_key $scdn_tier_resource;\nproxy_cache_key $scdn_purge_key;'
        front = front.replace(old, key)
        backend = backend.replace(old, key)
        if self.revalidate:
            front = 'scdn_purge_revalidate 1s; scdn_purge_stale updating=0 error=0;\n' + front
            backend = 'scdn_purge_revalidate 1s; scdn_purge_stale updating=0 error=0;\n' + backend
        module = '' if self.static else f'load_module {self.prefix}/modules/ngx_http_scdn_tier_module.so;\n'
        text = base[:base.index(f'    server {{ listen 127.0.0.1:{self.http};')]
        text = module + text.replace('    access_log off;', f'''access_log off;
            scdn_tier_zone heat 1m; scdn_tier_heat 3 2s;
            scdn_tier_socket {self.backend};''')
        text += f'''server {{ listen unix:{self.backend}; listen 127.0.0.1:{self.second};
            location = /_tier_status {{ scdn_tier_status; }}
            location / {{ scdn_tier_max_size 1k 4k; {backend} }}
        }}
        server {{ listen 127.0.0.1:{self.http};
        '''
        for path, selector in (('/', 'auto'), ('/l1/', 'l1'), ('/l2/', 'l2'), ('/off/', 'off')):
            text += f'''location {path} {{
                scdn_tier_front {selector} http://127.0.0.1:{self.origin.server_port};
                scdn_tier_identity $host 127.0.0.1 "$http_x_scope" "$http_x_revision|$host|$request_uri" $request_uri;
                scdn_tier_max_size 1k 4k;
                {front}
            }}'''
        return text + '\n}\n}\n'

    def tier_status(self):
        connection = http.client.HTTPConnection('localhost', timeout=3)
        connection.sock = socket.socket(socket.AF_UNIX); connection.sock.connect(str(self.backend))
        try:
            connection.request('GET', '/_tier_status')
            response = connection.getresponse(); return json.loads(response.read())
        finally: connection.close()

    def run(self):
        self.start()
        workers = self.started_workers
        first = self.request('/asset')
        self.check('cold lookup fills the persistent L2 through native proxy cache', first[0] == 200
                   and first[1].get('X-Cache-Layer') == 'origin' and self.origin.calls == 1)
        second = self.request('/asset')
        self.check('second cold request is served from L2', second[1].get('X-Cache-Layer') == 'l2' and self.origin.calls == 1)
        third = self.request('/asset')
        self.check('promotion reads the existing L2 object without origin traffic', third[1].get('X-Cache-Layer') == 'l2' and self.origin.calls == 1)
        fourth = self.request('/asset')
        self.check('promoted object is served from L1', fourth[1].get('X-Cache-Layer') == 'l1' and self.origin.calls == 1)
        self.check('tier protocol response fields do not escape to clients', all(not name.lower().startswith('x-tier-') for name in fourth[1]))
        self.check('tier token and routing metadata are stripped before origin',
                   all(not key.lower().startswith('x-tier-') for request in self.origin.seen for key in request))
        self.check('origin receives the trusted client IP header', self.origin.seen[0].get('X-Clinet-IP') == '127.0.0.1')
        time.sleep(2.05)
        self.check('expired heat window demotes to the retained L2 copy', self.request('/asset')[1].get('X-Cache-Layer') == 'l2'
                   and self.origin.calls == 1)
        for path in ('/l1/direct', '/l2/direct'):
            self.request(path)
            hit = self.request(path)
            self.check(path + ' respects a fixed cache layer', hit[1]['X-Cache-Layer'] == ('l1' if path.startswith('/l1/') else 'l2'))
        before = self.origin.calls
        self.request('/off/direct'); off = self.request('/off/direct')
        self.check('off bypasses the two cache zones', self.origin.calls == before + 2 and off[1]['X-Cache'] == 'BYPASS')
        connection = http.client.HTTPConnection('127.0.0.1', self.http, timeout=5)
        try:
            before = self.origin.calls
            for _ in range(2):
                connection.request('GET', '/l1/credential', headers={'Host': 'localhost', 'X-Scope': 'one', 'Authorization': 'Bearer fixture'})
                response = connection.getresponse(); response.read()
                self.check('credentialed request bypasses both tiers', response.getheader('X-Cache') == 'BYPASS')
            self.check('credentialed responses are never reused', self.origin.calls == before + 2)
        finally: connection.close()
        for header_name in ('Api-Key', 'Proxy-Authorization', 'Pragma'):
            path = '/l1/credential-review/' + header_name.lower()
            self.request(path); self.request(path)
            connection = http.client.HTTPConnection('127.0.0.1', self.http, timeout=5)
            responses = []
            before = self.origin.calls
            try:
                for value in ('fixture-user-a', 'fixture-user-b'):
                    supplied = 'no-cache' if header_name == 'Pragma' else value
                    connection.request('GET', path, headers={'Host': '127.0.0.1', 'X-Scope': 'one', 'X-Revision': 'a', header_name: supplied})
                    response = connection.getresponse()
                    responses.append((response.getheader('X-Cache'), response.read()))
            finally: connection.close()
            self.check(header_name + ' bypasses an existing public object in both tiers',
                       all(status == 'BYPASS' for status, _ in responses) and self.origin.calls == before + 2)
            if header_name != 'Pragma':
                self.check(header_name + ' keeps different caller responses isolated',
                           responses[0][1].endswith(b':fixture-user-a') and responses[1][1].endswith(b':fixture-user-b')
                           and self.request(path)[2].endswith(b':anonymous'))
        for header_name, first_value, second_value in (
                ('Api-Key', 'fixture-a', 'fixture-b'), ('X-API-Key', 'fixture-a', 'fixture-b'),
                ('Cache-Control', 'public', 'no-cache'), ('Pragma', 'fixture', 'no-cache')):
            path = '/l1/duplicate-privacy/' + header_name.lower()
            self.request(path); self.request(path)
            before = self.origin.calls
            connection = http.client.HTTPConnection('127.0.0.1', self.http, timeout=5)
            try:
                connection.putrequest('GET', path, skip_host=True)
                for name, value in (('Host', '127.0.0.1'), ('X-Scope', 'one'), ('X-Revision', 'a'),
                                    (header_name, first_value), (header_name.lower(), second_value)):
                    connection.putheader(name, value)
                connection.endheaders()
                response = connection.getresponse(); response.read()
                self.check('duplicate ' + header_name + ' cannot disable cache bypass',
                           response.getheader('X-Cache') == 'BYPASS' and self.origin.calls == before + 1)
            finally: connection.close()
        for path in ('/l1/private/item', '/l1/failure/item'):
            before = self.origin.calls
            self.request(path); self.request(path)
            self.check(path + ' is not cached', self.origin.calls == before + 2)
        self.request('/l1/large/item'); big = self.request('/l1/large/item')
        self.check('object exceeding L1 budget stays in L2', big[1]['X-Cache-Layer'] == 'l2'
                   and self.request('/l1/large/item')[1]['X-Cache-Layer'] == 'l2')
        before = self.origin.calls
        self.request('/l1/huge/item'); self.request('/l1/huge/item')
        self.check('object exceeding L2 budget is served without storage', self.origin.calls == before + 2)
        for language in ('en', 'zh'):
            self.request('/l1/vary/item', language=language)
            value = self.request('/l1/vary/item', language=language)
            self.check('Vary representation ' + language + ' survives both tiers', value[2].startswith(f'v1:{language}:'.encode()))
        self.request('/l1/query?a=1'); self.request('/l1/query?a=2')
        self.check('query strings keep independent objects', self.request('/l1/query?a=1')[2].endswith(b'?a=1')
                   and self.request('/l1/query?a=2')[2].endswith(b'?a=2'))
        self.request('/l1/scoped', scope='one'); self.request('/l1/scoped', scope='two')
        self.version(2)
        self.control('exact', keys=['/l1/scoped'])
        self.check('Purge invalidates L1 and L2 with one logical epoch', self.request('/l1/scoped')[2].startswith(b'v2:'))
        self.check('Purge retains another scope', self.request('/l1/scoped', scope='two')[2].startswith(b'v1:'))
        for path in ('/l1/group/a', '/l2/group/b'):
            self.request(path); self.request(path)
        self.version(3)
        self.control('suffix', keys=['/group/a'])
        self.check('pattern purge remains effective on promoted resources', self.request('/l1/group/a')[2].startswith(b'v3:'))
        self.control('site', keys=None)
        self.check('site purge fences both tiers', self.request('/l2/group/b')[2].startswith(b'v3:'))
        before = self.origin.calls
        with ThreadPoolExecutor(max_workers=8) as pool:
            values = list(pool.map(lambda _: self.request('/l1/concurrent')[0], range(16)))
        self.check('concurrent fills preserve successful responses', all(code == 200 for code in values))
        self.check('native cache locks bound duplicate origin fills', self.origin.calls <= before + 2)
        # L1 must inherit the original L2 expiry rather than restart its TTL.
        self.version(4)
        self.request('/short/item'); time.sleep(1.05)
        self.request('/short/item'); self.request('/short/item'); self.request('/short/item')
        self.version(5); time.sleep(3.1)
        self.check('expired lower object fetches the new origin version', self.request('/short/item')[2].startswith(b'v5:'))
        # Pin L1 selection so a heat-window demotion cannot hide a bad TTL reset.
        self.version(50); first_short = self.request('/l1/short/absolute'); self.request('/l1/short/absolute')
        from email.utils import parsedate_to_datetime
        original_deadline = parsedate_to_datetime(first_short[1]['Date']).timestamp() + 4.1
        self.stop()
        import shutil
        shutil.rmtree(self.root / 'cache1')
        time.sleep(1.05); self.start()
        self.check('promotion after L1 loss reads the still-fresh L2 object', self.request('/l1/short/absolute')[1]['X-Cache-Layer'] == 'l2')
        self.version(51); time.sleep(max(0, original_deadline - time.time()))
        expiry_reply = self.request('/l1/short/absolute')
        if not expiry_reply[2].startswith(b'v51:'):
            import struct
            print('expiry diagnostic:', {'now': time.time(), 'expected': original_deadline,
                  'headers': expiry_reply[1], 'body': expiry_reply[2].decode()}, flush=True)
            for cache_path in ('cache1', 'cache2'):
                for file in (self.root / cache_path).rglob('*'):
                    if file.is_file():
                        content = file.read_bytes()
                        if b'/l1/short/absolute' in content:
                            print('cache expiry:', cache_path, struct.unpack_from('=q', content, 8)[0], flush=True)
        self.check('L1 promotion preserves the original absolute expiry', expiry_reply[2].startswith(b'v51:'))
        workers = self.workers()
        self.check('backend rejects public TCP requests', self.request('/asset', second=True)[0] == 403)
        connection = http.client.HTTPConnection('localhost', timeout=3)
        connection.sock = socket.socket(socket.AF_UNIX); connection.sock.connect(str(self.backend))
        try:
            connection.request('GET', '/asset', headers={'X-Tier-Token': '0' * 64})
            response = connection.getresponse(); response.read()
            self.check('backend rejects unauthenticated Unix callers', response.status == 403)
        finally: connection.close()
        self.request('/l1/short/absolute'); self.request('/off/after-restart')
        stats = self.tier_status()
        self.check('native tier counters record both layers and bypass', stats['l1_hits'] > 0 and stats['l2_hits'] > 0
                   and stats['bypasses'] > 0 and stats['lua_required'] is False)
        self.check('tier traffic leaves Workers intact', workers == self.workers())
        self.request('/l1/restart'); self.request('/l1/restart')
        self.stop(); self.start()
        before = self.origin.calls
        # Fixed l2 uses the same key; explicitly remove only the disposable L1
        # cache fixture to model loss of a RAM mount, while nginx is stopped.
        self.stop()
        import shutil
        shutil.rmtree(self.root / 'cache1')
        self.start()
        restart = self.request('/l1/restart')
        self.check('L1 loss and restart recover from persisted L2 without a flush script', restart[1]['X-Cache-Layer'] == 'l2'
                   and self.origin.calls == before)
        self.check('recovered L2 repopulates L1', self.request('/l1/restart')[1]['X-Cache-Layer'] == 'l1')
        self.stop(); self.revalidate = True; self.start()
        self.version(6); self.request('/l1/revalidate'); self.request('/l1/revalidate')
        self.version(7); time.sleep(2.05)
        self.until(lambda: value if (value := self.request('/l1/revalidate'))[2].startswith(b'v7:') else None, 'tier origin revalidation')
        self.check('L1 revalidation reaches origin through L2 instead of reusing a fresh lower object',
                   self.request('/l1/revalidate')[2].startswith(b'v7:'))
        self.version(8); self.request('/l2/revalidate'); self.request('/l2/revalidate')
        self.version(9); time.sleep(2.05)
        self.until(lambda: value if (value := self.request('/l2/revalidate'))[2].startswith(b'v9:') else None, 'L2 origin revalidation')
        self.check('cold L2 requests also participate in origin revalidation', self.request('/l2/revalidate')[2].startswith(b'v9:'))
        logs = ''.join((self.root / name).read_text(errors='replace') for name in ('error.log', 'stdout.log'))
        self.check('tier paths have no sanitizer diagnostics', 'runtime error:' not in logs and 'AddressSanitizer' not in logs)
        return self.checks


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--prefix', required=True, type=Path)
    parser.add_argument('--static', action='store_true'); parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    prefix = args.prefix / 'nginx' if (args.prefix / 'nginx/sbin/nginx').exists() else args.prefix
    with tempfile.TemporaryDirectory(prefix='native-tier-test-') as directory:
        review = Review(Path(directory), prefix, args.static)
        try:
            checks = review.run()
            if args.report: args.report.write_text(json.dumps({'passed': len(checks), 'checks': checks}, indent=2) + '\n')
            print(f'{len(checks)} native tier checks passed', flush=True)
        except Exception:
            fixture.dump_runtime_logs(review.root)
            raise
        finally: review.close()


if __name__ == '__main__': main()
