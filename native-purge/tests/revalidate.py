#!/usr/bin/env python3
"""Conditional origin requests and finite stale reuse with real Nginx workers."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from email.utils import formatdate
import hashlib
import http.client
import http.server
import json
from pathlib import Path
import signal
import subprocess
import tempfile
import threading
import time
from urllib.parse import urlsplit

from integration import Review
from nginx_process import dump_runtime_logs


class ConditionalOrigin(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def do_HEAD(self):
        self.respond(head=True)

    def do_GET(self):
        self.respond()

    def respond(self, head=False):
        path = urlsplit(self.path).path
        with self.server.guard:
            state = dict(self.server.settings.get(path, {}))
        version = state.get('version', 1)
        language = self.headers.get('Accept-Language', 'none')
        body = f'v{version}:{language}:{self.path}'.encode()
        if 'payload_bytes' in state:
            body = f'v{version}:'.encode() + b'x' * state['payload_bytes']
        etag = '"' + hashlib.sha256(body).hexdigest() + '"'
        modified = formatdate(1735689600 + state.get('modified_version', version), usegmt=True)
        validators = state.get('validators', 'etag')
        code = state.get('status', 200)
        if code == 200 and validators != 'none':
            if self.headers.get('If-None-Match') is not None:
                same = self.headers['If-None-Match'] == etag
            else:
                same = self.headers.get('If-Modified-Since') == modified
            if same:
                code = 304
        record = dict(path=self.path, method=self.command, language=language,
                      etag=self.headers.get('If-None-Match'),
                      modified=self.headers.get('If-Modified-Since'), status=code)
        with self.server.guard:
            self.server.records.append(record)
        gate = state.get('gate')
        if gate:
            gate[0].set()
            gate[1].wait(8)
        if state.get('delay'):
            time.sleep(state['delay'])
        if state.get('split'):
            self.wfile.write(f'HTTP/1.1 {code} Response\r\n'.encode())
            self.wfile.flush()
            time.sleep(0.03)
        else:
            self.send_response(code)
        self.send_header('Content-Length', str(0 if code == 304 else len(body)))
        if code!=304 or not state.get('omit_304_cache_control'):
            self.send_header('Cache-Control', state.get('cache_control', 'public,max-age=86400'))
        if state.get('cookie'):
            self.send_header('Set-Cookie', 'session=test; HttpOnly')
        self.send_header('X-Accel-Expires', '86400') if state.get('accel') else None
        if validators == 'etag':
            self.send_header('ETag', etag)
        if validators != 'none':
            self.send_header('Last-Modified', modified)
        if path.startswith('/vary/'):
            self.send_header('Vary', 'Accept-Language')
        self.end_headers()
        if code != 304 and not head:
            try:
                self.wfile.write(body[:3] if state.get('truncate') else body)
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass
        if state.get('truncate'):
            self.close_connection = True

    def log_message(self, *args):
        pass


class Revalidation(Review):
    def __init__(self, root, prefix):
        super().__init__(root, prefix, faults=False)
        self.origin.RequestHandlerClass = ConditionalOrigin
        self.origin.settings = {}
        self.origin.records = []

    def config(self, allow_all=True):
        conf = super().config(allow_all)
        conf = conf.replace('location / {', 'location / {\n'
                            'scdn_purge_revalidate 1s;\n'
                            'scdn_purge_stale updating=10s error=0;')
        locations = []
        for path, extra in [
            ('/bounded/', 'scdn_purge_stale updating=1s error=4s;'),
            ('/blocking/', 'scdn_purge_stale updating=0 error=0;'),
            ('/error-only/', 'scdn_purge_stale updating=0 error=4s;'),
            ('/forced/', 'proxy_ignore_headers Cache-Control Expires X-Accel-Expires;'),
            ('/off/', 'scdn_purge_revalidate off;'),
            ('/short/', 'scdn_purge_revalidate 5s;'),
        ]:
            locations.append(f'''location {path} {{
                scdn_purge_key "$http_x_scope" "$request_uri";
                {'scdn_purge_revalidate 1s;' if path not in ('/off/','/short/') else ''}
                {extra}
                proxy_pass http://127.0.0.1:{self.origin.server_port};
                proxy_cache l1; proxy_cache_key $scdn_purge_key;
                proxy_cache_valid 200 1d;
                proxy_cache_use_stale updating error timeout http_500 http_503;
                proxy_connect_timeout 1s; proxy_read_timeout 1s;
                add_header X-Cache $upstream_cache_status always;
                add_header X-Worker $pid always;
            }}''')
        return conf.replace('location /baseline/ {', '\n'.join(locations) + '\nlocation /baseline/ {')

    def set(self, path, **values):
        with self.origin.guard:
            self.origin.settings.setdefault(urlsplit(path).path, {}).update(values)

    def records(self, path):
        with self.origin.guard:
            return [dict(record) for record in self.origin.records if record['path'] == path]

    def expire(self):
        # Native cache freshness uses whole seconds and valid_sec < now.
        time.sleep(2.05)

    def fresh(self, path, version, language=None):
        def ready():
            result = self.request(path, language=language)
            return result if (result[0] == 200 and result[2].startswith(f'v{version}:'.encode())
                              and result[1].get('X-Cache') == 'HIT') else None
        return self.until(ready, 'updated body: ' + path)

    def run(self):
        self.start()
        workers = self.started_workers
        path = '/etag/item'
        first = self.fill(path)
        count = len(self.records(path))
        self.expire()
        self.check('idle resources are not polled', len(self.records(path)) == count)
        stale = self.request(path)
        self.until(lambda: len(self.records(path)) > count, 'conditional GET')
        self.fresh(path, 1)
        record = self.records(path)[-1]
        self.check('ETag and Last-Modified generate conditional GET with 304',
                   record['method'] == 'GET' and record['etag'] is not None
                   and record['modified'] is not None and record['status'] == 304)
        self.check('background validation serves the previous body',
                   stale[0] == 200 and stale[2] == first[2] and stale[1]['X-Cache'] == 'STALE')
        self.expire()
        previous = len(self.records(path))
        self.request(path)
        self.until(lambda: len(self.records(path)) > previous, 'second 304')
        self.fresh(path, 1)
        self.check('304 renewal remains capped despite one-day origin max-age', self.records(path)[-1]['status'] == 304)
        self.set(path, version=2, modified_version=1)
        self.expire()
        self.request(path)
        changed = self.fresh(path, 2)
        self.check('same-length changed content replaces old cache', len(changed[2]) == len(first[2]) and changed[2] != first[2])
        self.check('ETag detects changes even when Last-Modified is unchanged', changed[1]['Last-Modified'] == first[1]['Last-Modified'])

        path='/short/item'
        self.set(path,cache_control='public,max-age=1',omit_304_cache_control=True)
        self.fill(path);self.expire();self.request(path);self.fresh(path,1)
        count=len(self.records(path));self.expire();self.request(path)
        self.until(lambda:len(self.records(path))>count,'short TTL after 304')
        self.check('a 304 without freshness headers preserves the shorter stored TTL',self.records(path)[-1]['status']==304)

        path = '/modified/item'
        self.set(path, validators='modified')
        self.fill(path)
        self.expire(); self.request(path)
        self.until(lambda: any(r['status'] == 304 for r in self.records(path)), 'Last-Modified validation')
        record = self.records(path)[-1]
        self.check('Last-Modified alone is used without an invented ETag', record['etag'] is None and record['modified'] is not None)
        self.set(path, version=2)
        self.expire(); self.request(path); self.fresh(path, 2)
        self.check('Last-Modified changes fetch a new body', self.records(path)[-1]['status'] == 200)

        path = '/plain/item'
        self.set(path, validators='none')
        self.fill(path); self.set(path, version=2)
        self.expire(); self.request(path); self.fresh(path, 2)
        record = self.records(path)[-1]
        self.check('missing validators fall back to full GET', record['etag'] is None and record['modified'] is None and record['status'] == 200)
        path='/redirect/item'
        self.fill(path);self.set(path,status=301);self.expire()
        sequence=self.status()['sequence'];self.request(path)
        self.until(lambda:self.status()['sequence']>sequence,'redirect invalidation')
        values=[self.request(path),self.request(path)]
        self.check('redirects withdraw old successful bodies without becoming cached successes',all(v[0]==301 and v[1]['X-Cache']!='HIT' for v in values))

        path = '/forced/item'
        self.set(path, cache_control='public,max-age=86400', accel=True)
        self.fill(path); self.set(path, version=2)
        self.expire(); self.request(path); self.fresh(path, 2)
        self.check('force-cache rules cannot postpone the configured check', len(self.records(path)) >= 2)
        path = '/accel/item'
        self.set(path, accel=True)
        self.fill(path); self.set(path, version=2)
        self.expire(); self.request(path); self.fresh(path, 2)
        self.check('X-Accel-Expires is capped without globally ignoring origin headers', len(self.records(path)) >= 2)

        path='/head/item'
        self.fill(path);self.set(path,version=2);self.expire()
        connection=http.client.HTTPConnection('127.0.0.1',self.http,timeout=6)
        try:
            connection.request('HEAD',path,headers={'X-Scope':'one'})
            response=connection.getresponse();body=response.read()
            self.check('HEAD clients receive no body while a GET refresh fills the cache', response.status==200 and body==b'')
        finally:connection.close()
        self.fresh(path,2)
        self.check('background HEAD conversion fetches the complete representation',self.records(path)[-1]['method']=='GET')

        path='/off/item'
        first=self.fill(path);self.set(path,version=2);self.expire()
        self.check('disabled locations retain native long-lived caching',self.request(path)[2]==first[2])

        path = '/vary/item'
        self.fill(path, language='en'); self.fill(path, language='fr')
        self.set(path, version=2); self.expire()
        self.request(path, language='en'); en = self.fresh(path, 2, 'en')
        self.request(path, language='fr'); fr = self.fresh(path, 2, 'fr')
        self.check('Vary representations retain independent validators and bodies', b':en:' in en[2] and b':fr:' in fr[2]
                   and all(r['status'] == 200 for r in self.records(path)[-2:]))

        path = '/concurrent/item'
        self.fill(path)
        started, release = threading.Event(), threading.Event()
        self.set(path, version=2, gate=(started, release)); self.expire()
        before = len(self.records(path))
        try:
            result = self.request(path)
            self.until(started.is_set, 'background update started')
            with ThreadPoolExecutor(max_workers=24) as pool:
                results = list(pool.map(lambda _: self.request(path), range(48)))
            self.check('two workers coalesce a concurrent background update', len(self.records(path)) == before + 1
                       and all(r[0] == 200 and r[2].startswith(b'v1:') for r in results))
            self.check('the triggering client does not wait for the origin body', result[2].startswith(b'v1:') and not release.is_set())
        finally:
            release.set()
        self.fresh(path, 2)

        path = '/failure/item'
        self.fill(path); self.set(path, status=503); self.expire()
        self.request(path)
        self.until(lambda: self.records(path)[-1]['status'] == 503, 'failed validation')
        before = len(self.records(path))
        with ThreadPoolExecutor(max_workers=16) as pool:
            values = list(pool.map(lambda _: self.request(path), range(40)))
        time.sleep(0.1)
        if len(self.records(path)) != before or any(v[0] != 200 for v in values):
            print('retry diagnostic', before, len(self.records(path)), [v[0] for v in values], self.status(), flush=True)
        self.check('a failed origin is not retried for every hot request', len(self.records(path)) == before and all(v[0] == 200 for v in values))
        time.sleep(1.05); self.request(path)
        self.until(lambda: len(self.records(path)) > before, 'bounded retry')
        self.set(path, status=200, version=2)
        time.sleep(1.05); self.request(path); self.fresh(path, 2)
        self.check('retry suppression ends and recovery refreshes the cache', self.records(path)[-1]['status'] == 200)

        path = '/error-only/item'
        self.fill(path); self.set(path, status=503); self.expire()
        value = self.request(path)
        self.check('503 reuses stale content within the error window', value[0] == 200 and value[1]['X-Cache'] == 'STALE')
        time.sleep(4.1)
        self.check('stale-if-error cannot outlive its configured window', self.request(path)[0] == 503)
        path = '/bounded/item'
        self.fill(path); self.set(path, status=500)
        time.sleep(7.1)
        self.check('native unconditional stale flags cannot bypass module time limits', self.request(path)[0] == 500)
        path = '/blocking/item'
        self.fill(path); self.set(path, version=2); self.expire()
        value = self.request(path)
        self.check('zero update window requires foreground validation', value[2].startswith(b'v2:') and value[1]['X-Cache'] == 'EXPIRED')

        for status in (403, 404, 410):
            path = f'/withdrawn/{status}'
            self.fill(path); self.set(path, status=status); self.expire()
            sequence = self.status()['sequence']; self.request(path)
            self.until(lambda: self.status()['sequence'] > sequence, 'withdrawn resource invalidation')
            self.check(f'{status} withdraws stale successful content', self.request(path)[0] == status)
        path = '/privacy/item'
        self.fill(path); self.set(path, cache_control='private,no-store', version=2); self.expire()
        sequence = self.status()['sequence']; self.request(path)
        self.until(lambda: self.status()['sequence'] > sequence, 'private response invalidation')
        values = [self.request(path), self.request(path)]
        self.check('a resource becoming private is invalidated and not recached',
                   all(v[2].startswith(b'v2:') and v[1]['X-Cache'] != 'HIT' for v in values))
        path='/cookie/item'
        self.fill(path);self.set(path,cookie=True,version=2);self.expire()
        sequence=self.status()['sequence'];self.request(path)
        self.until(lambda:self.status()['sequence']>sequence,'Set-Cookie invalidation')
        self.check('a response becoming session-specific withdraws the old public cache',self.request(path)[1]['X-Cache']!='HIT')
        path='/privacy304/item'
        self.fill(path);self.set(path,cache_control='private,no-store');self.expire()
        saved=self.root/'temporarily-unavailable-journal';self.journal.rename(saved)
        try:
            self.request(path)
            self.until(lambda:any(r['status']==304 for r in self.records(path)),'uncacheable 304')
            time.sleep(0.2)
            self.check('an uncacheable 304 cannot renew old TTL when durable invalidation fails',self.request(path)[1]['X-Cache']!='HIT')
        finally:saved.rename(self.journal)
        time.sleep(1.05);sequence=self.status()['sequence'];self.request(path)
        self.until(lambda:self.status()['sequence']>sequence,'uncacheable 304 recovery')
        self.check('withdrawal retries after journal availability recovers',self.request(path)[1]['X-Cache']!='HIT')

        path = '/partial/item'
        self.fill(path); self.set(path, version=2, truncate=True); self.expire()
        self.request(path)
        self.until(lambda: len(self.records(path)) > 1, 'truncated update')
        time.sleep(0.2)
        self.check('an incomplete 200 cannot replace a complete cached object', self.request(path)[2].startswith(b'v1:'))
        self.set(path, truncate=False); time.sleep(1.1); self.request(path); self.fresh(path, 2)

        path = '/split/item'
        self.set(path, split=True)
        self.fill(path); self.set(path, version=2); self.expire()
        self.request(path); self.fresh(path, 2)
        self.check('split status and header reads retain the validation hook', len(self.records(path)) >= 2)

        path = '/purged/item'
        self.fill(path); self.set(path, status=503)
        self.control('exact', keys=[path])
        self.check('explicit invalidation never falls back to the purged epoch', self.request(path)[0] == 503)
        path = '/race/item'
        self.fill(path)
        started, release = threading.Event(), threading.Event()
        self.set(path, version=2, gate=(started, release)); self.expire()
        self.request(path); self.until(started.is_set, 'old refresh in flight')
        self.control('exact', keys=[path]); self.set(path, version=3, gate=None)
        try:
            self.fresh(path, 3)
        finally:
            release.set()
        time.sleep(0.1)
        self.check('an old refresh cannot resurrect a manually purged version', self.request(path)[2].startswith(b'v3:'))
        self.check('automatic refreshes preserve worker processes', self.workers() == workers)
        self.check('revalidation metrics are exposed as per-worker counters', 'worker_revalidate' in self.status())
        metrics={}
        for _ in range(30):
            value=self.status();metrics[value['worker_pid']]=value['worker_revalidate']
            if len(metrics)==2:break
        self.check('304 completion is counted',sum(m['not_modified'] for m in metrics.values())>0)
        self.check('completed 200 replacement is counted',sum(m['fetched'] for m in metrics.values())>0)
        self.check('origin metadata and credentials are not logged', self.token not in (self.root / 'error.log').read_text(errors='replace'))

        text = self.path.read_text()
        for directive in ('scdn_purge_revalidate 0;', 'scdn_purge_revalidate 25h;',
                          'scdn_purge_stale updating=1s updating=2s;',
                          'scdn_purge_stale updating=1s error=25h;'):
            invalid = self.root / 'invalid.conf'
            invalid.write_text(text.replace('scdn_purge_revalidate 1s;', directive, 1))
            result = subprocess.run([str(self.nginx), '-t', '-p', str(self.root) + '/', '-c', str(invalid)], capture_output=True)
            self.check('invalid policy rejected: ' + directive, result.returncode != 0)
        return self.checks


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--prefix', required=True, type=Path)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    prefix = args.prefix / 'nginx' if (args.prefix / 'nginx/sbin/nginx').exists() else args.prefix
    with tempfile.TemporaryDirectory(prefix='scdn-revalidate-test-') as directory:
        review = Revalidation(Path(directory), prefix.resolve())
        try:
            checks = review.run()
            if args.report:
                args.report.write_text(json.dumps(dict(passed=len(checks), checks=checks), indent=2) + '\n')
            print(f'{len(checks)} revalidation checks passed', flush=True)
        except Exception:
            dump_runtime_logs(review.root)
            raise
        finally:
            for state in review.origin.settings.values():
                if state.get('gate'):
                    state['gate'][1].set()
            review.close()


if __name__ == '__main__':
    main()
