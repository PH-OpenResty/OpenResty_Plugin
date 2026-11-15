#!/usr/bin/env python3
"""Real mTLS Master -> native Node -> persistent Purge / cache warmup path."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from integration import Review, free_port, identity, write
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tests'))
from nginx_process import assert_clean_startup, runtime_log_offsets, worker_pids


class Origin(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def do_GET(self):
        with self.server.guard:
            version = self.server.version
            self.server.records.append((self.path, self.headers.get('X-Clinet-IP')))
        if self.path.startswith('/slow/'):
            self.server.slow.set()
            time.sleep(2)
        body = f'v{version}:{self.path}'.encode()
        status = 302 if self.path.startswith('/redirect/') else 503 if self.path.startswith('/fail/') else 200
        self.send_response(status)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('ETag', f'"v{version}"')
        self.send_header('Cache-Control', 'private,no-store' if self.path.startswith('/private/') else 'public,max-age=600')
        if status == 302:
            self.send_header('Location', 'http://redirect.example.test/unused')
        self.end_headers()
        try:
            self.wfile.write(body)
        except (OSError, ConnectionError):
            pass

    def log_message(self, *args):
        pass


class OriginServer(http.server.ThreadingHTTPServer):
    daemon_threads = True


class CacheReview(Review):
    def __init__(self, root, prefix, static):
        super().__init__(root, prefix, None if static else prefix / 'modules/ngx_http_scdn_sync_module.so')
        self.static = static
        self.http, self.https = free_port(), free_port()
        self.purge_socket = root / 'purge.sock'
        self.purge_token = secrets.token_urlsafe(32)
        write(root / 'purge.token', self.purge_token + '\n')
        for role in ('master', 'node'):
            (root / (role + '-tasks')).mkdir(mode=0o700)
        (root / 'logs').mkdir()
        # A second registered identity exercises per-node isolation, without an executor.
        from cryptography.hazmat.primitives import serialization, hashes
        from cryptography import x509
        ca = x509.load_pem_x509_certificate((root / 'ca.crt').read_bytes())
        key = serialization.load_pem_private_key((root / 'ca.key').read_bytes(), password=None)
        _, peer = identity(root, 'node-b', key, ca)
        self.second_fingerprint = peer.fingerprint(hashes.SHA256()).hex()
        self.origin = OriginServer(('127.0.0.1', 0), Origin)
        self.origin.guard = threading.Lock()
        self.origin.version, self.origin.records = 1, []
        self.origin.slow = threading.Event()
        threading.Thread(target=self.origin.serve_forever, daemon=True).start()

    def config(self, name, directives, servers):
        text = super().config(name, directives, servers)
        if not self.static:
            text = text.replace('worker_processes 2;',
                f'load_module {self.prefix}/modules/ngx_http_scdn_purge_module.so;\nworker_processes 2;')
        return text.replace('worker_processes 2;', 'worker_processes 2;\n'
            'thread_pool scdn_sync_tasks threads=1 max_queue=16;\n'
            'thread_pool scdn_cache_purge threads=1 max_queue=16;')

    def job(self, name, kind='refresh', mode='exact', scope='one', body='/asset\n',
            node='node-a', method='POST', headers=None, role='master', token=True):
        supplied = {'Content-Type': 'text/plain', 'X-Task-ID': name, 'X-Task-Type': kind,
                    'X-Purge-Mode': mode, 'X-Node-ID': node}
        if scope is not None:
            supplied['X-Purge-Scope'] = scope
        supplied.update(headers or {})
        return self.request('/__scdn_sync/v1/cache/tasks', role=role, method=method,
                            token=token, body=body if method == 'POST' else None, headers=supplied)

    def status(self, name, node='node-a', role='master'):
        status, _, body = self.job(name, node=node, method='GET', role=role)
        return status, json.loads(body)

    def until(self, predicate, description, timeout=15):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            time.sleep(.025)
        raise AssertionError('deadline: ' + description)

    def terminal(self, name):
        def done():
            status, value = self.status(name)
            return value if status == 200 and value['state'] in ('succeeded', 'failed') else None
        try:
            return self.until(done, 'task ' + name)
        except AssertionError:
            print('Master task diagnostic:', self.status(name), flush=True)
            print('Node task diagnostic:', self.status(name, role='node'), flush=True)
            raise

    def asset(self, path='/asset', headers=None, tls=False):
        if tls:
            import ssl
            connection = http.client.HTTPSConnection('localhost', self.https,
                context=ssl.create_default_context(cafile=str(self.root / 'ca.crt')), timeout=5)
        else:
            connection = http.client.HTTPConnection('127.0.0.1', self.http, timeout=5)
        try:
            connection.request('GET', path, headers={'Host': 'localhost', **(headers or {})})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def fill(self, path='/asset'):
        return self.until(lambda: (v if (v := self.asset(path))[1].get('X-Cache') == 'HIT' else None), 'cache fill')

    def submit(self, name, **kwargs):
        result = self.job(name, **kwargs)
        self.check(name + ' durably accepted', result[0] == 202)
        return self.terminal(name)

    def run(self):
        token = f'scdn_sync_control_token_file {self.root}/control.token;'
        control = 'location /__scdn_sync/v1/ { scdn_sync_api control; }'
        exchange = 'location /_scdn_sync/v1/ { scdn_sync_api exchange; }'
        master = f'''scdn_sync_role master; scdn_sync_id master-a; {token}
            scdn_sync_peer node-a edge {self.fingerprint};
            scdn_sync_peer node-b other {self.second_fingerprint};
            scdn_sync_cache_tasks {self.root}/master-tasks;
            scdn_sync_cache_allow_all on;
            client_body_buffer_size 128k; client_max_body_size 64k;'''
        master_servers = f'''server {{ listen unix:{self.master_socket}; {control} }}
            server {{ listen 127.0.0.1:{self.exchange_port} ssl;
                ssl_certificate {self.root}/master.crt; ssl_certificate_key {self.root}/master.key;
                ssl_client_certificate {self.root}/ca.crt; ssl_verify_client on;
                location = /_scdn_sync/v1/cache/result {{
                    if (-f {self.root}/fail-ack) {{ return 503; }}
                    scdn_sync_api exchange;
                }}
                {exchange} }}'''
        node = f'''scdn_sync_role node; scdn_sync_id node-a; scdn_sync_scope edge; {token}
            scdn_sync_cache_tasks {self.root}/node-tasks;
            scdn_sync_cache_master https://localhost:{self.exchange_port};
            scdn_sync_cache_mtls {self.root}/ca.crt {self.root}/node-a.crt {self.root}/node-a.key;
            scdn_sync_cache_purge {self.purge_socket} {self.root}/purge.token /purge;
            scdn_sync_cache_site one http://localhost:{self.http};
            scdn_sync_cache_site secure https://localhost:{self.https};
            scdn_sync_cache_local_ca {self.root}/ca.crt;
            scdn_sync_cache_allow_all on;
            scdn_sync_cache_poll 100ms;
            scdn_purge_zone epochs 4m; scdn_purge_journal {self.root}/epochs.log;
            scdn_purge_token_file {self.root}/purge.token; scdn_purge_allow_all on;
            proxy_cache_path {self.root}/cache levels=1:2 keys_zone=content:4m;
            client_body_buffer_size 128k;'''
        business = f'''location / {{
            scdn_purge_key one "$request_uri";
            proxy_cache content; proxy_cache_key $scdn_purge_key;
            proxy_pass http://127.0.0.1:{self.origin.server_port};
            proxy_set_header X-Clinet-IP $remote_addr;
            proxy_cache_valid 200 10m; proxy_cache_lock on;
            proxy_buffer_size 16k; proxy_buffers 8 16k;
            add_header X-Cache $upstream_cache_status always;
        }}'''
        node_servers = f'''server {{ listen unix:{self.node_socket}; {control} }}
            server {{ listen unix:{self.purge_socket}; location = /purge {{ scdn_purge_api; }} }}
            server {{ listen 127.0.0.1:{self.http}; server_name localhost; {business} }}
            server {{ listen 127.0.0.1:{self.https} ssl; server_name localhost;
                ssl_certificate {self.root}/master.crt; ssl_certificate_key {self.root}/master.key;
                {business.replace('scdn_purge_key one', 'scdn_purge_key secure')}
            }}'''
        examples = Path(__file__).resolve().parents[1] / 'examples'
        template = (examples / 'cache-master.conf').read_text().replace(
            '/var/lib/scdn-sync-native/master/cache-tasks', str(self.root / 'master-tasks'))
        self.test_config('published-master-cache-template',
            f'scdn_sync_role master; scdn_sync_id master-a; {token}' + template, master_servers)
        template = (examples / 'cache-node.conf').read_text()
        replacements = {
            '/var/lib/scdn-sync-native/node/cache-tasks': str(self.root / 'node-tasks'),
            'https://sync.example.com:8443': f'https://localhost:{self.exchange_port}',
            '/etc/scdn-sync-native/node/pki/master-ca.crt': str(self.root / 'ca.crt'),
            '/etc/scdn-sync-native/node/pki/node.crt': str(self.root / 'node-a.crt'),
            '/etc/scdn-sync-native/node/pki/node.key': str(self.root / 'node-a.key'),
            '/run/scdn-purge/control.sock': str(self.purge_socket),
            '/etc/scdn-purge/control.token': str(self.root / 'purge.token'),
            'http://www.example.com:8081': f'http://localhost:{self.http}',
        }
        for source, destination in replacements.items():
            template = template.replace(source, destination)
        self.test_config('published-node-cache-template',
            f'scdn_sync_role node; scdn_sync_id node-a; scdn_sync_scope edge; {token}' + template,
            f'server {{ listen unix:{self.node_socket}; {control} }}')
        self.test_config('off-tasks', f'scdn_sync_cache_tasks {self.root}/master-tasks;', expected=False)
        self.test_config('incomplete-node-tasks', f'scdn_sync_role node; scdn_sync_id node-a; '
            f'scdn_sync_scope edge; scdn_sync_cache_tasks {self.root}/node-tasks;', expected=False)
        self.test_config('insecure-master-url', node.replace('https://localhost:', 'http://localhost:'), expected=False)
        self.test_config('master-url-userinfo', node.replace('https://localhost:', 'https://' + 'user:example@localhost:'), expected=False)
        self.test_config('preheat-url-path', node.replace(f'http://localhost:{self.http};', f'http://localhost:{self.http}/path;'), expected=False)
        self.test_config('poll-too-fast', node.replace('100ms', '1ms'), expected=False)
        self.test_config('duplicate-site', node + f'scdn_sync_cache_site one http://localhost:{self.http};', expected=False)
        self.test_config('master-node-only-setting', master + 'scdn_sync_cache_poll 1s;', expected=False)
        self.master_config = self.test_config('master', master, master_servers)
        self.node_config = self.test_config('node', node, node_servers)
        self.launch('master', self.master_config)
        self.check('task control requires bearer auth', self.job('unauthorized', token=False)[0] == 401)
        self.check('unknown node rejected', self.job('unknown-node', node='unknown')[0] == 404)
        self.check('preheat rejects empty body', self.job('empty', kind='preheat', body='')[0] == 400)
        for index, body in enumerate(('http://example.test/a\n', '//example.test/a\n', '/a#b\n',
                                      '/a%0d%0ab\n', '/a\\b\n', '/a\r\n', '/a%XX\n')):
            self.check('unsafe preheat target ' + str(index), self.job('unsafe' + str(index), kind='preheat', body=body)[0] == 400)
        self.check('task batch bound enforced', self.job('too-many', body='/x\n' * 257)[0] == 400)
        self.check('oversized task rejected', self.job('too-big', body='x' * 65537)[0] == 413)
        self.check('only exact preheat accepted', self.job('prefix-warm', kind='preheat', mode='prefix')[0] == 400)
        first = self.job('durable-warm', kind='preheat', body='/warm?x=1%202\n')
        self.check('Master queues before Node exists', first[0] == 202 and json.loads(first[2])['state'] == 'queued')
        self.check('same ID and payload are idempotent', self.job('durable-warm', kind='preheat', body='/warm?x=1%202\n')[0] == 200)
        self.check('same ID different payload conflicts', self.job('durable-warm', kind='preheat', body='/other\n')[0] == 409)
        self.check('nonterminal task cannot be deleted', self.job('durable-warm', method='DELETE')[0] == 409)
        self.check('other mTLS Node cannot pull this task', self.request('/_scdn_sync/v1/cache/next', exchange=True,
            certificate='node-b', method='POST', body='', token=False)[0] == 204)
        self.check('unregistered certificate cannot pull tasks', self.request('/_scdn_sync/v1/cache/next', exchange=True,
            certificate='unregistered', method='POST', body='', token=False)[0] == 403)
        self.check('read method cannot consume a lease', self.request('/_scdn_sync/v1/cache/next', exchange=True,
            method='GET', token=False)[0] == 405)
        self.check('mTLS node cannot claim another node ID', self.request('/_scdn_sync/v1/cache/next', exchange=True,
            certificate='node-b', method='POST', body='', token=False, headers={'X-Node-ID': 'node-a'})[0] == 400)
        self.check('scope-change fixture queued', self.job('scope-change', node='node-b')[0] == 202)
        self.edit_record(self.root / 'master-tasks/node-b/scope-change.task', node_scope='previous-scope')
        self.check('new registration scope does not execute an older scoped task',
            self.request('/_scdn_sync/v1/cache/next', exchange=True, certificate='node-b',
                         method='POST', body='', token=False)[0] == 204
            and self.status('scope-change', node='node-b')[1]['error'] == 'node_scope_changed')
        self.check('obsolete scoped task is terminal and removable',
                   self.job('scope-change', node='node-b', method='DELETE')[0] == 200)
        self.check('lease fixture queued', self.job('lease-exhausted', node='node-b')[0] == 202)
        self.edit_record(self.root / 'master-tasks/node-b/lease-exhausted.task', state=1, attempt=3, lease=0)
        self.check('expired final lease becomes failed rather than executing indefinitely',
            self.request('/_scdn_sync/v1/cache/next', exchange=True, certificate='node-b',
                         method='POST', body='', token=False)[0] == 204
            and self.status('lease-exhausted', node='node-b')[1]['error'] == 'lease_expired')
        self.check('exhausted lease task is removable', self.job('lease-exhausted', node='node-b', method='DELETE')[0] == 200)
        old_master = self.processes[-1]
        old_master.terminate(); old_master.wait(timeout=10)
        self.launch('master', self.master_config)
        self.check('Master restart preserves queued task', self.status('durable-warm')[1]['state'] == 'queued')
        self.launch('node', self.node_config)
        workers = [worker_pids(process.pid) for process in self.processes[-2:]]
        result = self.terminal('durable-warm')
        self.check('native Node pulls and acknowledges persisted warmup', result['state'] == 'succeeded' and result['completed'] == 1)
        value = self.asset('/warm?x=1%202')
        self.check('unvisited resource is already a cache HIT', value[1].get('X-Cache') == 'HIT')
        self.fill()
        with self.origin.guard:
            self.origin.version = 2
        self.check('old resource remains cached before refresh', self.asset()[2].startswith(b'v1:'))
        result = self.submit('refresh-one')
        self.check('refresh completes after durable Purge commit', result['state'] == 'succeeded' and result['completed'] == 1
                   and result['physical_deleted'] is False)
        self.check('refreshed request fetches updated origin body', self.asset()[2].startswith(b'v2:'))
        result = self.submit('batch-warm', kind='preheat', body='/batch/a\n/batch/b\n')
        self.check('batch warmup verifies both cache entries', result['state'] == 'succeeded' and result['completed'] == 2
                   and self.asset('/batch/a')[1]['X-Cache'] == 'HIT' and self.asset('/batch/b')[1]['X-Cache'] == 'HIT')
        result = self.submit('batch-refresh', body='/batch/a\n/batch/b\n')
        self.check('batch refresh invalidates both entries', result['state'] == 'succeeded' and result['completed'] == 2
                   and self.asset('/batch/a')[1]['X-Cache'] == 'MISS' and self.asset('/batch/b')[1]['X-Cache'] == 'MISS')
        write(self.root / 'fail-ack', 'test fault')
        self.check('lost-ack task accepted', self.job('lost-ack', kind='preheat', body='/lost-ack\n')[0] == 202)
        self.until(lambda: self.status('lost-ack', role='node')[0] == 200
                   and self.status('lost-ack', role='node')[1]['state'] == 'succeeded', 'Node result before ACK')
        self.check('failed ACK does not mark Master task complete', self.status('lost-ack')[1]['state'] == 'running')
        before_ack = len([r for r in self.origin.records if r[0] == '/lost-ack'])
        node_process = self.processes[-1]
        node_process.terminate(); node_process.wait(timeout=10)
        (self.root / 'fail-ack').unlink()
        # Advance this fixture's persisted lease, without a two minute sleep.
        self.edit_record(self.root / 'master-tasks/node-a/lost-ack.task', lease=0)
        self.launch('node', self.node_config)
        workers = [worker_pids(self.processes[1].pid), worker_pids(self.processes[-1].pid)]
        result = self.terminal('lost-ack')
        self.check('Node restart and lost ACK replay the durable result', result['state'] == 'succeeded'
                   and result['attempt'] == 2 and before_ack == len([r for r in self.origin.records if r[0] == '/lost-ack']))
        for index, (mode, target) in enumerate((('prefix', '/match/'), ('wildcard', '/match/*'),
                ('regex', '^/match/.*$'), ('suffix', '.js'), ('directory', '/match/'),
                ('site', ''), ('node', ''))):
            path = f'/match/file{index}.js'
            self.fill(path)
            result = self.submit('mode-' + mode, mode=mode, body=target, scope=None if mode == 'node' else 'one')
            self.check('distributed ' + mode + ' invalidation', result['state'] == 'succeeded' and self.asset(path)[1]['X-Cache'] == 'MISS')
        result = self.submit('scope-denied', scope='unregistered-cache-scope')
        self.check('Node cache scope allowlist enforced', result['state'] == 'failed' and result['error'] == 'scope_not_allowed')
        for name, path in (('not-cacheable', '/private/item'), ('redirect', '/redirect/item'), ('origin-failed', '/fail/item')):
            result = self.submit(name, kind='preheat', body=path + '\n')
            self.check(name + ' is never falsely successful', result['state'] == 'failed' and result['completed'] == 0)
        result = self.submit('tls-warm', kind='preheat', scope='secure', body='/https/item\n')
        self.check('HTTPS preheat retains hostname and verifies CA', result['state'] == 'succeeded'
                   and self.asset('/https/item', tls=True)[1]['X-Cache'] == 'HIT')
        self.asset('/ip-header', headers={'X-Clinet-IP': '192.0.2.30'})
        self.check('client IP header is overwritten from the connection',
                   ('/ip-header', '127.0.0.1') in self.origin.records)
        self.check('Node cannot submit Master jobs', self.job('node-submit', role='node')[0] == 403)
        self.check('Sync token cannot authorize Purge', self.purge_with_sync_token() == 401)
        with ThreadPoolExecutor(max_workers=6) as pool:
            accepted = list(pool.map(lambda _: self.job('concurrent', kind='preheat', body='/concurrent\n')[0], range(6)))
        result = self.terminal('concurrent')
        self.check('concurrent producers share one durable task identity', accepted.count(202) == 1
                   and all(status in (200, 202) for status in accepted) and result['state'] == 'succeeded')
        self.job('slow-warm', kind='preheat', body='/slow/item\n')
        self.until(self.origin.slow.is_set, 'background origin request')
        start = time.monotonic()
        self.check('cache traffic progresses during slow warmup', self.asset('/warm?x=1%202')[0] == 200
                   and time.monotonic() - start < .75)
        self.check('slow warmup finishes', self.terminal('slow-warm')['state'] == 'succeeded')
        self.check('cache jobs do not rebuild either instance Workers',
                   workers == [worker_pids(self.processes[1].pid), worker_pids(self.processes[-1].pid)])
        before = len([record for record in self.origin.records if record[0] == '/concurrent'])
        node_process = self.processes[-1]
        node_process.terminate(); node_process.wait(timeout=10)
        self.launch('node', self.node_config)
        self.check('terminal Master result survives Node restart', self.status('concurrent')[1]['state'] == 'succeeded')
        time.sleep(.3)
        self.check('acknowledged task is not executed again after restart',
                   before == len([record for record in self.origin.records if record[0] == '/concurrent']))
        self.check('terminal task can be explicitly removed', self.job('concurrent', method='DELETE')[0] == 200
                   and self.status('concurrent')[0] == 404)
        # Corruption fails visibly and is never interpreted as an empty queue.
        corrupt = self.root / 'master-tasks/node-b/broken.task'
        write(corrupt, 'broken task record')
        self.check('corrupt task blocks only its own Node queue', self.request('/_scdn_sync/v1/cache/next', exchange=True,
            certificate='node-b', method='POST', body='', token=False)[0] == 503)
        corrupt.unlink()
        # Queue capacity is checked on actual durable records, not an unbounded memory list.
        with ThreadPoolExecutor(max_workers=4) as pool:
            accepted = list(pool.map(lambda i: self.job('capacity-' + str(i), node='node-b')[0], range(128)))
        self.check('per-Node queue accepts its bounded capacity', all(status == 202 for status in accepted))
        self.check('full queue fails explicitly', self.job('capacity-overflow', node='node-b')[0] == 507)
        result = self.submit('healthy-after-other-corruption', kind='preheat', body='/healthy\n')
        self.check('other Node queue failure does not block healthy Node', result['state'] == 'succeeded')
        for process in self.processes:
            self.check('created process has not crashed', process.poll() in (None, 0))
        for role in ('master', 'node'):
            logs = ''.join((self.root / role / name).read_text(errors='replace') for name in ('stdout.log', 'error.log'))
            self.check(role + ' logs omit both tokens and task bodies', self.token not in logs and self.purge_token not in logs
                       and 'AddressSanitizer' not in logs and 'runtime error:' not in logs)
        return self.checks

    @staticmethod
    def edit_record(path, **changes):
        payload = path.read_bytes()[70:]
        fields = payload.split(b'\n', 14)
        for name, value in changes.items():
            fields[{'state': 6, 'attempt': 7, 'lease': 10, 'node_scope': 2}[name]] = str(value).encode()
        fields[13] = hashlib.sha256(b'\n'.join(fields[:6]) + b'\n' + fields[14]).hexdigest().encode()
        payload = b'\n'.join(fields)
        path.write_bytes(b'SCT1:' + hashlib.sha256(payload).hexdigest().encode() + b'\n' + payload)

    def purge_with_sync_token(self):
        connection = http.client.HTTPConnection('localhost', timeout=3)
        connection.sock = socket.socket(socket.AF_UNIX)
        connection.sock.connect(str(self.purge_socket))
        try:
            connection.request('POST', '/purge', body='/a\n', headers={'Authorization': 'Bearer ' + self.token,
                'Content-Type': 'text/plain', 'X-Purge-Mode': 'exact', 'X-Purge-Scope': 'one'})
            response = connection.getresponse()
            status = response.status
            response.read()
            return status
        finally:
            connection.close()

    def close(self):
        super().close()
        self.origin.shutdown()
        self.origin.server_close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--prefix', type=Path, required=True)
    parser.add_argument('--static', action='store_true')
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    prefix = args.prefix / 'nginx' if (args.prefix / 'nginx/sbin/nginx').exists() else args.prefix
    with tempfile.TemporaryDirectory(prefix='scdn-cache-task-test-') as directory:
        review = CacheReview(Path(directory), prefix, args.static)
        try:
            checks = review.run()
            if args.report:
                args.report.write_text(json.dumps(dict(passed=len(checks), checks=checks), indent=2) + '\n')
            print(f'{len(checks)} native cache task checks passed', flush=True)
        except Exception:
            for role in ('master', 'node'):
                for name in ('error.log', 'stdout.log'):
                    path = review.root / role / name
                    if path.exists():
                        print(f'[{role}/{name}]\n' + path.read_text(errors='replace')[-6000:]
                              .replace(review.token, '[redacted]').replace(review.purge_token, '[redacted]'), flush=True)
            raise
        finally:
            review.close()


if __name__ == '__main__':
    main()
