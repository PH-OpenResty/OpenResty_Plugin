#!/usr/bin/env python3
"""An unacknowledged receipt survives capacity pressure and a real lease expiry."""
import argparse
import http.server
import json
import socketserver
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'native-sync/tests'))
from integration import Review, free_port, write


class Purge(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        with self.server.guard:
            self.server.bodies.append(body.decode())
        result = b'{"ok":true}\n'
        self.send_response(200)
        self.send_header('Content-Length', str(len(result)))
        self.end_headers()
        self.wfile.write(result)

    def log_message(self, *args):
        pass


class UnixHTTP(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def wait(predicate, timeout=15):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        value = predicate()
        if value:
            return value
        time.sleep(.03)
    raise AssertionError('fixture deadline')


def fields(path):
    return path.read_bytes()[70:].split(b'\n', 14)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--prefix', required=True, type=Path)
    parser.add_argument('--static', action='store_true')
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    prefix = args.prefix / 'nginx' if (args.prefix / 'nginx/sbin/nginx').exists() else args.prefix
    output = {}
    with tempfile.TemporaryDirectory(prefix='sync-audit-receipt-') as temporary:
        root = Path(temporary)
        review = Review(root, prefix, None if args.static else prefix / 'modules/ngx_http_scdn_sync_module.so')
        for name in ('logs', 'master-tasks', 'node-tasks'):
            (root / name).mkdir(mode=0o700)
        purge = UnixHTTP(str(root / 'purge.sock'), Purge)
        purge.guard = threading.Lock()
        purge.bodies = []
        threading.Thread(target=purge.serve_forever, daemon=True).start()
        token = f'scdn_sync_control_token_file {root}/control.token;'
        control = 'location /__scdn_sync/v1/ { scdn_sync_api control; }'
        master = f'''scdn_sync_role master; scdn_sync_id master-a; {token}
          scdn_sync_peer node-a edge {review.fingerprint};
          scdn_sync_cache_tasks {root}/master-tasks;
          client_body_buffer_size 128k;'''
        write(root / 'fail-ack', 'fixture')
        servers = f'''server {{ listen unix:{review.master_socket}; {control} }}
          server {{ listen 127.0.0.1:{review.exchange_port} ssl;
          ssl_certificate {root}/master.crt; ssl_certificate_key {root}/master.key;
          ssl_client_certificate {root}/ca.crt; ssl_verify_client on;
          location = /_scdn_sync/v1/cache/result {{
            set $blocked "";
            if ($http_x_task_id = unacked) {{ set $blocked A; }}
            if (-f {root}/fail-ack) {{ set $blocked "${{blocked}}B"; }}
            if ($blocked = AB) {{ return 503; }}
            scdn_sync_api exchange;
          }}
          location /_scdn_sync/v1/ {{ scdn_sync_api exchange; }} }}'''
        node = f'''scdn_sync_role node; scdn_sync_id node-a; scdn_sync_scope edge; {token}
          scdn_sync_cache_tasks {root}/node-tasks;
          scdn_sync_cache_master https://localhost:{review.exchange_port};
          scdn_sync_cache_mtls {root}/ca.crt {root}/node-a.crt {root}/node-a.key;
          scdn_sync_cache_purge {root}/purge.sock {root}/control.token /purge;
          scdn_sync_cache_site one http://localhost:{free_port()};
          scdn_sync_cache_poll 100ms;'''
        original = review.config
        review.config = lambda *args: original(*args).replace('worker_processes 2;',
            'worker_processes 2;\nthread_pool scdn_sync_tasks threads=1 max_queue=16;')
        try:
            master_cfg = review.test_config('master', master, servers)
            node_cfg = review.test_config('node', node,
                f'server {{ listen unix:{review.node_socket}; {control} }}')
            review.launch('master', master_cfg)
            review.launch('node', node_cfg)

            def task(name, method='POST'):
                return review.request('/__scdn_sync/v1/cache/tasks', role='master',
                    method=method, body=('/' + name + '\n') if method == 'POST' else None,
                    headers={'Content-Type': 'text/plain', 'X-Node-ID': 'node-a',
                             'X-Task-ID': name, 'X-Task-Type': 'refresh',
                             'X-Purge-Mode': 'exact', 'X-Purge-Scope': 'one'})

            def terminal(name):
                status, _, body = task(name, 'GET')
                return status == 200 and json.loads(body)['state'] == 'succeeded'

            assert task('unacked')[0] == 202
            receipt = root / 'node-tasks/node-a/unacked.done'
            wait(receipt.exists)
            first_fields = fields(receipt)
            output['unacknowledged_receipt_lease'] = int(first_fields[10])
            assert output['unacknowledged_receipt_lease'] > 0
            output['master_before_gc'] = json.loads(task('unacked', 'GET')[2])['state']
            assert output['master_before_gc'] == 'running'
            print('First durable receipt: ' + json.dumps(output), flush=True)
            # Receipt age uses whole seconds. Avoid ties with later fixture tasks.
            time.sleep(1.1)
            for i in range(128):
                name = f'acked-{i:03}'
                assert task(name)[0] == 202
                wait(lambda: terminal(name))
                assert task(name, 'DELETE')[0] == 200
                if i in (31, 63, 95, 127):
                    print(f'Completed {i + 1} sequential temporary cache tasks', flush=True)
            output['unacknowledged_receipt_survives_capacity'] = receipt.exists()
            output['master_after_gc'] = json.loads(task('unacked', 'GET')[2])['state']
            with purge.guard:
                output['initial_effect_count'] = purge.bodies.count('/unacked\n')
            print('Receipt capacity result: ' + json.dumps(output), flush=True)
            assert receipt.exists()
            assert output['master_after_gc'] == 'running'
            # Keep the actual 120-second Master lease; do not rewrite task state.
            (root / 'fail-ack').unlink()
            print('Waiting for the real lease expiry to verify repeated side effect', flush=True)
            wait(lambda: terminal('unacked'), timeout=135)
            with purge.guard:
                output['effect_count_after_lease'] = purge.bodies.count('/unacked\n')
            assert output['effect_count_after_lease'] == 1
            wait(lambda: int(fields(receipt)[10]) == 0)
            print(json.dumps(output, indent=2), flush=True)
            if args.report:
                args.report.write_text(json.dumps({'passed': 6, 'checks': output}, indent=2) + '\n')
        finally:
            review.close()
            purge.shutdown()
            purge.server_close()


if __name__ == '__main__':
    main()
