#!/usr/bin/env python3
"""Real reload, key rotation and authenticated sequence recovery regressions."""
import argparse
import http.server
import json
import signal
import sys
import tempfile
import time
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'native-sync/tests'))
from distribution import Review as DistributionReview
from integration import write
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

class Probe(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        node = self.path.split('/')[1]
        with self.server.guard:
            self.server.active[node] = self.server.active.get(node, 0) + 1
            self.server.maximum[node] = max(self.server.maximum.get(node, 0), self.server.active[node])
        time.sleep(.3)
        with self.server.guard: self.server.active[node] -= 1
        self.send_response(200); self.send_header('Content-Length', '0'); self.end_headers()
    def log_message(self, *args): pass

class Review(DistributionReview):
    def config(self, name, directives, servers):
        if name in ('node-a', 'node-b'):
            import re
            probes = '\n'.join(f'scdn_sync_config_probe http://127.0.0.1:{self.probe_port}/{name}/{i} 200;' for i in range(4))
            directives = re.sub(r'scdn_sync_config_probe [^;]*;', probes, directives)
            directives += '\nscdn_sync_config_apply_timeout 5s;'
        return super().config(name, directives, servers)


def metadata(path):
    envelope = path.read_bytes()
    return {'sequence': int.from_bytes(envelope[8:16], 'big'),
            'scope': envelope[152:152 + envelope[49]].decode()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--prefix', required=True, type=Path)
    parser.add_argument('--static', action='store_true')
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    prefix = args.prefix / 'nginx' if (args.prefix / 'nginx/sbin/nginx').exists() else args.prefix
    output = {}
    with tempfile.TemporaryDirectory(prefix='sync-audit-scope-') as temporary:
        root = Path(temporary)
        review = Review(root, prefix, args.static)
        probes = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Probe)
        probes.guard = threading.Lock(); probes.active = {}; probes.maximum = {}; probes.daemon_threads = True
        review.probe_port = probes.server_port
        threading.Thread(target=probes.serve_forever, daemon=True).start()
        try:
            review.start()
            review.applied(); review.applied(1)
            desired = root / 'publisher/node-a/desired.bundle'
            output['initial_publication'] = metadata(desired)
            review.processes[1].terminate()
            review.processes[1].wait(timeout=10)
            master = review.master_config.read_text()
            master = master.replace('scdn_sync_peer node-a edge ', 'scdn_sync_peer node-a reassigned ')
            master = master.replace(f'scdn_sync_config_source edge {review.source};',
                f'scdn_sync_config_source edge {review.source};\n'
                f'scdn_sync_config_source reassigned {review.source};')
            write(review.master_config, master)
            review.processes[0].send_signal(signal.SIGHUP)
            state = root / 'replacement-state'
            state.mkdir(mode=0o700)
            write(state / 'active.conf', f'sites {{ site bootstrap {{ host localhost; enabled off; '
                f'upstream http://127.0.0.1:{review.origins[0].server_port}; cache off; }} }}\n')
            node = review.node_configs[0].read_text().replace('scdn_sync_scope edge;',
                'scdn_sync_scope reassigned;').replace(str(root / 'node-a-state'), str(state))
            write(review.node_configs[0], node)
            review.launch('node-a', review.node_configs[0])
            review.until(lambda: metadata(desired)['scope'] == 'reassigned', 'scope-bound publication rebuilt')
            applied = review.applied(after=1)
            output['configured_scope'] = 'reassigned'
            output['publication_after_reload'] = metadata(desired)
            output['node_error_after_reload'] = review.state()['last_error']
            assert output['publication_after_reload']['scope'] == 'reassigned'
            assert not output['node_error_after_reload']
            previous = int(applied['sequence'])
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            write(root / 'node-a-decrypt.key', key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode())
            write(root / 'node-a-encrypt.pub', key.public_key().public_bytes(serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo).decode())
            rotated = review.applied(after=previous)
            output['key_rotation_sequence'] = int(rotated['sequence'])
            (root / 'publisher/node-a/sequence.state').unlink()
            review.update(review.source.read_text() + '\n# a new configuration after state loss\n')
            recovered = review.applied(after=int(rotated['sequence']))
            output['recovered_sequence'] = int(recovered['sequence'])
            assert output['recovered_sequence'] > output['key_rotation_sequence'] > previous
            output['live_business_status'] = review.call(0)[0]
            assert output['live_business_status'] == 200
            output['probe_parallelism'] = dict(probes.maximum)
            assert probes.maximum == {'node-a': 4, 'node-b': 4}
            assert recovered['business_health'] == 'passed'
            print(json.dumps(output, indent=2), flush=True)
            if args.report: args.report.write_text(json.dumps({'passed': 8, 'checks': output}, indent=2) + '\n')
        finally:
            review.close()
            probes.shutdown(); probes.server_close()


if __name__ == '__main__':
    main()
