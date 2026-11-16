#!/usr/bin/env python3
"""Encrypted Master publication and real multi-Worker configuration/TLS apply."""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from integration import Review as RoleReview, identity, free_port, write
from nginx_process import worker_pids


class Origin(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith('/slow'):
            self.server.entered.set()
            time.sleep(1.5)
        body = (self.server.label + ':' + self.path).encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Content-Type', 'text/plain')
        self.send_header('ETag', '"distribution"')
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass
    def log_message(self, *args):
        pass


class Review(RoleReview):
    def __init__(self, root, prefix, static):
        super().__init__(root, prefix, None if static else prefix / 'modules/ngx_http_scdn_sync_module.so')
        self.static = static
        (root / 'logs').mkdir()
        self.ca = x509.load_pem_x509_certificate((root / 'ca.crt').read_bytes())
        self.ca_key = serialization.load_pem_private_key((root / 'ca.key').read_bytes(), password=None)
        _, cert = identity(root, 'node-b', self.ca_key, self.ca)
        self.fingerprint_b = cert.fingerprint(hashes.SHA256()).hex()
        _, self.site_cert = identity(root, 'business', self.ca_key, self.ca, server=True)
        for name in ('signing',):
            key = ed25519.Ed25519PrivateKey.generate()
            write(root / (name + '.key'), key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode())
            write(root / (name + '.pub'), key.public_key().public_bytes(serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo).decode())
        for name in ('node-a', 'node-b'):
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            write(root / (name + '-decrypt.key'), key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode())
            write(root / (name + '-encrypt.pub'), key.public_key().public_bytes(serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo).decode())
        self.origins = []
        for label in ('a', 'b'):
            origin = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Origin)
            origin.daemon_threads = True; origin.label = label; origin.entered = threading.Event()
            threading.Thread(target=origin.serve_forever, daemon=True).start()
            self.origins.append(origin)
        self.http_ports = [free_port(), free_port()]
        self.tls_ports = [free_port(), free_port()]
        self.health_ports = [free_port(), free_port()]
        for name in ('publisher', 'node-a-state', 'node-b-state'):
            (root / name).mkdir(mode=0o700)
        for name in ('node-a', 'node-b'):
            write(root / (name + '-state/active.conf'), f'sites {{ site bootstrap {{ host localhost; enabled off; upstream http://127.0.0.1:{self.origins[0].server_port}; cache off; }} }}\n')
        self.source = root / 'source.conf'
        self.source.write_text(self.sites())

    def config(self, name, directives, servers):
        text = super().config(name, directives, servers)
        modules = '' if self.static else ''.join(f'load_module {self.prefix}/modules/ngx_http_scdn_{module}_module.so;\n'
                                                for module in ('config', 'ban', 'api', 'edge'))
        return text.replace('worker_processes 2;', modules + '''worker_processes 2;
            thread_pool scdn_config_reader threads=1 max_queue=2;
            thread_pool scdn_sync_distribution threads=2 max_queue=16;
            thread_pool scdn_sync_publisher threads=1 max_queue=2;''')

    def sites(self, origin=0, extra='', enabled='on'):
        return f'''sites {{ site alpha {{ host localhost; enabled {enabled};
            upstream http://127.0.0.1:{self.origins[origin].server_port}; cache off;
            cache_headers on; cache_request_header X-Cache-Tag "published";
            certificate {self.root}/business.crt; certificate_key {self.root}/business.key;
            prefix /api/ {{ upstream http://127.0.0.1:{self.origins[origin].server_port}; cache off; }}
        }} {extra} }}\n'''

    def update(self, text):
        temporary = self.root / 'source.next'
        temporary.write_text(text); temporary.replace(self.source)

    def call(self, node, path='/asset', tls=False, host='localhost'):
        connection = http.client.HTTPConnection('127.0.0.1', self.http_ports[node], timeout=5)
        certificate = None
        if tls:
            raw = socket.create_connection(('127.0.0.1', self.tls_ports[node]), timeout=5)
            context = ssl.create_default_context(cafile=str(self.root / 'ca.crt'))
            connection.sock = context.wrap_socket(raw, server_hostname='localhost')
            certificate = hashlib.sha256(connection.sock.getpeercert(binary_form=True)).hexdigest()
        try:
            connection.request('GET', path, headers={'Host': host})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read(), certificate
        finally:
            connection.close()

    def state(self, node=0, master=False):
        connection = http.client.HTTPConnection('localhost', timeout=5)
        connection.sock = socket.socket(socket.AF_UNIX); connection.sock.settimeout(5)
        connection.sock.connect(str(self.master_socket if master else self.root / ('node-a.sock' if node == 0 else 'node-b.sock')))
        try:
            connection.request('GET', '/__scdn_sync/v1/status', headers={'Authorization': 'Bearer ' + self.token})
            response = connection.getresponse()
            data = response.read()
            if response.status != 200:
                return {'sync_state': 'http_error', 'last_error': str(response.status)}
            return json.loads(data)
        finally:
            connection.close()

    def until(self, callback, label, timeout=25):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            try:
                value = callback()
                if value: return value
            except (OSError, http.client.HTTPException, KeyError):
                pass
            time.sleep(.05)
        print('Master:', self.state(master=True), flush=True)
        print('Node A:', self.state(), flush=True)
        print('Node B:', self.state(1), flush=True)
        raise AssertionError('deadline: ' + label)

    def applied(self, node=0, after=0):
        return self.until(lambda: s if (s := self.state(node))['sync_state'] == 'applied'
                          and int(s['sequence']) > after else None, 'applied Node ' + str(node))

    def start(self):
        token = f'scdn_sync_control_token_file {self.root}/control.token;'
        control = 'location /__scdn_sync/v1/ { scdn_sync_api control; }'
        master = f'''scdn_sync_role master; scdn_sync_id master-a; {token}
            scdn_sync_peer node-a edge {self.fingerprint}; scdn_sync_peer node-b edge {self.fingerprint_b};
            scdn_sync_config_state {self.root}/publisher;
            scdn_sync_config_source edge {self.source};
            scdn_sync_config_signing_key {self.root}/signing.key;
            scdn_sync_config_peer_key node-a {self.root}/node-a-encrypt.pub;
            scdn_sync_config_peer_key node-b {self.root}/node-b-encrypt.pub;'''
        master_servers = f'''server {{ listen unix:{self.master_socket}; {control} }}
            server {{ listen 127.0.0.1:{self.exchange_port} ssl;
            ssl_certificate {self.root}/master.crt; ssl_certificate_key {self.root}/master.key;
            ssl_client_certificate {self.root}/ca.crt; ssl_verify_client on;
            location = /_scdn_sync/v1/config/result {{
                if (-f {self.root}/fail-ack) {{ return 503; }}
                scdn_sync_api exchange;
            }}
            location /_scdn_sync/v1/ {{ scdn_sync_api exchange; }} }}'''
        self.master_config = self.test_config('master', master, master_servers)
        self.node_configs = []
        for i, name in enumerate(('node-a', 'node-b')):
            state = self.root / (name + '-state')
            node = f'''scdn_sync_role node; scdn_sync_id {name}; scdn_sync_scope edge; {token}
                scdn_sync_config_state {state};
                scdn_sync_config_master https://localhost:{self.exchange_port};
                scdn_sync_config_mtls {self.root}/ca.crt {self.root}/{name}.crt {self.root}/{name}.key;
                scdn_sync_config_trust_key {self.root}/signing.pub;
                scdn_sync_config_decryption_key {self.root}/{name}-decrypt.key;
                scdn_sync_config_status_socket {self.root}/{name}.sock;
                scdn_sync_config_probe http://localhost:{self.health_ports[i]}/health 200;
                scdn_config_managed {state}; scdn_config_zone cfg 128k;
                scdn_config_interval 100ms; scdn_config_settle 200ms;
                scdn_edge_zone counters 2m;'''
            servers = f'''server {{ listen unix:{self.root}/{name}.sock; {control}
                location = /status {{ scdn_config_status; }} }}
                server {{ listen 127.0.0.1:{self.health_ports[i]};
                    location = /health {{
                        if (-f {self.root}/fail-probe) {{ return 503; }}
                        proxy_pass http://127.0.0.1:{self.origins[0].server_port};
                    }} }}
                server {{ listen 127.0.0.1:{self.http_ports[i]}; listen 127.0.0.1:{self.tls_ports[i]} ssl;
                    ssl_certificate {self.root}/master.crt; ssl_certificate_key {self.root}/master.key;
                    ssl_session_cache off; ssl_session_tickets off;
                    scdn_edge on; scdn_edge_tls on;
                    location / {{ return 404; }}
                    location @scdn_edge_proxy {{ proxy_pass $scdn_edge_upstream;
                        proxy_set_header Host $scdn_edge_origin_host;
                        proxy_set_header X-Clinet-IP $remote_addr;
                        proxy_cache off; }} }}'''
            # return in / would terminate before Edge; use a harmless static root.
            servers = servers.replace('location / { return 404; }', f'location / {{ root {self.root}; }}')
            config = self.test_config(name, node, servers)
            self.node_configs.append(config)
        self.launch('master', self.master_config)
        self.launch('node-a', self.node_configs[0]); self.launch('node-b', self.node_configs[1])

    def run(self):
        self.start()
        workers = [worker_pids(process.pid) for process in self.processes]
        a, b = self.applied(), self.applied(1)
        self.check('Master automatically publishes a complete snapshot to both Nodes', int(a['sequence']) == 1 and int(b['sequence']) == 1)
        for i in (0, 1):
            self.check('Node ' + str(i) + ' serves the published origin', self.call(i)[2] == b'a:/asset')
            self.check('Node ' + str(i) + ' installs and serves the published certificate',
                       self.call(i, tls=True)[3] == self.site_cert.fingerprint(hashes.SHA256()).hex())
        first = (self.root / 'publisher/node-a/desired.bundle').read_bytes()
        second = (self.root / 'publisher/node-b/desired.bundle').read_bytes()
        self.check('each Node receives a different encrypted signed envelope', first != second and first[:8] == b'SCNBND02')
        self.check('published envelope contains neither private PEM nor site source',
                   b'PRIVATE KEY' not in first and self.source.read_bytes() not in first and b'upstream http' not in first)
        self.check('Node certificate paths belong to its immutable version directory',
                   b'/node-a-state/releases/r00000000000000000001/000.crt' in (self.root / 'node-a-state/active.conf').read_bytes())
        status, _, _ = self.request('/_scdn_sync/v1/config/desired', exchange=True, token=False, certificate='unregistered')
        self.check('unregistered mTLS identity cannot download snapshots', status == 403)
        self.update(self.sites(origin=1))
        a2, b2 = self.applied(after=1), self.applied(1, after=1)
        self.check('source edit changes routing on both Nodes', self.call(0)[2] == b'b:/asset' and self.call(1)[2] == b'b:/asset')
        self.check('configuration update preserves all Worker PIDs', workers == [worker_pids(p.pid) for p in self.processes])
        self.check('source change advances a durable delivery sequence', int(a2['sequence']) > int(a['sequence']))
        self.update('sites { site broken {')
        self.until(lambda: self.state(master=True)['sync_state'] == 'source_rejected', 'bad source rejected')
        self.check('bad source cannot replace last desired snapshot', (self.root / 'publisher/node-a/desired.bundle').read_bytes() != first
                   and int(self.state()['sequence']) == int(a2['sequence']))
        self.check('both Nodes retain service while Master source is invalid', self.call(0)[2] == b'b:/asset' and self.call(1)[2] == b'b:/asset')
        self.update(self.sites(origin=1, enabled='off'))
        disabled = self.applied(after=int(a2['sequence']))
        self.applied(1, after=int(b2['sequence']))
        self.check('full snapshot carries site disable to every Node', self.call(0)[0] == 403 and self.call(1)[0] == 403)
        self.update(self.sites(origin=1, extra=f'site added {{ host added.example.test; upstream http://127.0.0.1:{self.origins[0].server_port}; cache off; }}'))
        added = self.applied(after=int(disabled['sequence'])); self.applied(1, after=int(disabled['sequence']))
        self.check('full snapshot can add a site', self.call(0, host='added.example.test')[2] == b'a:/asset')
        self.update(self.sites(origin=1))
        removed = self.applied(after=int(added['sequence'])); self.applied(1, after=int(added['sequence']))
        self.check('full snapshot deletion removes an old site', self.call(0, host='added.example.test')[0] == 403)
        _, rotated = identity(self.root, 'business-new', self.ca_key, self.ca, server=True)
        (self.root / 'business.crt').write_bytes((self.root / 'business-new.crt').read_bytes())
        self.until(lambda: self.state(master=True)['sync_state'] == 'source_rejected', 'certificate half rotation')
        self.check('mismatched certificate pair preserves live TLS', self.call(0, tls=True)[3] == self.site_cert.fingerprint(hashes.SHA256()).hex())
        (self.root / 'business.key').write_bytes((self.root / 'business-new.key').read_bytes())
        rotated_state = self.applied(after=int(removed['sequence'])); self.applied(1, after=int(removed['sequence']))
        self.check('same-path certificate rotation propagates without reload', self.call(0, tls=True)[3] == rotated.fingerprint(hashes.SHA256()).hex()
                   and self.call(1, tls=True)[3] == rotated.fingerprint(hashes.SHA256()).hex())
        self.check('certificate rotation preserves Worker PIDs', workers == [worker_pids(p.pid) for p in self.processes])
        write(self.root / 'fail-probe', 'health fault fixture')
        self.update(self.sites(origin=0))
        self.until(lambda: self.state()['last_error'] == 'business_probe_failed', 'failed probe rollback')
        rejected_sequence = int(self.state()['sequence'])
        self.check('failed business probe restores the previous effective route', self.call(0)[2] == b'b:/asset'
                   and self.state()['applied_revision'] == rotated_state['applied_revision'])
        time.sleep(1.2)
        self.check('rejected publication does not repeatedly switch the live configuration',
                   self.state()['last_error'] == 'business_probe_failed' and self.call(0)[2] == b'b:/asset')
        write(self.root / 'fail-ack', 'fault fixture')
        (self.root / 'fail-probe').unlink()
        self.update(self.sites(origin=1))
        ack_pending = self.applied(after=rejected_sequence)
        self.check('Node applies configuration before waiting for Master result receipt',
                   not (self.root / 'node-a-state/apply.pending').exists()
                   and int.from_bytes((self.root / 'node-a-state/reported.state').read_bytes()[8:16], 'big') < int(ack_pending['sequence']))
        (self.root / 'fail-ack').unlink()
        self.until(lambda: int.from_bytes((self.root / 'node-a-state/reported.state').read_bytes()[8:16], 'big') == int(ack_pending['sequence']),
                   'durable result retry')
        self.check('lost result ACK is retried from durable application state', self.state()['applied_revision'] == ack_pending['applied_revision'])
        rotated_state = ack_pending
        latest = (self.root / 'publisher/node-a/desired.bundle').read_bytes()
        self.update('sites { site paused-publisher {')
        self.until(lambda: self.state(master=True)['sync_state'] == 'source_rejected', 'freeze publisher with invalid source')
        corrupted = bytearray(latest); corrupted[-1] ^= 1
        corrupted[8:16] = (int(rotated_state['sequence']) + 1).to_bytes(8, 'big')
        (self.root / 'publisher/node-a/desired.bundle').write_bytes(corrupted)
        self.until(lambda: self.state()['last_error'] == 'snapshot_verification_failed', 'tampered signature')
        self.check('tampered envelope preserves applied configuration', self.call(0)[2] == b'b:/asset')
        (self.root / 'publisher/node-a/desired.bundle').write_bytes(first)
        self.until(lambda: self.state()['last_error'] == 'snapshot_replay_or_conflict', 'old signed snapshot replay')
        self.check('old signed sequence cannot roll back runtime', self.call(0)[2] == b'b:/asset')
        (self.root / 'publisher/node-a/desired.bundle').write_bytes(second)
        self.until(lambda: self.state()['last_error'] == 'snapshot_verification_failed', 'cross-node envelope')
        self.check('snapshot for another Node is rejected', self.call(0)[2] == b'b:/asset')
        # A fully authentic, correctly encrypted envelope still cannot be used
        # outside its publication lifetime.
        expired = bytearray(latest)
        wrapped = int.from_bytes(expired[40:48], 'big')
        rsa_key = serialization.load_pem_private_key((self.root / 'node-a-decrypt.key').read_bytes(), password=None)
        content_key = rsa_key.decrypt(bytes(expired[320:320 + wrapped]), padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        aes = AESGCM(content_key)
        plaintext = aes.decrypt(bytes(expired[280:292]), bytes(expired[320 + wrapped:-64]) + bytes(expired[292:308]), bytes(expired[:292]))
        expired[8:16] = (int(rotated_state['sequence']) + 1).to_bytes(8, 'big')
        expired[16:24] = (int(time.time()) - 172800).to_bytes(8, 'big')
        expired[24:32] = (int(time.time()) - 86400).to_bytes(8, 'big')
        cipher = aes.encrypt(bytes(expired[280:292]), plaintext, bytes(expired[:292]))
        expired[292:308] = cipher[-16:]; expired[320 + wrapped:-64] = cipher[:-16]
        signing = serialization.load_pem_private_key((self.root / 'signing.key').read_bytes(), password=None)
        expired[-64:] = signing.sign(bytes(expired[:-64]))
        (self.root / 'publisher/node-a/desired.bundle').write_bytes(expired)
        self.until(lambda: self.state()['last_error'] == 'snapshot_verification_failed', 'expired signed encrypted publication')
        self.check('expired authentic publication cannot apply or refresh its TTL', self.call(0)[2] == b'b:/asset')
        (self.root / 'publisher/node-a/desired.bundle').write_bytes(latest)
        self.applied(after=int(rotated_state['sequence']) - 1)
        highest_path = self.root / 'node-a-state/highest.state'
        highest = highest_path.read_bytes(); highest_path.write_bytes(b'incomplete')
        self.until(lambda: self.state()['sync_state'] == 'failed', 'corrupt high watermark')
        self.check('corrupt replay watermark fails closed while preserving service', self.call(0)[2] == b'b:/asset')
        highest_path.write_bytes(highest)
        self.applied(after=int(rotated_state['sequence']) - 1)
        master_process = self.processes[0]; master_process.terminate(); master_process.wait(timeout=10)
        self.until(lambda: self.state()['last_error'] == 'master_unavailable', 'Master outage')
        self.check('Master outage does not remove Node configuration or TLS', self.call(0)[2] == b'b:/asset'
                   and self.call(1, tls=True)[3] == rotated.fingerprint(hashes.SHA256()).hex())
        self.launch('master', self.master_config)
        self.update(self.sites(origin=0))
        recovered = self.applied(after=int(rotated_state['sequence']))
        self.check('Master restart preserves monotonic publication', int(recovered['sequence']) > int(rotated_state['sequence'])
                   and self.call(0)[2] == b'a:/asset')
        # Simulate a killed transaction between replacing active.conf and finalization.
        node = self.processes[1]; node.terminate(); node.wait(timeout=10)
        state = self.root / 'node-a-state'
        previous = (state / 'active.conf').read_bytes()
        write(state / 'previous.conf', previous.decode())
        (state / 'apply.pending').write_bytes(b'SCNDP01\0' + hashlib.sha256(previous).digest())
        (state / 'apply.pending').chmod(0o600)
        write(state / 'active.conf', 'broken candidate')
        self.launch('node-a', self.node_configs[0])
        self.until(lambda: self.call(0)[2] == b'a:/asset', 'transaction startup recovery')
        self.check('unfinished transaction recovers before bootstrap', (state / 'active.conf').read_bytes() == previous
                   and not (state / 'apply.pending').exists())
        self.check('durable application receipt survives Node restart', self.applied(after=int(recovered['sequence']) - 1)['applied_revision'] == recovered['applied_revision'])
        self.check('runtime uses only native modules for publication and application',
                   not list(self.root.rglob('*.lua')) and not list(self.root.rglob('*.ljbc')))
        for name in ('master', 'node-a', 'node-b'):
            logs = ''.join((self.root / name / f).read_text(errors='replace') for f in ('error.log', 'stdout.log'))
            self.check(name + ' logs have no token or sanitizer diagnostic', self.token not in logs
                       and 'runtime error:' not in logs and 'AddressSanitizer' not in logs)
        return self.checks

    def close(self):
        super().close()
        for origin in self.origins:
            origin.shutdown(); origin.server_close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--prefix', required=True, type=Path)
    parser.add_argument('--static', action='store_true')
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    prefix = args.prefix / 'nginx' if (args.prefix / 'nginx/sbin/nginx').exists() else args.prefix
    with tempfile.TemporaryDirectory(prefix='sync-distribution-') as directory:
        review = Review(Path(directory), prefix, args.static)
        try:
            checks = review.run()
            if args.report: args.report.write_text(json.dumps({'passed': len(checks), 'checks': checks}, indent=2) + '\n')
            print(f'{len(checks)} configuration distribution checks passed', flush=True)
        except Exception:
            for role in ('master', 'node-a', 'node-b'):
                for name in ('error.log', 'stdout.log'):
                    path = review.root / role / name
                    if path.exists(): print(role, name, path.read_text(errors='replace')[-6000:].replace(review.token, '[redacted]'), flush=True)
            raise
        finally:
            review.close()


if __name__ == '__main__': main()
