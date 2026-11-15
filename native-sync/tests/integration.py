#!/usr/bin/env python3
"""Exercise the compiled module in isolated master and node nginx instances."""
from __future__ import annotations

import argparse
import datetime
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tests'))
from nginx_process import assert_clean_startup,runtime_log_offsets,wait_for_workers


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def write(path, value, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding='utf-8')
    path.chmod(mode)


def identity(root, name, ca_key=None, ca_cert=None, server=False):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    ca = ca_key is None
    builder = (x509.CertificateBuilder().subject_name(subject)
        .issuer_name(ca_cert.subject if ca_cert else subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), critical=True))
    if not ca:
        builder = builder.add_extension(x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        builder = builder.add_extension(x509.SubjectAlternativeName([
            x509.DNSName('localhost' if server else name)]), critical=False)
    cert = builder.sign(ca_key or key, hashes.SHA256())
    write(root / (name + '.crt'), cert.public_bytes(serialization.Encoding.PEM).decode())
    write(root / (name + '.key'), key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode())
    return key, cert


class Review:
    def __init__(self, root, prefix, module):
        self.root, self.prefix, self.module = root, prefix, module
        self.nginx = prefix / 'sbin/nginx'
        self.processes, self.logs, self.checks = [], [], []
        self.token = secrets.token_urlsafe(32)
        write(root / 'control.token', self.token + '\n')
        ca_key, ca = identity(root, 'ca')
        identity(root, 'master', ca_key, ca, server=True)
        _, peer = identity(root, 'node-a', ca_key, ca)
        identity(root, 'unregistered', ca_key, ca)
        self.fingerprint = peer.fingerprint(hashes.SHA256()).hex()
        self.exchange_port, self.control_port = free_port(), free_port()
        self.master_socket, self.node_socket = root / 'master.sock', root / 'node.sock'

    def check(self, name, condition):
        if not condition:
            raise AssertionError(name)
        self.checks.append(name)
        print('PASS ' + name, flush=True)

    def config(self, name, directives, servers):
        runtime = self.root / name
        runtime.mkdir(exist_ok=True)
        user = 'user root root;\n' if os.geteuid() == 0 else ''
        modules=f'load_module {self.module};\n' if self.module is not None else ''
        return (f'{modules}{user}worker_processes 2;\n'
            f'pid {runtime}/nginx.pid;\nerror_log {runtime}/error.log warn;\n'
            f'events {{ worker_connections 128; }}\nhttp {{ access_log off; '
            f'client_header_timeout 3s; client_body_timeout 3s; keepalive_timeout 2s; '
            f'{directives}\n{servers}\n}}\n')

    def test_config(self, name, directives, servers='', expected=True, fragment=None):
        path = self.root / (name + '.conf')
        write(path, self.config(name, directives, servers))
        result = subprocess.run([str(self.nginx), '-p', str(self.root) + '/', '-t', '-c', str(path)],
                                capture_output=True, text=True, timeout=10)
        if 'ERROR: AddressSanitizer' in result.stderr or 'runtime error:' in result.stderr:
            raise AssertionError('sanitizer diagnostic in configuration test: '
                                 + result.stderr.replace(self.token, '[redacted]'))
        if ((result.returncode == 0) != expected
                or (fragment is not None and fragment not in result.stderr)):
            print(f'configuration diagnostic: {name}, exit={result.returncode}\n'
                  + result.stderr.replace(self.token, '[redacted]'), flush=True)
        self.check('configuration: ' + name, (result.returncode == 0) == expected
                   and (fragment is None or fragment in result.stderr))
        return path

    def launch(self, name, config):
        runtime=self.root/name
        path = runtime/'stdout.log'
        log = path.open('wb')
        offsets=runtime_log_offsets(runtime)
        process = subprocess.Popen([str(self.nginx), '-p', str(self.root) + '/',
            '-c', str(config), '-g', 'daemon off;'], stdout=log, stderr=log)
        self.processes.append(process)
        self.logs.append(log)
        wait_for_workers(process)
        assert_clean_startup(runtime,offsets)

    def request(self, path, role='node', method='GET', token=True, body=None, headers=None,
                exchange=False, certificate='node-a', tcp=False):
        supplied = dict(headers or {})
        if token:
            supplied['Authorization'] = 'Bearer ' + self.token
        if exchange:
            context = ssl.create_default_context(cafile=str(self.root / 'ca.crt'))
            if certificate:
                context.load_cert_chain(str(self.root / (certificate + '.crt')),
                                        str(self.root / (certificate + '.key')))
            connection = http.client.HTTPSConnection('localhost', self.exchange_port, context=context, timeout=3)
        elif tcp:
            connection = http.client.HTTPConnection('127.0.0.1', self.control_port, timeout=3)
        else:
            connection = http.client.HTTPConnection('localhost', timeout=3)
            connection.sock = socket.socket(socket.AF_UNIX)
            connection.sock.settimeout(3)
            connection.sock.connect(str(self.master_socket if role == 'master' else self.node_socket))
        try:
            connection.request(method, path, body=body, headers=supplied)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def run(self):
        registered = f'scdn_sync_peer node-a edge {self.fingerprint};'
        token = f'scdn_sync_control_token_file {self.root}/control.token;'
        control = 'location /__scdn_sync/v1/ { scdn_sync_api control; }'
        exchange = 'location /_scdn_sync/v1/ { scdn_sync_api exchange; }'
        plain_server = f'server {{ listen 127.0.0.1:{free_port()}; {control} }}'
        node = f'scdn_sync_role node; scdn_sync_id node-a; scdn_sync_scope edge; {token}'
        master = f'scdn_sync_role master; scdn_sync_id master-a; {token} {registered}'
        self.test_config('default-off', '',
                         f'server {{ listen 127.0.0.1:{free_port()}; return 200 "$scdn_sync_role"; }}')
        self.test_config('off-with-api', '', plain_server, expected=False, fragment='active role')
        self.test_config('unknown-role', 'scdn_sync_role primary;', expected=False, fragment='off, master or node')
        self.test_config('duplicate-role', 'scdn_sync_role master; scdn_sync_role node;', expected=False, fragment='duplicate')
        self.test_config('missing-id', 'scdn_sync_role master;', expected=False, fragment='instance ID')
        self.test_config('invalid-id', 'scdn_sync_role master; scdn_sync_id ../master;', expected=False, fragment='instance ID')
        self.test_config('missing-scope', 'scdn_sync_role node; scdn_sync_id node-a;', expected=False, fragment='requires a scope')
        self.test_config('master-with-scope', master + 'scdn_sync_scope edge;', expected=False, fragment='individual peer')
        self.test_config('node-registers-peers', node + registered, expected=False, fragment='cannot register peers')
        self.test_config('duplicate-peer', master + registered, expected=False, fragment='duplicates a node')
        self.test_config('invalid-fingerprint', 'scdn_sync_role master; scdn_sync_id master-a; scdn_sync_peer node-a edge invalid;',
                         expected=False, fragment='DER fingerprint')
        self.test_config('node-exchange', node, f'server {{ listen 127.0.0.1:{free_port()}; {exchange} }}',
                         expected=False, fragment='requires the master role')
        self.test_config('master-without-mtls', master, f'server {{ listen 127.0.0.1:{free_port()}; {exchange} }}',
                         expected=False, fragment='ssl_verify_client on')
        self.test_config('missing-token', 'scdn_sync_role node; scdn_sync_id node-a; scdn_sync_scope edge;',
                         plain_server, expected=False, fragment='absolute token file')
        write(self.root / 'weak.token', 'weak\n')
        self.test_config('weak-token', node.replace('control.token', 'weak.token'), plain_server,
                         expected=False, fragment='bounded token')
        write(self.root / 'public.token', self.token, mode=0o644)
        self.test_config('public-token', node.replace('control.token', 'public.token'), plain_server,
                         expected=False, fragment='private regular file')
        (self.root / 'link.token').symlink_to(self.root / 'control.token')
        self.test_config('symlink-token', node.replace('control.token', 'link.token'), plain_server,
                         expected=False, fragment='cannot open')
        self.test_config('handler-after-api', node,
                         f'server {{ listen 127.0.0.1:{free_port()}; '
                         'location / { scdn_sync_api control; proxy_pass http://127.0.0.1:9; } }',
                         expected=False,fragment='replaced by another content handler')
        self.test_config('handler-before-api', node,
                         f'server {{ listen 127.0.0.1:{free_port()}; '
                         'location / { proxy_pass http://127.0.0.1:9; scdn_sync_api control; } }',
                         expected=False,fragment='conflicts with another content handler')

        master_servers = f'''
server {{ listen unix:{self.master_socket}; {control} }}
server {{ listen 127.0.0.1:{self.exchange_port} ssl;
    ssl_certificate {self.root}/master.crt; ssl_certificate_key {self.root}/master.key;
    ssl_client_certificate {self.root}/ca.crt; ssl_verify_client on;
    ssl_protocols TLSv1.2 TLSv1.3; ssl_session_tickets off;
    {exchange}
}}'''
        node_servers = f'''
server {{ listen unix:{self.node_socket}; listen 127.0.0.1:{self.control_port};
    {control}
    location = /variables {{ return 200 "$scdn_sync_role|$scdn_sync_id|$scdn_sync_scope"; }}
}}'''
        master_config = self.test_config('master', master, master_servers)
        node_config = self.test_config('node', node, node_servers)
        self.launch('master', master_config)
        self.launch('node', node_config)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                if self.request('/__scdn_sync/v1/status')[0] == 200:
                    break
            except (OSError, http.client.HTTPException):
                pass
            time.sleep(0.05)
        else:
            raise AssertionError('native node did not start')

        for role in ('master', 'node'):
            status, headers, body = self.request('/__scdn_sync/v1/status', role=role)
            value = json.loads(body)
            self.check(role + ' identifies its role', status == 200 and value['role'] == role)
            self.check(role + ' does not falsely report applied or healthy',
                       value['applied_revision'] is None and value['business_health'] == 'unknown'
                       and value['sync_state'] == 'not_started')
            self.check(role + ' control is not cacheable', headers.get('Cache-Control') == 'no-store')
            status, headers, body = self.request('/__scdn_sync/v1/status', role=role, token=False)
            self.check(role + ' rejects missing token', status == 401 and 'WWW-Authenticate' in headers)
            status, headers, _ = self.request('/__scdn_sync/v1/status', role=role, token=False,
                                        headers={'Authorization': 'Bearer invalid'})
            self.check(role + ' rejects incorrect token', status == 401 and 'WWW-Authenticate' in headers)
        status, _, body = self.request('/__scdn_sync/v1/peers', role='master')
        self.check('master lists scoped peers without fingerprints', status == 200
                   and json.loads(body)['peers'] == [dict(node_id='node-a',scope_id='edge')]
                   and self.fingerprint.encode() not in body)
        self.check('node has no master peer management route',
                   self.request('/__scdn_sync/v1/peers')[0] == 404)
        status, _, body = self.request('/__scdn_sync/v1/capabilities')
        features = json.loads(body)['features']
        self.check('capabilities disclose the unimplemented synchronization functions', status == 200
                   and not features['encrypted_distribution'] and not features['apply_transactions']
                   and not features['node_pull'])
        status, _, body = self.request('/variables', tcp=True)
        self.check('native role variables work without Lua', status == 200 and body == b'node|node-a|edge')
        self.check('loopback control still requires authentication',
                   self.request('/__scdn_sync/v1/status',tcp=True,token=False)[0] == 401)
        self.check('query credentials are rejected',
                   self.request('/__scdn_sync/v1/status?token=invalid',token=False)[0] == 400)
        self.check('empty query is rejected',self.request('/__scdn_sync/v1/status?')[0] == 400)
        self.check('encoded control paths are rejected',self.request('/%5f_scdn_sync/v1/status')[0] == 400)
        status, headers, body = self.request('/__scdn_sync/v1/status',method='HEAD')
        self.check('HEAD returns metadata without a response body', status == 200 and not body
                   and int(headers['Content-Length']) > 0)
        status, headers, _ = self.request('/__scdn_sync/v1/status',method='POST',body='{}')
        self.check('mutation methods cannot succeed', status == 405 and headers.get('Allow') == 'GET, HEAD')
        self.check('GET bodies are rejected',self.request('/__scdn_sync/v1/status',body='invalid')[0] == 400)

        status, _, body = self.request('/_scdn_sync/v1/capabilities',exchange=True,token=False)
        value = json.loads(body)
        self.check('registered mTLS identity is mapped to its node and scope', status == 200
                   and value['role'] == 'master' and value['peer'] == dict(node_id='node-a',scope_id='edge'))
        status, _, _ = self.request('/_scdn_sync/v1/capabilities',exchange=True,
                                    certificate='unregistered',headers={'X-Node-ID':'node-a'})
        self.check('token and claimed node ID cannot authorize an unregistered certificate',status == 403)
        try:
            status, _, _ = self.request('/_scdn_sync/v1/capabilities',exchange=True,certificate=None)
            rejected = status != 200
        except (ssl.SSLError, OSError, http.client.HTTPException):
            rejected = True
        self.check('exchange requires a client certificate',rejected)
        self.check('exchange cannot access local control routes',
                   self.request('/__scdn_sync/v1/status',exchange=True)[0] == 404)
        self.check('local control cannot serve master distribution routes',
                   self.request('/_scdn_sync/v1/desired')[0] == 404)
        self.check('unimplemented distribution cannot return a false success',
                   self.request('/_scdn_sync/v1/desired',exchange=True)[0] == 404)
        for name in ('master','node'):
            log = ''.join((self.root/name/filename).read_text(errors='replace')
                          for filename in ('error.log','stdout.log'))
            self.check(name + ' logs contain no control token',self.token not in log)
        return self.checks

    def close(self):
        for process in reversed(self.processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        for log in self.logs:
            log.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--prefix',required=True,type=Path)
    parser.add_argument('--module',type=Path)
    parser.add_argument('--static',action='store_true')
    parser.add_argument('--report',type=Path)
    args = parser.parse_args()
    if args.static and args.module:
        parser.error('--static cannot load a separate --module')
    prefix = args.prefix/'nginx' if (args.prefix/'nginx/sbin/nginx').exists() else args.prefix
    module = None if args.static else (args.module or prefix/'modules/ngx_http_scdn_sync_module.so').resolve()
    with tempfile.TemporaryDirectory(prefix='scdn-native-test-') as directory:
        review = Review(Path(directory),prefix.resolve(),module)
        try:
            checks = review.run()
            if args.report:
                args.report.parent.mkdir(parents=True,exist_ok=True)
                args.report.write_text(json.dumps(dict(passed=len(checks),checks=checks),indent=2)+'\n')
            print(f'{len(checks)} native master/node checks passed',flush=True)
        except Exception:
            for role in ('master','node'):
                for name in ('error.log','stdout.log'):
                    path=review.root/role/name
                    if path.exists():
                        print(f'[{role}/{name}]\n'+path.read_text(errors='replace')[-6000:].replace(review.token,'[redacted]'),flush=True)
            raise
        finally:
            review.close()


if __name__ == '__main__':
    main()
