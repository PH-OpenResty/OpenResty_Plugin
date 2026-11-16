#!/usr/bin/env python3
"""Exercise the native classifier and real proxy I/O with disposable origins.

No vendor credentials, public model calls or production listeners are used.
"""
from __future__ import annotations

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import datetime
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import signal
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, RequestReceived, ResponseReceived, StreamEnded, TrailersReceived

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def unused_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def certificate(root):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'model.example.test')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName('model.example.test')]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256()))
    (root / 'origin.crt').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    private = root / 'origin.key'
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    private.chmod(0o600)


class OriginServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 128

    def __init__(self):
        self.accepted = 0
        self.lock = threading.Lock()
        self.cancelled = threading.Event()
        self.sni = []
        super().__init__(('127.0.0.1', 0), Origin)

    def get_request(self):
        result = super().get_request()
        with self.lock:
            self.accepted += 1
        return result


class Origin(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *args):
        pass

    def read_body(self):
        if self.headers.get('Transfer-Encoding', '').lower() != 'chunked':
            return self.rfile.read(int(self.headers.get('Content-Length', 0)))
        chunks = []
        while True:
            size = int(self.rfile.readline().split(b';', 1)[0], 16)
            if not size:
                while self.rfile.readline() not in (b'\r\n', b'\n', b''):
                    pass
                return b''.join(chunks)
            chunks.append(self.rfile.read(size))
            assert self.rfile.read(2) == b'\r\n'

    def respond(self):
        body = self.read_body()
        if self.path.startswith(('/events', '/opaque-events', '/v1/chat/completions')):
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Transfer-Encoding', 'chunked')
            self.send_header('Cache-Control', 'public, max-age=60')
            self.end_headers()
            chunks = (b'data: {"delta":"first"}\n\n', b'data: {"delta":"second"}\n\n', b'data: [DONE]\n\n')
            if self.path.endswith('cancel'):
                chunks = (b'data: ' + b'x' * 16384 + b'\n\n',) * 200
            try:
                for index, data in enumerate(chunks):
                    if index:
                        time.sleep(.03 if self.path.endswith('cancel') else .6)
                    self.wfile.write(f'{len(data):X}\r\n'.encode() + data + b'\r\n')
                    self.wfile.flush()
                self.wfile.write(b'0\r\n\r\n'); self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                self.server.cancelled.set()
            return
        if self.path.startswith('/ws'):
            nonce = self.headers.get('Sec-WebSocket-Key', '')
            accept = base64.b64encode(hashlib.sha1((nonce + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
            self.send_response(101)
            self.send_header('Upgrade', 'websocket')
            self.send_header('Connection', 'Upgrade')
            self.send_header('Sec-WebSocket-Accept', accept)
            self.end_headers()
            try:
                frame = self.rfile.read(2)
                mask = self.rfile.read(4)
                data = self.rfile.read(frame[1] & 127)
                decoded = bytes(value ^ mask[index % 4] for index, value in enumerate(data))
                self.wfile.write(bytes([0x81, len(decoded)]) + decoded); self.wfile.flush()
            except (OSError, IndexError):
                pass
            self.close_connection = True
            return
        result = json.dumps({'method': self.command, 'path': self.path,
            'body_sha256': hashlib.sha256(body).hexdigest(), 'body_bytes': len(body),
            'host': self.headers.get('Host'), 'profile': self.headers.get('X-Test-Profile'),
            'client_ip': self.headers.get('X-Clinet-IP'),
            'connection_header': self.headers.get('Connection'),
            'accept_encoding': self.headers.get('Accept-Encoding'),
            'source_port': self.client_address[1]}, sort_keys=True).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain' if self.path.startswith('/asset') else 'application/json')
        self.send_header('Cache-Control', 'public, max-age=60')
        self.send_header('ETag', '"api-fixture"')
        self.send_header('Content-Length', str(len(result)))
        self.end_headers()
        self.wfile.write(result)

    do_GET = respond
    do_POST = respond
    do_PUT = respond
    do_OPTIONS = respond


class GrpcOrigin(socketserver.BaseRequestHandler):
    def handle(self):
        connection = H2Connection(config=H2Configuration(client_side=False, header_encoding='utf-8'))
        connection.initiate_connection()
        self.request.sendall(connection.data_to_send())
        bodies = {}
        try:
            while True:
                data = self.request.recv(65536)
                if not data:
                    return
                for event in connection.receive_data(data):
                    if isinstance(event, RequestReceived):
                        bodies[event.stream_id] = bytearray()
                    elif isinstance(event, DataReceived):
                        bodies[event.stream_id].extend(event.data)
                        connection.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                    elif isinstance(event, StreamEnded):
                        connection.send_headers(event.stream_id, [(':status', '200'), ('content-type', 'application/grpc')])
                        connection.send_data(event.stream_id, bytes(bodies.pop(event.stream_id)))
                        connection.send_headers(event.stream_id, [('grpc-status', '0')], end_stream=True)
                self.request.sendall(connection.data_to_send())
        except (OSError, ValueError):
            return


class GrpcServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


class Review:
    def __init__(self, root, prefix, static, templates=False, purge=False, sync=False):
        self.root, self.static, self.templates, self.purge = root, static, templates, purge
        self.sync=sync
        self.sync_token=base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip('=')
        if sync:
            token=root/'sync.token'
            token.write_text(self.sync_token+'\n');token.chmod(0o600)
        self.purge_token = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip('=')
        if purge:
            token = root / 'purge.token'
            token.write_text(self.purge_token + '\n')
            token.chmod(0o600)
        self.prefix = prefix / 'nginx' if (prefix / 'nginx/sbin/nginx').exists() else prefix
        self.http, self.tls = unused_port(), unused_port()
        self.socket = root / 'control.sock'
        self.nginx = self.prefix / 'sbin/nginx'
        self.process = None
        self.checks = []
        self.origins = [OriginServer(), OriginServer()]
        self.grpc = GrpcServer(('127.0.0.1', 0), GrpcOrigin)
        threading.Thread(target=self.grpc.serve_forever, daemon=True).start()
        certificate(root)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(root / 'origin.crt', root / 'origin.key')
        context.set_servername_callback(lambda sock, name, ctx: self.origins[1].sni.append(name))
        self.origins[1].socket = context.wrap_socket(self.origins[1].socket, server_side=True)
        for server in self.origins:
            threading.Thread(target=server.serve_forever, daemon=True).start()
        self.source = root / 'sites.conf'
        self.source.write_text(self.sites())

    def sites(self, origin_host='model.example.test'):
        return f'''sites {{
site plain {{ host www.example.test; upstream http://pooled-origin; cache l1; }}
site tls {{ host tls.example.test; upstream https://tls-origin; origin_host {origin_host}; cache off; }}
site direct {{ host direct.example.test; upstream https://127.0.0.1:{self.origins[1].server_port}; origin_host model.example.test; cache off; }}
site badtls {{ host badtls.example.test; upstream https://tls-origin; origin_host wrong.example.test; cache off; }}
site grpc {{ host grpc.example.test; upstream http://grpc-origin; cache off; }}
site prefix {{ host prefix.example.test; upstream http://pooled-origin; cache off;
 prefix /secure/ {{ upstream https://tls-origin; origin_host model.example.test; cache off; }} }}
}}'''

    def proxy(self, name, profile, cache=False, stream=False):
        key = '"$scdn_api_cache_namespace|$scdn_edge_revision|$host|$request_uri"'
        purge = ''
        if self.purge:
            purge = 'scdn_purge_key $scdn_edge_site ' + key + ' $request_uri;\n scdn_purge_revalidate 1h;'
            key = '$scdn_purge_key'
        return f'''location @{name} {{
 {purge}
 proxy_pass $scdn_edge_upstream;
 proxy_http_version 1.1;
 proxy_set_header Host $scdn_edge_origin_host;
 proxy_set_header Connection $scdn_api_connection;
 proxy_set_header Upgrade $http_upgrade;
 proxy_set_header Accept-Encoding "";
 proxy_set_header X-Test-Profile {profile};
 proxy_set_header X-Clinet-IP $remote_addr;
 proxy_ssl_server_name on;
 proxy_ssl_name $scdn_edge_origin_sni;
 proxy_ssl_verify on;
 proxy_ssl_trusted_certificate {self.root}/origin.crt;
 proxy_ssl_verify_depth 2;
 proxy_ignore_client_abort off;
 proxy_connect_timeout 1s;
 proxy_read_timeout {'8s' if stream else '3s'};
 proxy_send_timeout 8s;
 proxy_next_upstream off;
 proxy_cache {'$scdn_edge_cache' if cache else 'off'};
 proxy_cache_key {key};
 proxy_cache_bypass $scdn_api_skip_cache;
 proxy_no_cache $scdn_api_skip_cache;
 proxy_cache_valid 200 1m;
 {'proxy_buffering off; proxy_request_buffering off; gzip off;' if stream else ''}
}}'''

    def config(self):
        names=('config','ban','api','edge')+ (('purge',) if self.purge else ()) + (('sync',) if self.sync else ())
        modules = '' if self.static else '\n'.join(
            f'load_module {self.prefix}/modules/ngx_http_scdn_{name}_module.so;'
            for name in names)
        user = 'user root root;' if os.geteuid() == 0 else ''
        purge = ''
        purge_control = ''
        sync=''
        sync_control=''
        if self.sync:
            sync=f'''scdn_sync_role node; scdn_sync_id integration-node;
 scdn_sync_scope edge; scdn_sync_control_token_file {self.root}/sync.token;'''
            sync_control='location /__scdn_sync/v1/ { scdn_sync_api control; }'
        if self.purge:
            purge = f'''scdn_purge_zone epochs 8m;
 scdn_purge_journal {self.root}/epochs.log;
 scdn_purge_token_file {self.root}/purge.token;'''
            purge_control = 'location = /purge { scdn_purge_api; }'
        settings = '''scdn_api on;
  scdn_api_inspect_body 16k;
  scdn_api_stream_timeout 8s;
  scdn_api_dynamic_location @api;
  scdn_api_ai_location @ai;
  scdn_api_stream_location @stream;
  scdn_api_websocket_location @websocket;
  scdn_api_grpc_location @grpc;'''
        profiles = '\n'.join([self.proxy('scdn_edge_proxy', 'web', cache=True),
            self.proxy('api', 'api'), self.proxy('ai', 'ai', stream=True),
            self.proxy('stream', 'stream', stream=True), self.proxy('websocket', 'websocket', stream=True),
            '''location @grpc {
               grpc_pass $scdn_edge_grpc_upstream;
               grpc_next_upstream off;
               grpc_read_timeout 8s;
            }'''])
        if self.templates:
            examples = Path(__file__).resolve().parents[1] / 'examples'
            common = (examples / 'proxy-common.conf').read_text().replace(
                '/etc/ssl/certs/ca-certificates.crt', str(self.root / 'origin.crt'))
            common += '\nproxy_set_header X-Test-Profile $scdn_api_kind;\n'
            (self.root / 'proxy-common.conf').write_text(common)
            profiles = (examples / 'profiles.conf').read_text().replace(
                '/etc/scdn/proxy-common.conf', str(self.root / 'proxy-common.conf')).replace(
                '/etc/ssl/certs/ca-certificates.crt', str(self.root / 'origin.crt'))
            settings = ''
        return f'''{modules}
{user}
worker_processes 1;
thread_pool scdn_config_reader threads=1 max_queue=2;
{'thread_pool scdn_cache_purge threads=2 max_queue=128;' if self.purge else ''}
pid {self.root}/nginx.pid;
error_log {self.root}/error.log info;
events {{ worker_connections 256; }}
http {{
 access_log off;
 client_body_buffer_size 32k;
 scdn_config_zone configurations 128k;
 scdn_config_watch {self.source};
 scdn_config_interval 100ms;
 scdn_config_settle 200ms;
 scdn_edge_zone counters 2m;
 scdn_api_zone api_counters 64k;
 {purge}
 {sync}
 proxy_cache_path {self.root}/cache keys_zone=l1:1m;
 upstream pooled-origin {{ server 127.0.0.1:{self.origins[0].server_port}; keepalive 16; }}
 upstream tls-origin {{ server 127.0.0.1:{self.origins[1].server_port}; keepalive 16; }}
 upstream grpc-origin {{ server 127.0.0.1:{self.grpc.server_address[1]}; }}
 server {{ listen unix:{self.socket};
  location = /status {{ scdn_config_status; }}
  location = /metrics {{ scdn_api_metrics; }}
  {purge_control}
  {sync_control}
 }}
 server {{
  listen 127.0.0.1:{self.http};
  listen 127.0.0.1:{self.tls} ssl;
  http2 on;
  ssl_certificate {self.root}/origin.crt;
  ssl_certificate_key {self.root}/origin.key;
  server_name _;
  scdn_edge on;
  {settings}
  gzip on;
  gzip_min_length 1;
  gzip_types application/json text/event-stream;
  add_header X-Kind $scdn_api_kind always;
  add_header X-Reason $scdn_api_reason always;
  add_header X-Stream $scdn_api_stream always;
  add_header X-Skip $scdn_api_skip_cache always;
  location / {{ root {self.root}; }}
  {profiles}
 }}
}}'''

    def control(self, path='/status'):
        connection = http.client.HTTPConnection('localhost', timeout=3)
        connection.sock = socket.socket(socket.AF_UNIX)
        connection.sock.settimeout(3)
        connection.sock.connect(str(self.socket))
        connection.request('GET', path)
        response = connection.getresponse()
        data = response.read()
        connection.close()
        assert response.status == 200
        return json.loads(data) if path == '/status' else data.decode()

    def sync_control(self,path,credential):
        connection=http.client.HTTPConnection('localhost',timeout=3)
        connection.sock=socket.socket(socket.AF_UNIX);connection.sock.settimeout(3)
        connection.sock.connect(str(self.socket))
        try:
            headers={'Authorization':'Bearer '+credential} if credential is not None else {}
            connection.request('GET',path,headers=headers)
            response=connection.getresponse()
            return response.status,json.loads(response.read())
        finally:connection.close()

    def start(self):
        (self.root / 'logs').mkdir()
        (self.root / 'nginx.conf').write_text(self.config())
        result = subprocess.run([str(self.nginx), '-t', '-p', str(self.root), '-c', str(self.root / 'nginx.conf')],
            capture_output=True, text=True)
        if result.returncode:
            raise AssertionError(result.stderr)
        self.log = (self.root / 'process.log').open('wb')
        self.process = subprocess.Popen([str(self.nginx), '-p', str(self.root),
            '-c', str(self.root / 'nginx.conf'), '-g', 'daemon off;'], stdout=self.log, stderr=self.log)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise AssertionError((self.root / 'process.log').read_text())
            try:
                if self.control()['ready']:
                    return
            except (OSError, ValueError, AssertionError):
                pass
            time.sleep(.1)
        raise AssertionError('native configuration was not ready')

    def request(self, path='/opaque', method='GET', body=None, headers=None, host='www.example.test', chunked=False):
        connection = http.client.HTTPConnection('127.0.0.1', self.http, timeout=10)
        connection.request(method, path, body=body, headers={'Host': host, **(headers or {})}, encode_chunked=chunked)
        response = connection.getresponse()
        data = response.read()
        result = response.status, {key.lower(): value for key, value in response.getheaders()}, data
        connection.close()
        return result

    def check(self, name, value=True):
        if not value:
            raise AssertionError(name)
        self.checks.append(name)
        print('PASS ' + name, flush=True)

    def h2_requests(self, requests):
        context = ssl.create_default_context(cafile=str(self.root / 'origin.crt'))
        context.set_alpn_protocols(['h2'])
        sock = context.wrap_socket(socket.create_connection(('127.0.0.1', self.tls), timeout=5),
            server_hostname='model.example.test')
        assert sock.selected_alpn_protocol() == 'h2'
        client = H2Connection(config=H2Configuration(client_side=True, header_encoding='utf-8'))
        client.initiate_connection()
        results = {}
        for index, (authority, path, content_type, payload) in enumerate(requests):
            stream = index * 2 + 1
            client.send_headers(stream, [(':method', 'POST'), (':scheme', 'https'),
                (':authority', authority), (':path', path), ('content-type', content_type),
                ('te', 'trailers'), ('content-length', str(len(payload)))])
            client.send_data(stream, payload, end_stream=True)
            results[stream] = {'body': bytearray(), 'headers': {}, 'trailers': {}, 'done': False}
        sock.sendall(client.data_to_send())
        while not all(result['done'] for result in results.values()):
            incoming = sock.recv(65536)
            if not incoming:
                raise AssertionError('HTTP/2 ended before all streams completed')
            for event in client.receive_data(incoming):
                if isinstance(event, ResponseReceived):
                    results[event.stream_id]['headers'] = dict(event.headers)
                elif isinstance(event, TrailersReceived):
                    results[event.stream_id]['trailers'] = dict(event.headers)
                elif isinstance(event, DataReceived):
                    results[event.stream_id]['body'].extend(event.data)
                    client.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                elif isinstance(event, StreamEnded):
                    results[event.stream_id]['done'] = True
            outgoing = client.data_to_send()
            if outgoing:
                sock.sendall(outgoing)
        sock.close()
        return list(results.values())

    def run(self):
        self.start()
        if self.sync:
            code,status=self.sync_control('/__scdn_sync/v1/status',self.sync_token)
            self.check('Sync role and identity coexist with active Config/API/Edge/Purge',
                code==200 and status['role']=='node' and status['instance_id']=='integration-node')
            self.check('Sync status does not claim the watched business configuration was synchronized',
                status['sync_state']=='not_started' and status['applied_revision'] is None and status['business_health']=='unknown')
            code,capabilities=self.sync_control('/__scdn_sync/v1/capabilities',self.sync_token)
            self.check('Sync capabilities remain accurate in the five-module runtime',code==200
                and not capabilities['features']['encrypted_distribution'] and not capabilities['features']['node_pull'])
            self.check('Sync control requires its own token in the shared control server',
                self.sync_control('/__scdn_sync/v1/status',None)[0]==401
                and self.sync_control('/__scdn_sync/v1/status',self.purge_token)[0]==401)
            self.check('Config status remains available beside authenticated Sync control',self.control()['ready'])
        status, headers, data = self.request('/asset?a=1')
        self.check('ordinary content stays in the web profile', status == 200 and headers['x-kind'] == 'web'
            and json.loads(data)['profile'] == 'web')
        _, _, identity = self.request('/api/client-ip', headers={'X-Clinet-IP': '192.0.2.20'})
        self.check('X-Clinet-IP is overwritten from the trusted connection',
                   json.loads(identity)['client_ip'] == '127.0.0.1')
        _, hit, _ = self.request('/asset?a=1')
        self.check('ordinary public GET retains native nginx caching', hit.get('x-cache') == 'HIT')
        if self.purge:
            connection = http.client.HTTPConnection('localhost', timeout=5)
            connection.sock = socket.socket(socket.AF_UNIX)
            connection.sock.settimeout(5)
            connection.sock.connect(str(self.socket))
            connection.request('POST', '/purge', b'/asset?a=1\n',
                {'Authorization': 'Bearer ' + self.purge_token, 'Content-Type': 'text/plain',
                 'X-Purge-Mode': 'exact', 'X-Purge-Scope': 'plain'})
            response = connection.getresponse()
            result = json.loads(response.read())
            connection.close()
            _, purged, _ = self.request('/asset?a=1')
            self.check('Purge and origin revalidation coexist with the API cache namespace',
                response.status == 200 and result['durable'] and purged.get('x-cache') != 'HIT')
        for name, value in [('Authorization', 'Bearer fixture'), ('Cookie', 'session=fixture'),
                            ('X-API-Key', 'fixture'), ('Cache-Control', 'no-cache')]:
            _, private, _ = self.request('/asset?a=1', headers={name: value})
            self.check(name + ' bypasses an already cached public object', private.get('x-cache') != 'HIT'
                and private['x-skip'] == '1')
        _, headers, data = self.request('/api/users')
        self.check('dynamic API path selects the API profile', headers['x-kind'] == 'api'
            and json.loads(data)['profile'] == 'api')
        _, headers, data = self.request('/lookup', headers={'Accept': 'application/json'})
        self.check('JSON Accept identifies an opaque API before proxying', headers['x-kind'] == 'api'
            and json.loads(data)['profile'] == 'api')
        _, headers, _ = self.request('/opaque')
        _, again, _ = self.request('/opaque')
        self.check('response JSON prevents storing an otherwise unidentified GET', headers['x-reason'] == 'response_json'
            and again.get('x-cache') != 'HIT')

        cases = [
            ('chat messages', {'model': 'fixture', 'messages': [{'role': 'user', 'content': 'hello'}], 'stream': True}),
            ('Responses input', {'model': 'fixture', 'input': 'hello'}),
            ('completion prompt', {'model': 'fixture', 'prompt': 'hello'}),
        ]
        for name, payload in cases:
            body = json.dumps(payload).encode()
            status, headers, data = self.request('/opaque-post', 'POST', body, {'Content-Type': 'application/json'})
            origin = json.loads(data)
            self.check(name + ' is recognized before proxy routing without changing the body', status == 200
                and headers['x-kind'] == 'ai' and headers['x-reason'] == 'json_schema'
                and origin['profile'] == 'ai' and origin['body_sha256'] == hashlib.sha256(body).hexdigest())
        escaped = b'{"mo\\u0064el":"fixture","mess\\u0061ges":[],"stream":true}'
        _, headers, _ = self.request('/opaque-post', 'POST', escaped, {'Content-Type': 'application/json'})
        self.check('escaped JSON property names are decoded structurally', headers['x-kind'] == 'ai')
        for name, payload in [
            ('nested fields', b'{"metadata":{"model":"fixture","messages":[]}}'),
            ('keys inside text', b'{"note":"\\\"model\\\":\\\"fixture\\\",\\\"messages\\\":[]"}'),
            ('model alone', b'{"model":"fixture"}'),
            ('malformed JSON', b'{"model":"fixture","messages":[],}'),
            ('trailing garbage', b'{"model":"fixture","messages":[]}oops'),
            ('invalid UTF-8', b'{"model":"\xff","messages":[]}'),
        ]:
            _, headers, data = self.request('/opaque-post', 'POST', payload, {'Content-Type': 'application/json'})
            self.check(name + ' does not become an AI request', headers['x-kind'] == 'api'
                and json.loads(data)['body_sha256'] == hashlib.sha256(payload).hexdigest())
        big = json.dumps({'model': 'fixture', 'input': 'x' * 20000}).encode()
        _, headers, data = self.request('/opaque-post', 'POST', big, {'Content-Type': 'application/json'})
        self.check('large body inspection is skipped and bytes remain intact', headers['x-kind'] == 'api'
            and json.loads(data)['body_sha256'] == hashlib.sha256(big).hexdigest())
        parts = [b'{"model":"fixture",', b'"input":"hello"}']
        _, headers, data = self.request('/opaque-post', 'POST', iter(parts), {'Content-Type': 'application/json'}, chunked=True)
        self.check('chunked uploads remain intact without unbounded sniffing', headers['x-kind'] == 'api'
            and json.loads(data)['body_sha256'] == hashlib.sha256(b''.join(parts)).hexdigest())

        payload = b'{"model":"fixture","input":"fragmented"}'
        raw = socket.create_connection(('127.0.0.1', self.http), timeout=5)
        raw.sendall((f'POST /opaque-post HTTP/1.1\r\nHost: www.example.test\r\nContent-Type: application/json\r\n'
            f'Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n').encode() + payload[:8])
        time.sleep(.05)
        raw.sendall(payload[8:])
        wire = b''
        while True:
            data = raw.recv(65536)
            if not data:
                break
            wire += data
        raw.close()
        self.check('asynchronous fragmented JSON resumes phases and preserves the body',
            b'X-Kind: ai' in wire and hashlib.sha256(payload).hexdigest().encode() in wire)

        for path, accept, expected in [('/events', True, 'stream'), ('/opaque-events', False, 'stream'),
                                       ('/v1/chat/completions', True, 'ai')]:
            connection = http.client.HTTPConnection('127.0.0.1', self.http, timeout=5)
            request_headers = {'Host': 'www.example.test', 'Accept-Encoding': 'gzip'}
            if accept:
                request_headers['Accept'] = 'text/event-stream'
            started = time.monotonic()
            connection.request('GET', path, headers=request_headers)
            response = connection.getresponse()
            first = response.readline()
            first_elapsed = time.monotonic() - started
            remainder = response.read()
            elapsed = time.monotonic() - started
            response_headers = dict((k.lower(), v) for k, v in response.getheaders())
            connection.close()
            self.check(path + ' flushes first SSE data before generation completes',
                first.startswith(b'data:') and b'[DONE]' in remainder and first_elapsed < .55 and elapsed > 1)
            self.check(path + ' streaming classification disables compression and caching',
                response_headers['x-kind'] == expected and response_headers['x-stream'] == '1'
                and 'content-encoding' not in response_headers and response_headers['x-skip'] == '1')

        _, _, first = self.request('/api/pooled-one')
        _, _, second = self.request('/api/pooled-two')
        self.check('named origin pools reuse real upstream TCP connections',
            json.loads(first)['source_port'] == json.loads(second)['source_port'])
        for host in ('tls.example.test', 'direct.example.test', 'prefix.example.test'):
            status, _, data = self.request('/secure/check', host=host)
            self.check(host + ' verifies HTTPS and sends the configured origin Host', status == 200
                and json.loads(data)['host'] == 'model.example.test')
        self.check('HTTPS origin receives matching SNI', 'model.example.test' in self.origins[1].sni)
        status, _, _ = self.request('/secure/check', host='badtls.example.test')
        self.check('wrong origin certificate hostname fails closed', status == 502)

        h2_result = self.h2_requests([
            ('www.example.test', '/opaque-post', 'application/json', b'{"model":"fixture","input":"h2"}'),
            ('www.example.test', '/opaque-post', 'application/json', b'{"ordinary":true}'),
        ])
        self.check('HTTP/2 multiplexing keeps automatic AI and API policies isolated',
            [result['headers'].get('x-kind') for result in h2_result] == ['ai', 'api']
            and [json.loads(result['body'])['profile'] for result in h2_result] == ['ai', 'api'])
        message = b'\x00\x00\x00\x00\x05hello'
        grpc = self.h2_requests([('grpc.example.test', '/fixture.Echo/Call', 'application/grpc', message)])[0]
        self.check('gRPC is detected and preserves binary DATA and status trailers over HTTP/2',
            grpc['headers'].get('x-kind') == 'grpc' and bytes(grpc['body']) == message
            and grpc['trailers'].get('grpc-status') == '0')

        def concurrent(index):
            ai = index % 2 == 0
            payload = json.dumps({'model': 'fixture', 'input': str(index)} if ai else {'ordinary': index}).encode()
            status, headers, data = self.request('/opaque-post', 'POST', payload, {'Content-Type': 'application/json'})
            return status == 200 and headers['x-kind'] == ('ai' if ai else 'api') \
                and json.loads(data)['profile'] == ('ai' if ai else 'api')

        with ThreadPoolExecutor(max_workers=8) as pool:
            self.check('concurrent API and AI requests do not share mutable policy state', all(pool.map(concurrent, range(32))))

        sock = socket.create_connection(('127.0.0.1', self.http), timeout=4)
        nonce = base64.b64encode(b'0123456789abcdef').decode()
        sock.sendall((f'GET /ws HTTP/1.1\r\nHost: www.example.test\r\nUpgrade: websocket\r\n'
            f'Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {nonce}\r\n\r\n').encode())
        raw = b''
        while b'\r\n\r\n' not in raw:
            raw += sock.recv(4096)
        payload, mask = b'hello', b'1234'
        masked = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
        sock.sendall(bytes([0x81, 0x80 | len(payload)]) + mask + masked)
        echo = sock.recv(4096)
        sock.close()
        self.check('WebSocket automatic dispatch preserves handshake and bidirectional data',
            b'101 Switching Protocols' in raw and b'X-Kind: websocket' in raw and echo == b'\x81\x05hello')

        connection = http.client.HTTPConnection('127.0.0.1', self.http, timeout=4)
        connection.request('GET', '/events-cancel', headers={'Host': 'www.example.test', 'Accept': 'text/event-stream'})
        response = connection.getresponse()
        response.read(128)
        response.close(); connection.close()
        self.check('disconnecting a stream closes upstream work promptly', self.origins[0].cancelled.wait(3))

        before = self.control()
        staged = self.root / 'sites.next'
        staged.write_text(self.sites('wrong.example.test'))
        staged.replace(self.source)
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if self.control()['revision'] != before['revision']:
                break
            time.sleep(.1)
        else:
            raise AssertionError('origin Host update did not become active')
        status, _, _ = self.request('/secure/check', host='tls.example.test')
        self.check('origin Host and SNI follow an immutable hot configuration update', status == 502)
        metrics = self.control('/metrics')
        self.check('native metrics expose bounded API categories without prompt contents',
            'scdn_api_requests_total{kind="ai"}' in metrics and 'scdn_api_stream_requests_total ' in metrics
            and 'fixture' not in metrics)
        status, _, _ = self.request('/asset', host='unknown.example.test')
        self.check('unknown sites retain the native Edge rejection policy', status == 403)
        status, _, _ = self.request('/asset')
        self.check('worker remains healthy after streaming, cancellation, TLS errors and hot updates', status == 200)

    def close(self):
        if self.process is not None and self.process.poll() is None:
            self.process.send_signal(signal.SIGQUIT)
            try:
                self.process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self.process.kill(); self.process.wait(timeout=3)
        if hasattr(self, 'log'):
            self.log.close()
        for server in self.origins:
            server.shutdown(); server.server_close()
        self.grpc.shutdown(); self.grpc.server_close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--prefix', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--static', action='store_true')
    parser.add_argument('--templates', action='store_true')
    parser.add_argument('--purge', action='store_true')
    parser.add_argument('--sync', action='store_true')
    args = parser.parse_args()
    if args.templates and args.purge:
        parser.error('--templates and --purge exercise separate configuration modes')
    if args.sync and not args.purge:
        parser.error('--sync exercises the full runtime and requires --purge')
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='scdn-api-integration-') as directory:
        review = Review(Path(directory), args.prefix, args.static, args.templates, args.purge, args.sync)
        try:
            review.run()
            result = {'passed': True, 'checks': review.checks, 'check_count': len(review.checks),
                'elapsed_seconds': round(time.monotonic() - started, 3),
                'runtime': subprocess.run([str(review.nginx), '-v'], capture_output=True, text=True).stderr.strip(),
                'production_modified': False, 'real_vendor_api_calls': 0}
            result['published_templates'] = args.templates
            result['linkage'] = 'static' if args.static else 'dynamic'
            result['purge_integration'] = args.purge
            result['sync_integration'] = args.sync
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(result, indent=2) + '\n')
            print(json.dumps(result))
        except Exception:
            for name in ('error.log', 'process.log'):
                path = Path(directory) / name
                if path.exists():
                    print(name + ':\n' + path.read_text(errors='replace')[-16000:].replace(review.purge_token,'[redacted]').replace(review.sync_token,'[redacted]'), flush=True)
            raise
        finally:
            review.close()


if __name__ == '__main__':
    main()
