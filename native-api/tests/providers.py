#!/usr/bin/env python3
"""Exercise concrete provider URLs and all pinned Sub2API gateway routes.

The corpus comes from the upstream platform registry, URL builders, gateway
router and public provider documentation, independently of the C route table.
"""
import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
from urllib.parse import urlsplit

import integration as fixture


ROOT = Path(__file__).resolve().parents[2]
RAW = json.dumps({'future_event': {'signature': 'opaque+/=', 'arguments': '{"x":'},
    'parts': [{'functionCall': {'id': 'opaque', 'name': 'lookup', 'args': {'x': 1}}}]},
    separators=(',', ':')).encode()
SSE = b': keepalive\r\nevent: unknown.future\r\ndata: ' + RAW + b'\r\n\r\ndata: [DONE]\n\n'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--prefix', type=Path, required=True)
    parser.add_argument('--static', action='store_true')
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    catalog = json.loads((ROOT / 'docs/api-provider-catalog-20261118.json').read_text())
    routes = json.loads((ROOT / 'docs/api-gateway-routes-20261118.json').read_text())
    original = fixture.Origin
    arrived = threading.Event()

    class Origin(original):
        def respond(self):
            if self.headers.get('Upgrade', '').lower() == 'websocket':
                nonce = self.headers['Sec-WebSocket-Key']
                accept = base64.b64encode(hashlib.sha1((nonce +
                    '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
                self.send_response(101)
                self.send_header('Upgrade', 'websocket')
                self.send_header('Connection', 'Upgrade')
                self.send_header('Sec-WebSocket-Accept', accept)
                self.end_headers()
                self.close_connection = True
                return
            if self.headers.get('Transfer-Encoding', '').lower() == 'chunked':
                chunks = []
                while True:
                    size = int(self.rfile.readline().split(b';', 1)[0], 16)
                    if not size:
                        while self.rfile.readline() not in (b'\r\n', b'\n', b''):
                            pass
                        break
                    chunks.append(self.rfile.read(size))
                    assert self.rfile.read(2) == b'\r\n'
                    arrived.set()
                body = b''.join(chunks)
            else:
                size = int(self.headers.get('Content-Length', '0'))
                body = self.rfile.read(min(size, 65536))
                arrived.set()
                body += self.rfile.read(size - len(body))
            streaming = self.headers.get('X-Provider-SSE') == '1'
            wire = SSE if streaming else RAW
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream' if streaming else 'application/json')
            self.send_header('Content-Length', str(len(wire)))
            self.send_header('Cache-Control', 'public, max-age=3600')
            self.send_header('X-Origin-Method', self.command)
            self.send_header('X-Origin-Path', self.path)
            self.send_header('X-Origin-Profile', self.headers.get('X-Test-Profile', ''))
            self.send_header('X-Origin-Hash', hashlib.sha256(body).hexdigest())
            self.end_headers()
            if self.command != 'HEAD':
                step = 7 if streaming else len(wire)
                for offset in range(0, len(wire), step):
                    self.wfile.write(wire[offset:offset + step])
                    self.wfile.flush()

        do_GET = do_POST = do_PATCH = do_DELETE = do_HEAD = do_PUT = do_OPTIONS = respond

    fixture.Origin = Origin

    class Review(fixture.Review):
        def config(self):
            return super().config().replace('scdn_api_inspect_body 16k;', 'scdn_api_inspect_body 0;').replace(
                'add_header X-Kind', 'add_header X-Protocol $scdn_api_protocol always;\n  add_header X-Kind').replace(
                'scdn_api_zone api_counters 64k;', '''scdn_api_zone api_counters 64k;
 scdn_api_endpoint systemone POST /vendor/decision plain;
 scdn_api_endpoint videos POST /vendor/render plain;
 scdn_api_endpoint realtime POST /vendor/live plain;
 scdn_api_endpoint messages POST /api/paas/v4/chat/completions tls;''')

    checks = []

    def check(name, condition):
        assert condition, name
        checks.append(name)

    with tempfile.TemporaryDirectory(prefix='scdn-api-providers-') as directory:
        review = Review(Path(directory), args.prefix, args.static)
        try:
            review.start()

            def probe(name, path, method='POST', protocol='generic', kind='ai', body=None,
                      chunked=False, streaming=False, reason=None, headers=None, host='www.example.test'):
                headers = {'Content-Type': 'application/octet-stream',
                    'Accept-Encoding': 'gzip' if kind == 'ai' else 'identity',
                    **(headers or {})}
                if streaming:
                    headers['X-Provider-SSE'] = '1'
                sent = body if body is not None else (b'opaque request\x00' * 6000 if method == 'POST' else None)
                request_body = iter((sent[:1000], sent[1000:])) if chunked else sent
                status, received, data = review.request(path, method, request_body, headers,
                    host=host, chunked=chunked)
                expected_reason = reason or ('ai_endpoint' if kind == 'ai' else 'api_endpoint')
                check(name + ' classification before body inspection', status == 200
                    and received.get('x-kind') == kind and received.get('x-protocol') == protocol
                    and received.get('x-reason') == expected_reason
                    and received.get('x-origin-profile') == kind)
                check(name + ' exact raw request and output', received.get('x-origin-path') == path
                    and received.get('x-origin-method') == method
                    and received.get('x-origin-hash') == hashlib.sha256(sent or b'').hexdigest()
                    and data == (b'' if method == 'HEAD' else SSE if streaming else RAW))
                check(name + ' bypasses shared cache and compression', received.get('x-skip') == '1'
                    and not received.get('content-encoding'))
                return received

            provider_count = 0
            for provider in catalog['platforms']:
                for index, request in enumerate(provider['requests']):
                    parsed = urlsplit(request['url'])
                    path = parsed.path + ('?' + parsed.query if parsed.query else '')
                    probe(provider['id'] + '/' + request['mode'] + '/' + request['protocol'],
                        path, request['method'], request['protocol'], chunked=index % 2 == 1,
                        streaming=index % 2 == 0)
                    provider_count += 1
            for request in catalog['official_variants']:
                parsed = urlsplit(request['url'])
                probe('official ' + request['provider'] + parsed.path, parsed.path,
                    request['method'], request['protocol'], chunked=True)
            for route in routes['routes']:
                # Explicit site overrides must win over a built-in route; this
                # router corpus does not contain that GLM upstream-only path.
                probe('Sub2API ' + route['method'] + ' ' + route['route'], route['path'],
                    route['method'], route['protocol'], route['kind'])
            for path, kind, protocol, method in [
                ('/v1internal:countTokens', 'ai', 'gemini', 'POST'),
                ('/v1internal:fetchAvailableModels', 'api', 'gemini', 'POST'),
                ('/v1internal:loadCodeAssist', 'api', 'gemini', 'POST'),
                ('/v1internal:onboardUser', 'api', 'gemini', 'POST'),
                ('/antigravity/v1beta/models/m:countTokens', 'ai', 'gemini', 'POST'),
                ('/responses/compact?mode=opaque', 'ai', 'responses', 'POST'),
                ('/responses/opaque/action', 'ai', 'responses', 'POST'),
                ('/responses/', 'ai', 'responses', 'POST'),
                ('/mount/v1/responses/opaque/action', 'ai', 'responses', 'POST'),
                ('/backend-api/codex/responses/opaque/action', 'ai', 'responses', 'POST'),
                ('/responses/' + '/'.join(['a'] * 8), 'ai', 'responses', 'POST'),
                ('/responses/' + 'a' * 128, 'ai', 'responses', 'POST'),
                ('/prefix/v1/responses/response_1/input_items', 'ai', 'responses', 'GET'),
                ('/v1/responses/response_1/cancel', 'ai', 'responses', 'POST'),
                ('/v1/responses/response_1', 'ai', 'responses', 'DELETE'),
                ('/v1/models', 'api', 'generic', 'HEAD'),
                ('/api/paas/v4/chat/completions', 'ai', 'messages', 'POST'),
                ('/vendor/decision', 'ai', 'systemone', 'POST'),
                ('/vendor/render', 'ai', 'videos', 'POST'),
                ('/vendor/live', 'ai', 'realtime', 'POST')]:
                configured = path.startswith('/vendor/') or path == '/api/paas/v4/chat/completions'
                probe('auxiliary or control ' + path, path, method, protocol, kind,
                    reason='configured_endpoint' if configured else None,
                    host='tls.example.test' if path == '/api/paas/v4/chat/completions' else 'www.example.test')

            # Prove the GLM built-in rule independently of its site override.
            probe('GLM other site built-in', '/api/paas/v4/chat/completions', protocol='chat',
                  host='www.example.test')

            for path, method in [
                ('/v1/images/edits-extra', 'POST'), ('/responses-extra', 'POST'),
                ('/responses/compact/extra', 'GET'), ('/unrelated/responses', 'POST'),
                ('/unrelated/responses/compact', 'POST'),
                ('/responses/' + '/'.join(['a'] * 9), 'POST'),
                ('/responses/' + 'a' * 129, 'POST'), ('/responses/opaque:action', 'POST'),
                ('/api/paas/v4/chat/completions', 'GET'), ('/api/paas/v4/chat/completions-extra', 'POST'),
                ('/v1/images/tasks/id/extra', 'GET'), ('/v1/videos/id/content/extra', 'GET'),
                ('/v1/images/tasks/', 'GET'), ('/v1/custom-voices/id/unknown', 'GET'),
                ('/v1internal:GenerateContent', 'POST'), ('/v1internal:generateContent/', 'POST'),
                ('/v1beta/models/id:unknownAction', 'POST'), ('/v1beta/cachedContentsExtra', 'POST'),
                ('/v1/systemone', 'GET'), ('/v1/responses/id/cancel', 'GET'),
                ('/v1/chat/completions', 'OPTIONS'), ('/api/paas/v4/chat/completions', 'PUT'),
                ('/api/ordinary?target=/v1/responses', 'POST')]:
                status, received, _ = review.request(path, method, b'opaque',
                    {'Content-Type': 'application/octet-stream'})
                check('no broad AI or protocol match ' + method + ' ' + path, status == 200
                    and received.get('x-kind') != 'ai' and received.get('x-protocol') == 'none')

            # Check real partial uploads, without first finishing the client
            # request. This catches accidental fallback to buffered API proxying.
            for path in ['/api/coding/paas/v4/chat/completions', '/responses/compact',
                         '/v1/systemone', '/v1internal:streamGenerateContent?alt=sse']:
                for chunked in (False, True):
                    arrived.clear()
                    body = b'preserve\x00raw\r\n' * 20000
                    connection = http.client.HTTPConnection('127.0.0.1', review.http, timeout=5)
                    connection.putrequest('POST', path, skip_host=True)
                    for key, value in {'Host': 'www.example.test', 'Content-Type': 'application/octet-stream',
                        **({'Transfer-Encoding': 'chunked'} if chunked else {'Content-Length': str(len(body))})}.items():
                        connection.putheader(key, value)
                    connection.endheaders()
                    def send(data):
                        connection.send((f'{len(data):x}\r\n'.encode() + data + b'\r\n') if chunked else data)
                    send(body[:131072])
                    early = arrived.wait(1)
                    send(body[131072:])
                    if chunked:
                        connection.send(b'0\r\n\r\n')
                    response = connection.getresponse()
                    data = response.read()
                    digest = response.getheader('X-Origin-Hash')
                    connection.close()
                    check('early upstream upload ' + path + ' chunked=' + str(chunked), early
                        and data == RAW and digest == hashlib.sha256(body).hexdigest())

            for path, protocol in [('/v1/realtime', 'realtime'), ('/responses', 'responses')]:
                sock = socket.create_connection(('127.0.0.1', review.http), timeout=5)
                try:
                    nonce = base64.b64encode(os.urandom(16)).decode()
                    sock.sendall((f'GET {path} HTTP/1.1\r\nHost: www.example.test\r\n'
                        'Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n'
                        f'Sec-WebSocket-Key: {nonce}\r\n\r\n').encode())
                    response = b''
                    while b'\r\n\r\n' not in response:
                        part = sock.recv(4096)
                        if not part:
                            break
                        response += part
                    check('WebSocket profile takes precedence for ' + path,
                        response.startswith(b'HTTP/1.1 101') and b'X-Kind: websocket\r\n' in response
                        and ('X-Protocol: ' + protocol + '\r\n').encode() in response)
                finally:
                    sock.close()
        finally:
            review.close()
            fixture.Origin = original

    report = {'passed': True, 'check_count': len(checks), 'checks': checks,
        'provider_count': len(catalog['platforms']), 'provider_requests': provider_count,
        'official_variants': len(catalog['official_variants']), 'gateway_routes': len(routes['routes']),
        'body_inspection': False, 'real_vendor_api_calls': 0, 'production_modified': False,
        'classifier_source_sha256': hashlib.sha256((ROOT / 'native-api/src/ngx_http_scdn_api_module.c').read_bytes()).hexdigest()}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: value for key, value in report.items() if key != 'checks'}))


if __name__ == '__main__':
    main()
