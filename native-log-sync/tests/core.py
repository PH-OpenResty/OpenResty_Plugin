#!/usr/bin/env python3
"""Crash/retry, full/tail, JSON, rotation and direct backend protocol checks."""
import argparse
import base64
import gzip
import hashlib
import http.server
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
import datetime as dt
import ipaddress
import ssl
import secrets

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from urllib.parse import parse_qs, urlsplit


class Backend(http.server.ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self):
        super().__init__(('127.0.0.1', 0), Handler)
        self.es, self.ch, self.ids, self.calls = [], [], {}, []
        self.fail_es = self.fail_ch = self.drop_es = self.slow = False
        self.lock = threading.Lock()


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers['Content-Length']))
        if self.server.slow:
            time.sleep(.8)
        rows = [json.loads(line) for line in body.splitlines()]
        with self.server.lock:
            self.server.calls.append((self.path, dict(self.headers), body))
        es = self.path.endswith('/_bulk')
        if es:
            assert self.headers['Content-Type'] == 'application/x-ndjson' and body.endswith(b'\n')
            assert len(rows) % 2 == 0
            items = []
            for metadata, event in zip(rows[::2], rows[1::2]):
                event_id = metadata['index']['_id']
                assert event_id == event['event_id'] and len(event_id) == 64
                with self.server.lock:
                    self.server.es.append(event)
                    self.server.ids[event_id] = event
                items.append({'index': {'_id': event_id, 'status': 429 if self.server.fail_es else 201}})
            if self.server.drop_es:
                self.close_connection = True
                return
            response = json.dumps({'errors': self.server.fail_es, 'items': items}).encode()
        else:
            query = parse_qs(urlsplit(self.path).query)
            assert query['query'] == ['INSERT INTO default.scdn_logs FORMAT JSONEachRow']
            assert query['wait_end_of_query'] == ['1'] and query['async_insert'] == ['0']
            assert len(query['insert_deduplication_token'][0]) == 64
            if self.server.fail_ch:
                response = b'Code: 999. DB::Exception: simulated insert failure'
            else:
                with self.server.lock:
                    self.server.ch.extend(rows)
                response = b''
        self.send_response(200)
        self.send_header('Content-Length', str(len(response)))
        self.end_headers()
        try:
            self.wfile.write(response)
        except (BrokenPipeError, ConnectionResetError):
            pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    binary = args.build / 'scdn-log-sync'
    backend = Backend()
    threading.Thread(target=backend.serve_forever, daemon=True).start()
    checks = []
    def check(name, value):
        assert value, name
        checks.append(name)
    def clear():
        backend.es.clear(); backend.ch.clear(); backend.ids.clear(); backend.calls.clear()
        backend.fail_es = backend.fail_ch = backend.drop_es = backend.slow = False
    with tempfile.TemporaryDirectory(prefix='scdn-log-core-') as directory:
        root = Path(directory)
        def fixture(name, start='full', paths=None, sinks=None, kind='log', extra=None):
            folder = root / name
            folder.mkdir()
            state = folder / 'state'; state.mkdir(mode=0o700)
            config = {'node': 'test_node', 'state_dir': str(state), 'line_bytes': 4096,
                'batch_records': 128, 'batch_bytes': 65536, 'retry_ms': 50,
                'sources': [{'id': 'input', 'paths': paths or [str(folder / '*.jsonl')],
                             'start': start, 'format': 'auto', 'kind': kind}],
                'sinks': sinks or [{'id': 'es', 'type': 'elasticsearch', 'allow_http': True,
                    'endpoint': f'http://127.0.0.1:{backend.server_port}', 'index': 'scdn-logs'},
                    {'id': 'ch', 'type': 'clickhouse', 'allow_http': True,
                     'endpoint': f'http://127.0.0.1:{backend.server_port}'}]}
            if extra: config.update(extra)
            path = folder / 'config.json'
            path.write_text(json.dumps(config))
            return folder, state, path, config
        def once(path, success=True):
            result = subprocess.run([str(binary), '--once', str(path)], capture_output=True, text=True, timeout=15)
            if success: assert result.returncode == 0, result.stdout + result.stderr + repr({'es_received':len(backend.es),'ch_received':len(backend.ch),'requests':len(backend.calls)})
            return result
        def events():
            return [base64.b64decode(e['raw_base64']) for e in backend.ids.values()]

        folder, state, path, conf = fixture('full')
        log = folder / 'access.jsonl'
        raw = b'{"message":"first","nested":{"a":null},"unknown_future":[1,2]}\n' + '{"message":"中文"}\n'.encode()
        log.write_bytes(raw)
        once(path)
        check('full bootstrap sends every original JSON line to both direct sinks', b''.join(events()) == raw and len(backend.ch) == 2)
        check('Elasticsearch has decoded JSON fields and unknown values', backend.es[0]['fields']['nested']['a'] is None)
        before = len(backend.calls); once(path)
        check('idle cycles do not resend acknowledged data', len(backend.calls) == before)
        with log.open('ab') as stream: stream.write(b'{"message":"partial"')
        once(path); check('unterminated live JSON remains at the cursor', len(backend.calls) == before)
        with log.open('ab') as stream: stream.write(b'}\n')
        once(path); check('completed partial line is delivered once', b'{"message":"partial"}\n' in events())

        clear();folder, state, path, conf = fixture('partial_sink')
        (folder / 'input.jsonl').write_bytes(b'{"n":1}\n')
        backend.fail_ch = True; result = once(path, False)
        check('ClickHouse HTTP 200 exception does not confirm or advance', result.returncode != 0 and (state / 'pending.json').exists())
        before = len(backend.es); backend.fail_ch = False; once(path)
        check('persisted per-sink receipt avoids re-sending to acknowledged ES', len(backend.es) == before and len(backend.ch) == 1)
        check('pending WAL clears only after every configured sink confirms', not (state / 'pending.json').exists())

        clear();folder,state,path,conf=fixture('commit_interruption')
        (folder/'input.jsonl').write_text('{"committed":true}\n')
        backend.fail_ch=True;once(path,False);pending=(state/'pending.json').read_bytes()
        backend.fail_ch=False;once(path);before=len(backend.calls)
        (state/'pending.json').write_bytes(pending);(state/'pending.json').chmod(0o600);once(path)
        check('crash residue after cursor commit is cleaned without re-delivery',len(backend.calls)==before and not (state/'pending.json').exists())

        clear();folder,state,path,conf=fixture('scratch_hardlink')
        protected=folder/'protected';protected.write_text('preserve me');protected.chmod(0o600)
        (state/'state.json.new').hardlink_to(protected)
        result=once(path,False)
        check('hardlinked scratch state is rejected before truncation',result.returncode!=0 and protected.read_text()=='preserve me')

        clear();folder, state, path, conf = fixture('bulk_error')
        (folder / 'input.jsonl').write_bytes(b'{"n":1}\n{"n":2}\n')
        backend.fail_es = True; result = once(path, False)
        check('ES per-item 429 in HTTP 200 is a retryable unconfirmed batch', result.returncode != 0 and (state / 'pending.json').exists())
        first_ids = set(backend.ids); before_ch = len(backend.ch)
        backend.fail_es = False; once(path)
        check('ES retry preserves deterministic document IDs', first_ids == set(backend.ids) and len(backend.es) == 4)
        check('successful CH sink is not repeated on ES retry', len(backend.ch) == before_ch)

        clear();folder, state, path, conf = fixture('lost_ack')
        (folder / 'input.jsonl').write_bytes(b'{"n":42}\n')
        backend.drop_es = True; once(path, False); first_ids = set(backend.ids)
        backend.drop_es = False; once(path)
        check('transport acknowledgement loss replays the same ES document', first_ids == set(backend.ids) and len(backend.ids) == 1)

        clear();folder, state, path, conf = fixture('tail', start='tail')
        log = folder / 'active.jsonl'; log.write_bytes(b'{"old":1}\nunfinished')
        once(path); check('incremental bootstrap skips existing bytes', not backend.calls)
        with log.open('ab') as stream: stream.write(b'_old_line\n{"new":2}\n')
        once(path); check('tail bootstrap does not turn an old partial line into a new event', events() == [b'{"new":2}\n'])
        (folder / 'new.jsonl').write_bytes(b'{"new_file":3}\n'); once(path)
        check('incremental mode reads newly created files from byte zero', b'{"new_file":3}\n' in events())

        clear();folder, state, path, conf = fixture('rotate')
        log = folder / 'active.jsonl'; log.write_bytes(b'{"n":1}\n'); once(path)
        old = folder / 'rotated.jsonl'; log.rename(old); log.write_bytes(b'{"n":2}\n')
        with old.open('ab') as stream: stream.write(b'{"n":3}\n')
        once(path); check('rename rotation drains late appends and starts the new inode', sorted(events()) == sorted([b'{"n":1}\n',b'{"n":2}\n',b'{"n":3}\n']))
        log.write_bytes(b'{"n":4}\n'); once(path)
        check('copytruncate creates a new generation when the cursor anchor changes', b'{"n":4}\n' in events())

        clear();folder, state, path, conf = fixture('gzip', paths=[str(root/'gzip'/'*.jsonl*')])
        raw = b''.join(json.dumps({'n': n}).encode()+b'\n' for n in range(200))
        with gzip.open(folder/'archive.jsonl.gz','wb') as stream: stream.write(raw)
        for _ in range(6):once(path)
        check('full compressed history retains all decompressed records', sorted(events()) == sorted(raw.splitlines(keepends=True)))

        clear();folder,state,path,conf=fixture('gzip_tail',start='tail',paths=[str(root/'gzip_tail'/'*.jsonl*')])
        with gzip.open(folder/'old.jsonl.gz','wb') as stream:stream.write(b'{"old":true}\n')
        once(path);check('incremental bootstrap skips sealed historical gzip archives',not backend.calls)
        with gzip.open(folder/'new.jsonl.gz','wb') as stream:stream.write(b'{"new":true}\n')
        once(path);check('incremental discovery reads a new sealed archive from its beginning',events()==[b'{"new":true}\n'])

        clear();folder,state,path,conf=fixture('gzip_adopt',paths=[str(root/'gzip_adopt'/'*.jsonl*')])
        old=folder/'rotated.jsonl';old.write_bytes(b'{"already_read":true}\n');once(path);before=len(backend.calls)
        with gzip.open(folder/'rotated.jsonl.gz','wb') as stream:stream.write(old.read_bytes())
        old.unlink();once(path)
        check('compression of an acknowledged rotated file adopts its matching cursor',len(backend.calls)==before)

        clear();folder,state,path,conf=fixture('sampling_disabled',extra={'telemetry':{'enabled':True}})
        (folder/'input.jsonl').write_text('{}\n');once(path)
        (state/'telemetry-retained.jsonl').write_text('{"time":1,"node":"test_node"}\n')
        conf['telemetry']['enabled']=False;path.write_text(json.dumps(conf));once(path)
        check('sampling configuration changes retain log cursors and drain existing metric segments',any(e['kind']=='metrics' for e in backend.es))

        clear();folder,state,path,conf=fixture('managed_segment_scope')
        (folder/'input.jsonl').write_text('{}\n');once(path)
        protected=folder/'protected.log';protected.write_text('user log must remain\n')
        envelope=json.loads((state/'state.json').read_text());payload=json.loads(envelope['payload'])
        payload['files']['synthetic-stale-entry']={'source':'telemetry','path':str(protected),'offset':protected.stat().st_size,'archive':False}
        encoded=json.dumps(payload,separators=(',',':'));envelope={'payload':encoded,'sha256':hashlib.sha256(encoded.encode()).hexdigest()}
        (state/'state.json').write_text(json.dumps(envelope))
        segment=state/('telemetry-'+'a'*32+'.jsonl');segment.write_text('{"time":1,"node":"test_node"}\n')
        once(path)
        check('acknowledged internally generated metric segments are reclaimed',not segment.exists())
        check('metric reclamation never removes a source path outside the managed filename scope',protected.read_text()=='user log must remain\n')

        clear();folder, state, path, conf = fixture('fragments')
        raw = b'{"big":"' + b'x'*10000 + b'"}\n' + b'\xff\x00\n'
        (folder/'input.jsonl').write_bytes(raw)
        for _ in range(3):once(path)
        check('oversized and invalid UTF8 logs retain all source bytes', b''.join(sorted(events(), key=lambda b: raw.find(b))) == raw)
        check('fragments and binary fallback are explicitly labelled', any(e['fragment'] for e in backend.es) and any(e['format']=='binary' for e in backend.es))

        clear();folder, state, path, conf = fixture('access', kind='access')
        document={'time':'2026-11-19T00:00:00Z','request_id':'a'*32,'client_ip':'192.0.2.1','host':'EXAMPLE.TEST',
            'site_id':'site_a','uri':'https://'+'user'+':'+'private'+'@example.test/a?q=private#fragment','method':'GET',
            'status':403,'bytes':32,'rt':.5,'urt':'0.1, 0.2','cache':'MISS','cache_layer':'origin','country':'ZZ','asn':0}
        (folder/'input.jsonl').write_text(json.dumps(document)+'\n');once(path)
        n=backend.es[0]['normalized']
        check('access normalization supplies every existing request dimension', n['uri']=='/a' and n['internal']==1 and n['duration_ms']==500 and abs(n['origin_ms']-300)<.001 and n['blocked']==1)
        (folder/'copy.jsonl').write_text(json.dumps(document)+'\n');once(path)
        check('valid Nginx request IDs deduplicate across copied files', len(backend.ids)==1)
        (folder/'invalid.jsonl').write_text('{"message":"not an HTTP access event"}\n');once(path)
        check('unrecognized access JSON is retained without fabricating a request',any(e['fields'].get('message')=='not an HTTP access event' and 'normalized'not in e for e in backend.es))

        clear();folder, state, path, conf = fixture('credentials')
        authorization='ApiKey '+secrets.token_urlsafe(24)
        secret=folder/'auth'; secret.write_text(authorization+'\n');secret.chmod(0o600)
        conf['sinks'][0]['authorization_file']=str(secret);path.write_text(json.dumps(conf))
        (folder/'input.jsonl').write_bytes(b'{}\n');once(path)
        check('direct ES authentication reads the protected file', backend.calls[0][1]['Authorization']==authorization)
        secret.chmod(0o644);(folder/'new.jsonl').write_bytes(b'{}\n');result=once(path,False)
        check('publicly readable credential file is rejected without printing its content', result.returncode!=0 and authorization not in result.stdout+result.stderr)

        clear();folder, state, path, conf = fixture('corruption')
        (folder/'input.jsonl').write_bytes(b'{}\n');once(path)
        saved=(state/'state.json').read_text();envelope=json.loads(saved);envelope['sha256']='0'*64
        (state/'state.json').write_text(json.dumps(envelope));result=once(path,False)
        check('corrupt durable cursor is rejected rather than reset', result.returncode!=0)

        clear();folder, state, path, conf = fixture('slow')
        (folder/'input.jsonl').write_bytes(b'{}\n');conf['timeout_ms']=150;conf['connect_ms']=100;path.write_text(json.dumps(conf))
        backend.slow=True;before=time.monotonic();result=once(path,False)
        check('backend timeout is bounded and preserves pending data', result.returncode!=0 and time.monotonic()-before<2 and (state/'pending.json').exists())
        backend.slow=False

        for mode in ['--check','--sample']:
            result=subprocess.run([str(binary),mode,str(path)],capture_output=True,text=True,timeout=10)
            check('standalone '+mode+' supports a valid configuration', result.returncode==0)
        legacy=json.loads(json.dumps(conf));legacy['node']='node-1';legacy['sources'][0]['id']='access-log'
        path.write_text(json.dumps(legacy))
        result=subprocess.run([str(binary),'--check',str(path)],capture_output=True,text=True)
        check('existing hyphenated node and source identifiers remain usable',result.returncode==0)
        path.write_text(json.dumps(conf))
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'loopback fixture')])
        now=dt.datetime.now(dt.timezone.utc)
        certificate=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now-dt.timedelta(minutes=1))
            .not_valid_after(now+dt.timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),critical=False)
            .sign(key,hashes.SHA256()))
        cert=root/'fixture.crt';private=root/'fixture.key'
        cert.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        private.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        private.chmod(0o600)
        tls=Backend();context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,private)
        tls.socket=context.wrap_socket(tls.socket,server_side=True)
        threading.Thread(target=tls.serve_forever,daemon=True).start()
        try:
            tls_sink=[{'id':'tls','type':'elasticsearch','endpoint':f'https://127.0.0.1:{tls.server_port}','ca_file':str(cert)}]
            folder,state,tls_path,_=fixture('tls',sinks=tls_sink);(folder/'input.jsonl').write_text('{"tls":true}\n')
            once(tls_path);check('direct Elasticsearch TLS validates a trusted CA and IP identity',len(tls.es)==1)
            tls_sink=[{'id':'tls','type':'elasticsearch','endpoint':f'https://127.0.0.1:{tls.server_port}'}]
            folder,state,tls_path,_=fixture('tls_untrusted',sinks=tls_sink);(folder/'input.jsonl').write_text('{}\n')
            r=once(tls_path,False);check('unknown TLS CA is rejected while keeping the pending batch',r.returncode!=0 and (state/'pending.json').exists())
        finally:tls.shutdown();tls.server_close()
        for label, mutation in [('plain HTTP without opt-in',lambda c:c['sinks'][0].pop('allow_http')),
            ('URL credentials',lambda c:c['sinks'][0].update(endpoint='https://'+'user'+':'+'private'+'@example.test')),
            ('unknown configuration keys',lambda c:c.update(typo=True)),
            ('SQL identifier injection',lambda c:c['sinks'][1].update(table='events;DROP TABLE x'))]:
            bad=json.loads(json.dumps(conf));mutation(bad);path.write_text(json.dumps(bad))
            result=subprocess.run([str(binary),'--check',str(path)],capture_output=True,text=True)
            check('configuration rejects '+label,result.returncode!=0 and 'private' not in result.stderr)

    backend.shutdown();backend.server_close()
    args.report.parent.mkdir(parents=True,exist_ok=True)
    report={'passed':True,'check_count':len(checks),'checks':checks,'production_modified':False,'real_backend_instances':False}
    args.report.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'passed':True,'check_count':len(checks)}))


if __name__=='__main__':main()
