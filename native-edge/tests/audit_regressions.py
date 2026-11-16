#!/usr/bin/env python3
"""Large host indexes, named pools, content polling and local control boundaries."""
import argparse
import http.client
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import time

from integration import Review as BaseReview

class Review(BaseReview):
    def config(self):
        return super().config().replace('http {', 'http {\nupstream fixturepool { server 127.0.0.1:'
            + str(self.origins[1].server_port) + '; keepalive 4; }', 1)

    def run(self):
        path = self.root/'nginx.conf'; path.write_text(self.config())
        self.log = (self.root/'stdout.log').open('wb')
        self.process = subprocess.Popen([str(self.nginx), '-p', str(self.root)+'/', '-c', str(path), '-g', 'daemon off;'],
            stdout=self.log, stderr=self.log)
        self.until(lambda: self.control(), 'startup')
        workers = self.until(lambda: p if len(p := self.workers()) == 2 else None, 'two workers')
        self.check('baseline route', self.request()[2] == b'a:/asset')
        self.check('case-insensitive indexed Host lookup', self.request(host='WWW.EXAMPLE.COM')[0] == 200)
        content = self.sites().replace('http://127.0.0.1:' + str(self.origins[0].server_port), 'http://fixturepool', 1)
        before = self.generation(); self.set_source(content); self.wait_change(before)
        self.check('variable proxy_pass resolves a declared http://pool', self.request()[2] == b'b:/asset')
        before = self.generation(); self.set_source(self.sites()); self.wait_change(before)
        previous = self.control()['revision']
        stamp = self.source.stat()
        changed = self.sites(origin=1)
        assert len(changed.encode()) == stamp.st_size
        self.source.write_text(changed); os.utime(self.source, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        self.wait_change(before + 1)
        self.check('same-size/mtime source replacement is detected', self.control()['revision'] != previous and self.request()[2] == b'b:/asset')
        key = self.root/'site.key'; key.chmod(0o644)
        self.until(lambda: self.control()['last_error'] == 'certificate_validation_failed', 'private key mode')
        self.check('public private key is rejected while the active TLS snapshot survives', self.request(tls=True)[3] == self.cert_a)
        key.chmod(0o600); self.until(lambda: not self.control()['last_error'], 'private key permission repair')
        self.source.chmod(0o666)
        self.until(lambda: self.control()['last_error'] == 'configuration_unavailable', 'writable site source')
        self.check('world-writable source cannot replace live routes', self.request()[2] == b'b:/asset')
        self.source.chmod(0o644); self.until(lambda: not self.control()['last_error'], 'source permission repair')
        extra = '\n'.join('site s%03d { %s upstream http://127.0.0.1:%d; }' %
            (i, ' '.join('host h%03d-%02d.example.com;' % (i,j) for j in range(32)), self.origins[0].server_port)
            for i in range(254))
        before = self.generation(); self.set_source(self.sites(extra=extra)); self.wait_change(before)
        self.check('256 sites and 8131 indexed hosts retain the final host', self.control()['sites'] == 256
            and self.request(host='h253-31.example.com')[2] == b'a:/asset')
        self.check('large index still rejects unknown hosts', self.request(host='absent.example.com')[0] == 403)
        def bytes_total():
            return int(re.search(r'scdn_edge_bytes_total\{site="alpha"\} (\d+)', self.control('/metrics'))[1])
        connection = http.client.HTTPConnection('127.0.0.1', self.http, timeout=5)
        try:
            start = bytes_total(); self.request(connection=connection); first = bytes_total()
            peer = connection.sock.getsockname()
            self.request(connection=connection); second = bytes_total()
            self.check('keepalive counts each response once on the same connection', connection.sock.getsockname() == peer
                and first > start and second - first == first - start)
        finally: connection.close()
        for endpoint in ('/status', '/metrics'):
            c = http.client.HTTPConnection('localhost'); c.sock = socket.socket(socket.AF_UNIX)
            c.sock.connect(str(self.socket)); c.request('GET', endpoint); response = c.getresponse(); response.read()
            self.check(endpoint + ' forbids response caching', response.getheader('Cache-Control') == 'no-store'); c.close()
        self.check('all changes retain worker PIDs', self.workers() == workers)
        self.process.terminate(); self.process.wait(timeout=10)
        path.write_text(self.config().replace('scdn_config_interval 100ms;', 'scdn_config_interval 10s;').replace(
            'scdn_config_settle 300ms;', 'scdn_config_settle 10s;'))
        self.process = subprocess.Popen([str(self.nginx), '-p', str(self.root)+'/', '-c', str(path), '-g', 'daemon off;'],
            stdout=self.log, stderr=self.log)
        def all_ready():
            c = http.client.HTTPConnection('localhost'); c.sock = socket.socket(socket.AF_UNIX)
            c.sock.connect(str(self.socket)); c.request('GET', '/status'); response = c.getresponse(); response.read()
            value = response.getheader('X-Config-Ready') == '1'; c.close(); return value
        self.until(all_ready, 'slow interval startup')
        time.sleep(5.5)
        self.check('ten-second poll interval remains ready after the old five-second threshold', all_ready())
        return self.checks

def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--prefix', required=True, type=Path)
    parser.add_argument('--static', action='store_true'); parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    prefix = args.prefix/'nginx' if (args.prefix/'nginx/sbin/nginx').exists() else args.prefix
    with tempfile.TemporaryDirectory(prefix='edge-audit-') as temporary:
        review = Review(Path(temporary), prefix, args.static)
        try:
            checks = review.run()
            if args.report: args.report.write_text(json.dumps(dict(passed=len(checks), checks=checks), indent=2)+'\n')
        finally: review.close()

if __name__ == '__main__': main()
