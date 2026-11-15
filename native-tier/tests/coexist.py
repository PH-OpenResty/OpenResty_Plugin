#!/usr/bin/env python3
"""Activate all six modules with real tier caching and API/streaming traffic."""
from __future__ import annotations
import argparse
import importlib.util
import json
from pathlib import Path
import tempfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('api_fixture', ROOT / 'native-api/tests/integration.py')
fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)


class Review(fixture.Review):
    def config(self):
        text = super().config()
        if not self.static:
            line = f'load_module {self.prefix}/modules/ngx_http_scdn_tier_module.so;\n'
            text = line + text
        templates = ROOT / 'native-tier/examples'
        backend = (templates / 'backend.conf').read_text().replace(
            '/etc/ssl/certs/ca-certificates.crt', str(self.root / 'origin.crt')).replace(
            'proxy_cache_key "$scdn_tier_scope|$scdn_tier_key";',
            'scdn_purge_key $scdn_tier_scope $scdn_tier_key $scdn_tier_resource; proxy_cache_key $scdn_purge_key;')
        extra = f'''scdn_tier_zone hierarchy 1m; scdn_tier_socket {self.root}/tier.sock;
            proxy_cache_path {self.root}/cache-l2 keys_zone=l2:1m;
            server {{ listen unix:{self.root}/tier.sock; location / {{ scdn_api on; {backend} }} }}
        '''
        text = text.replace(' scdn_edge_zone counters 2m;', extra + ' scdn_edge_zone counters 2m;')
        start = text.index('location @scdn_edge_proxy {')
        end = text.index('location @api {', start)
        web = text[start:end]
        key = '"$scdn_api_cache_namespace|$scdn_edge_revision|$host|$request_uri"'
        web = web.replace('scdn_purge_key $scdn_edge_site ' + key + ' $request_uri;',
            'scdn_purge_key $scdn_tier_scope $scdn_tier_key $scdn_tier_resource;')
        web = web.replace('proxy_pass $scdn_edge_upstream;', 'proxy_pass $scdn_tier_upstream;')
        web = web.replace('proxy_cache $scdn_edge_cache;', 'proxy_cache $scdn_tier_cache;')
        web = web.replace('proxy_no_cache $scdn_api_skip_cache;', 'proxy_no_cache $scdn_api_skip_cache $scdn_tier_no_store;')
        fields = '\n'.join(line for line in (templates / 'front.conf').read_text().splitlines()
                           if line.startswith('proxy_set_header X-Tier-'))
        native = f'''scdn_tier_front $scdn_edge_cache $scdn_edge_upstream;
            scdn_tier_identity $scdn_edge_origin_host $scdn_edge_origin_sni $scdn_edge_site {key} $request_uri;
            scdn_tier_bypass $scdn_api_skip_cache;
            {fields}
        '''
        web = web.replace('location @scdn_edge_proxy {', 'location @scdn_edge_proxy {\n' + native)
        return text[:start] + web + text[end:]

    def run(self):
        super().run()
        _, headers, _ = self.request('/asset?hierarchy=1')
        _, headers, _ = self.request('/asset?hierarchy=1')
        self.check('all six modules serve an actual L1 cache HIT', headers.get('x-cache') == 'HIT'
                   and headers.get('x-cache-layer') == 'l1')
        return self.checks


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--prefix', type=Path, required=True)
    parser.add_argument('--static', action='store_true'); parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='native-six-modules-') as directory:
        review = Review(Path(directory), args.prefix, args.static, purge=True, sync=True)
        try:
            checks = review.run()
            args.report.write_text(json.dumps({'passed': len(checks), 'checks': checks}, indent=2) + '\n')
            print(f'{len(checks)} six-module checks passed', flush=True)
        except Exception:
            for name in ('error.log', 'process.log'):
                path = review.root / name
                if path.exists(): print(path.read_text(errors='replace')[-7000:].replace(review.purge_token, '[redacted]').replace(review.sync_token, '[redacted]'))
            raise
        finally: review.close()


if __name__ == '__main__': main()
