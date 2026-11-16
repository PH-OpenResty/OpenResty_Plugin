#!/usr/bin/env python3
"""A static backend cache/key cannot promote a hit with an unknown deadline."""
import argparse
import json
from pathlib import Path
import shutil
import tempfile

from boundaries import Review as BaseReview

class Review(BaseReview):
    def config(self, *args, **kwargs):
        text = super().config(*args, **kwargs)
        start = text.index(f'server {{ listen unix:{self.backend};')
        end = text.index(f'server {{ listen 127.0.0.1:{self.http};', start)
        backend = text[start:end].replace('proxy_cache $scdn_tier_cache;', 'proxy_cache l2;').replace(
            'proxy_cache_key $scdn_purge_key;', 'proxy_cache_key "$host|$request_uri";').replace(
            'proxy_cache_bypass $scdn_tier_validate;', 'proxy_cache_bypass 0;')
        front = text[end:].replace('proxy_pass $scdn_tier_upstream;',
            'proxy_pass $scdn_tier_upstream; add_header X-Test-Tier-Store $upstream_http_x_tier_store always;')
        return text[:start] + backend + front

    def run(self):
        path = '/l1/custom-backend-key'; self.state(path, accel='20')
        self.start(); first = self.get(path)
        self.check('origin response is admitted with a known fresh deadline', first[0] == 200
            and first[1]['X-Test-Tier-Store'] == '1')
        self.stop(); shutil.rmtree(self.root/'cache1'); self.start()
        lower = self.get(path)
        self.check('static backend key still serves a fresh lower HIT', lower[0] == 200
            and lower[1]['X-Cache-Layer'] == 'l2' and len(self.records(path)) == 1)
        self.check('unknown original expiry denies promotion', lower[1]['X-Test-Tier-Store'] == '0')
        self.check('next request remains in L2 instead of extending L1 TTL', self.get(path)[1]['X-Cache-Layer'] == 'l2')
        return self.checks

def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--prefix', required=True, type=Path)
    parser.add_argument('--static', action='store_true'); parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    prefix = args.prefix/'nginx' if (args.prefix/'nginx/sbin/nginx').exists() else args.prefix
    with tempfile.TemporaryDirectory(prefix='tier-custom-cache-') as temporary:
        review = Review(Path(temporary), prefix, args.static)
        try:
            checks = review.run()
            if args.report: args.report.write_text(json.dumps(dict(passed=len(checks), checks=checks), indent=2)+'\n')
        finally: review.close()

if __name__ == '__main__': main()
