#!/usr/bin/env python3
"""Pattern invalidation boundaries, recovery and bounded matching."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import tempfile

from integration import Review


class Patterns(Review):
    def run(self):
        self.start()
        cases = [
            ('wildcard', ['/glob/a?.js*'], ['/glob/ab.js', '/glob/ac.js?v=2'],
             ['/glob/abc.js', '/glob/ab.css', '/other/ab.js']),
            ('wildcard', [r'/literal/\*.js'], ['/literal/*.js'], ['/literal/a.js']),
            ('regex', [r'^/rx/[^/]+\.(css|js)(\?.*)?$'], ['/rx/a.css', '/rx/b.js?v=1'],
             ['/rx/a.cssx', '/rx/sub/a.css', '/rx/A.CSS']),
            ('suffix', ['.css', '.js'], ['/assets/a.css', '/other/b.js?v=1'],
             ['/assets/a.cssx', '/assets/a.CSS', '/file.txt?name=a.css']),
            ('directory', ['/docs'], ['/docs', '/docs?x=1', '/docs/', '/docs/a/b'],
             ['/docs-other/x', '/docs%2fx', '/document']),
            ('directory', ['/tree/'], ['/tree', '/tree/a'], ['/tree-other/a']),
            ('directory', ['/double//'], ['/double/', '/double//a'], ['/double/a']),
        ]
        saved = []
        for i, (mode, rules, matches, misses) in enumerate(cases):
            scope = 'pattern-' + str(i)
            self.version(i * 2 + 1)
            previous = {key: self.fill(key, scope)[2] for key in matches + misses}
            self.version(i * 2 + 2)
            result = self.control(mode, scope, rules)
            self.check(mode + ' rules are durably acknowledged: ' + str(i), result[0] == 200 and result[1]['durable'])
            for key in matches:
                value = self.request(key, scope)
                self.check(mode + ' matches ' + key, value[2] != previous[key] and value[1]['X-Cache'] != 'HIT')
            for key in misses:
                self.check(mode + ' excludes ' + key, self.request(key, scope)[2] == previous[key])
            saved.append((scope, matches[0], self.fill(matches[0], scope)[2]))

        scope = 'isolated'
        self.version(31)
        previous = self.fill('/assets/a.css', scope)[2]
        self.version(32)
        self.control('suffix', 'another-site', ['.css'])
        self.check('pattern rules remain isolated by site', self.request('/assets/a.css', scope)[2] == previous)
        calls=self.origin.calls
        self.check('invalid scope cannot become a shared empty cache key', self.request('/bad-scope', ' ')[0] >= 500
                   and self.origin.calls == calls)

        sequence = self.status()['sequence']
        for mode, rules in [('regex', ['^/valid$', '(']), ('regex', ['a' * 1025]),
                            ('wildcard', ['abc\\']), ('wildcard', ['a' * 1025]),
                            ('directory', ['/docs?x=1']), ('suffix', ['.css?x'])]:
            value = self.control(mode, 'invalid', rules)
            self.check('invalid rule batch rejected: ' + mode + str(len(rules[0])),
                       value[0] == 400 and self.status()['sequence'] == sequence)

        scope = 'mixed-capacity'
        rules = ['/capacity/' + str(i) for i in range(125)]
        self.check('combined pattern capacity starts with prefixes', self.control('prefix', scope, rules)[0] == 200)
        self.check('wildcard regex and suffix share the same bounded rule budget',
                   self.control('wildcard', scope, ['/w/*'])[0] == 200
                   and self.control('regex', scope, ['^/r/'])[0] == 200
                   and self.control('suffix', scope, ['.css'])[0] == 200)
        self.check('directory cannot exceed the combined rule budget', self.control('directory', scope, ['/d'])[0] == 507)
        self.check('updating an existing rule consumes no extra capacity', self.control('regex', scope, ['^/r/'])[0] == 200)
        self.control('site', scope)
        self.check('whole-site alias reclaims all pattern types', self.control('directory', scope, ['/d'])[0] == 200)

        scope = 'regex-budget'
        key = '/' + 'a' * 300 + '!'
        self.fill(key, scope)
        self.control('regex', scope, ['(*NO_START_OPT)^/(a+)+$'])
        self.check('regex execution budget fails closed instead of exposing old content', self.request(key, scope)[0] >= 500)
        self.control('site', scope)
        self.check('a site invalidation clears an over-budget rule', self.request(key, scope)[0] == 200)

        scope = 'concurrent-pattern'
        keys = ['/parallel/a.css', '/parallel/b.js?x=1']
        self.version(41)
        for key in keys:
            self.fill(key, scope)
        self.version(42)
        self.control('regex', scope, [r'^/parallel/.*\.(css|js)(\?.*)?$'])
        with ThreadPoolExecutor(max_workers=16) as pool:
            values = list(pool.map(lambda i: self.request(keys[i % 2], scope), range(64)))
        self.check('concurrent requests after regex ACK cannot read old versions', all(v[2].startswith(b'v42:') for v in values))

        # Force the normal checkpoint writer to persist all new record modes.
        long_keys = ['/checkpoint/' + str(i) + '/' + 'x' * 700 for i in range(128)]
        for _ in range(3):
            self.control('exact', 'checkpoint-patterns', long_keys)
        sequence = self.status()['sequence']
        self.check('new rule modes pass through journal compaction', self.status()['checkpoints'] > 0)
        self.stop(); self.start()
        self.check('checkpoint replay restores pattern sequence', self.status()['sequence'] == sequence)
        self.version(99)
        for scope, key, body in saved:
            self.check('restarted rules preserve their cache namespace: ' + scope, self.request(key, scope)[2] == body)

        self.version(51)
        left = self.fill('/node/a', 'node-left')[2]
        right = self.fill('/node/b', 'node-right', second=True)[2]
        self.version(52)
        self.check('node alias clears all scopes and both cache zones',
                   self.control('node', scope=None)[0] == 200
                   and self.request('/node/a', 'node-left')[2] != left
                   and self.request('/node/b', 'node-right', second=True)[2] != right)
        self.stop(); self.start(allow_all=False)
        self.check('node-wide invalidation obeys the global permission switch', self.control('node', scope=None)[0] == 403)
        return self.checks


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--prefix', required=True, type=Path)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    prefix = args.prefix / 'nginx' if (args.prefix / 'nginx/sbin/nginx').exists() else args.prefix
    with tempfile.TemporaryDirectory(prefix='scdn-pattern-test-') as directory:
        review = Patterns(Path(directory), prefix.resolve(), faults=False)
        try:
            checks = review.run()
            if args.report:
                args.report.write_text(json.dumps(dict(passed=len(checks), checks=checks), indent=2) + '\n')
            print(f'{len(checks)} pattern checks passed', flush=True)
        except Exception:
            if (review.root / 'error.log').exists():
                print((review.root / 'error.log').read_text(errors='replace')[-5000:], flush=True)
            raise
        finally:
            review.close()


if __name__ == '__main__':
    main()
