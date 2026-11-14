#!/usr/bin/env python3
"""Reject private artifacts in tracked files or the exact Git staging index.

This guard complements Gitleaks and manual site/domain review. Findings never
include matching values. No files or Git state are modified.
"""
from __future__ import annotations

import argparse
from pathlib import Path, PurePosixPath
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PRIVATE_DIRS = {
    '.ssh', '.runtime', '.perf-work', '.dev-tools', '.build', '__pycache__',
    'keys', 'pki', 'secrets', 'credentials', 'backups', 'evidence',
    'logs', 'cache', 'data', 'generated',
}
PRIVATE_SUFFIXES = {
    '.pem', '.key', '.crt', '.cer', '.p12', '.pfx', '.jks', '.token',
    '.ljbc', '.luac', '.pyc', '.log', '.bak', '.dump', '.sql',
    '.zip', '.gz', '.tar', '.tgz', '.exe', '.dll', '.so', '.o',
}
PRIVATE_NAMES = {
    '.admin_token', 'id_rsa', 'id_ed25519', 'runtime.json', 'applied.json',
    'desired.json', 'journal.json', 'highest.json',
}
CONTENT_RULES = {
    'private-key-material': re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----'),
    'certificate-material': re.compile(r'-----BEGIN ' r'CERTIFICATE-----'),
    'github-token': re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b'),
    'credential-in-url': re.compile(r'https?://[^\s/<>"\x27]+:[^\s/<>"\x27]+@'),
    'personal-home-path': re.compile(r'(?i)(?:[a-z]:[\\/]+Users[\\/]+[^\\/\s]+|/(?:home|Users)/[^/\s]+)'),
    'private-deployment-path': re.compile(r'/(?:opt/)?PH_[A-Za-z0-9_/]+'),
}
EMAIL = re.compile(r'(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b')


def git(*args):
    return subprocess.check_output(['git', '-C', str(ROOT), *args])


def blocked_path(name):
    path = PurePosixPath(name)
    basename = path.name.lower()
    if any(part.lower() in PRIVATE_DIRS for part in path.parts):
        return True
    if path.suffix.lower() in PRIVATE_SUFFIXES or basename in PRIVATE_NAMES:
        return True
    if basename == '.env' or (basename.startswith('.env.') and basename != '.env.example'):
        return True
    if basename.endswith('-token') or '.local.' in basename:
        return True
    return False



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--staged', action='store_true', help='Read exact index blobs instead of the working tree')
    args = parser.parse_args()
    entries = git('ls-files', '--stage', '-z').decode('utf-8').split('\0')
    failures, count = [], 0
    for entry in filter(None, entries):
        metadata, name = entry.split('\t', 1)
        mode, oid, stage = metadata.split()
        count += 1
        if stage != '0' or mode not in ('100644', '100755'):
            failures.append((name, 0, 'non-regular-file-or-unmerged-index'))
            continue
        if blocked_path(name):
            failures.append((name, 0, 'private-or-generated-file'))
        path = ROOT / name
        if not args.staged and (path.is_symlink() or not path.is_file()):
            failures.append((name, 0, 'missing-or-non-regular-working-file'))
            continue
        content = git('cat-file', 'blob', oid) if args.staged else path.read_bytes()
        try:
            text = content.decode('utf-8')
        except UnicodeDecodeError:
            failures.append((name, 0, 'binary-or-non-utf8-file'))
            continue
        if '\0' in text:
            failures.append((name, 0, 'binary-file'))
        for rule, pattern in CONTENT_RULES.items():
            for match in pattern.finditer(text):
                failures.append((name, text.count('\n', 0, match.start()) + 1, rule))
        if name != 'LICENSE':
            for match in EMAIL.finditer(text):
                domain = match.group().rsplit('@', 1)[1].lower()
                if domain not in ('example.com', 'example.org', 'example.net', 'users.noreply.github.com'):
                    failures.append((name, text.count('\n', 0, match.start()) + 1, 'personal-email'))
    for name, line, rule in failures:
        print(f'{name}:{line}: {rule}')
    print(f'Publication check: {count} files, {len(failures)} findings; values redacted.')
    return bool(failures)


if __name__ == '__main__':
    raise SystemExit(main())
