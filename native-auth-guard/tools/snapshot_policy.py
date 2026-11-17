#!/usr/bin/env python3
"""Fetch the dedicated application policy exporter; never fetch admin options."""
import argparse
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import stat
import tempfile
import time
import urllib.parse
import urllib.request

MAXIMUM = 2 << 20
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,95}\Z')
DOMAIN = re.compile(r'(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')


class PolicyError(ValueError):
    pass


def mac(key, purpose, value):
    return hmac.new(key, purpose.encode() + b':' + value, hashlib.sha256).hexdigest()


def read_key(path):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > 66 or (os.name == 'posix' and info.st_mode & 0o077):
        raise PolicyError('realm key must be a private regular file')
    raw = path.read_bytes()
    if len(raw) != 32:
        try:
            raw = bytes.fromhex(raw.decode('ascii').rstrip('\r\n'))
        except (ValueError, UnicodeError) as error:
            raise PolicyError('invalid realm key file') from error
    if len(raw) != 32 or not any(raw):
        raise PolicyError('invalid realm key file')
    return raw


def domains(values):
    if not isinstance(values, list) or len(values) > 4096:
        raise PolicyError('invalid domain list')
    result = set()
    for value in values:
        if not isinstance(value, str) or len(value) > 253 or not DOMAIN.fullmatch(value):
            raise PolicyError('domain must be an ASCII DNS name or an explicit *. suffix')
        result.add(value)
    return sorted(result)


def normalize_policy(value, adapter):
    if not isinstance(value, dict) or value.get('adapter') != adapter:
        raise PolicyError('application adapter does not match the configured realm')
    result = {'adapter': adapter}
    revision = value.get('revision')
    if not isinstance(revision, str) or not NAME.fullmatch(revision):
        raise PolicyError('invalid application policy revision')
    result['revision'] = revision
    for name in ('registration_enabled', 'email_verify_enabled', 'strict_email', 'precreate_required', 'email_alias_restriction'):
        if type(value.get(name)) is not bool:
            raise PolicyError('missing typed policy flag: ' + name)
        result[name] = value[name]
    if not result['strict_email'] or not result['precreate_required']:
        raise PolicyError('this release requires strict email and the application pre-create hook')
    for name in ('allowed_domains', 'denied_domains'):
        result[name] = domains(value.get(name))
    # An empty allowlist or disabled verification remains a closed registration
    # policy at runtime. It must never become an allow-all snapshot.
    return result


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise PolicyError('policy exporter redirects are forbidden')


def fetch(endpoint, realm, key, opener=None):
    parsed = urllib.parse.urlsplit(endpoint)
    if parsed.username or parsed.password or parsed.query or parsed.fragment or not parsed.hostname:
        raise PolicyError('use one fixed policy-exporter URL without credentials or query')
    if parsed.scheme != 'https':
        try:
            loopback = ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:
            loopback = False
        if parsed.scheme != 'http' or not loopback:
            raise PolicyError('HTTPS is required outside a numeric loopback endpoint')
    stamp, nonce = str(int(time.time())), secrets.token_hex(16)
    binding = (stamp + '\n' + nonce + '\n' + realm).encode()
    request = urllib.request.Request(endpoint, headers={
        'X-SCDN-Auth-Time': stamp, 'X-SCDN-Auth-Nonce': nonce,
        'X-SCDN-Auth-Policy': mac(key, 'policy-request', binding), 'Accept': 'application/json'})
    if opener is None:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    with opener.open(request, timeout=5) as response:
        if response.status != 200:
            raise PolicyError('policy exporter did not return 200')
        raw = response.read(MAXIMUM + 1)
        signatures = response.headers.get_all('X-SCDN-Auth-Policy', [])
        if len(raw) > MAXIMUM or len(signatures) != 1 or not hmac.compare_digest(
                signatures[0], mac(key, 'policy-response', binding + b'\n' + raw)):
            raise PolicyError('policy response is oversized, stale or unauthenticated')
    return json.loads(raw)


def snapshot(config, getter=fetch):
    if not isinstance(config, dict) or config.get('version') != 1:
        raise PolicyError('invalid snapshot configuration')
    node = config.get('node_id', '')
    if not isinstance(node, str) or len(node) > 64 or not NAME.fullmatch(node):
        raise PolicyError('invalid node_id')
    result = {name: config[name] for name in ('version', 'node_id', 'password_file',
        'admin_key_file', 'trusted_proxies', 'max_entries', 'max_inflight') if name in config}
    result['realms'] = []
    realms = config.get('realms')
    if not isinstance(realms, list) or not 1 <= len(realms) <= 32:
        raise PolicyError('configure 1 to 32 realms')
    seen = set()
    for realm in realms:
        identifier, adapter = realm.get('id', ''), realm.get('adapter', '')
        if not isinstance(identifier, str) or len(identifier) > 64 or not NAME.fullmatch(identifier) or identifier in seen:
            raise PolicyError('invalid or duplicate realm')
        seen.add(identifier)
        if adapter not in ('sub2api', 'newapi'):
            raise PolicyError('unknown application adapter')
        key_path = realm['key_file']
        policy = normalize_policy(getter(realm['exporter_url'], identifier, read_key(key_path)), adapter)
        value = {name: realm[name] for name in ('id', 'key_file', 'limits') if name in realm}
        maximum_age = realm.get('max_age', 1800)
        if type(maximum_age) is not int or not 1 <= maximum_age <= 86400:
            raise PolicyError('max_age must be 1 to 86400 seconds')
        value.update(policy, checked_at=int(time.time()), max_age=maximum_age)
        result['realms'].append(value)
    return result


def atomic_write(path, value):
    path = Path(path)
    raw = (json.dumps(value, ensure_ascii=True, indent=2) + '\n').encode()
    descriptor, temporary = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    published = False
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path); published = True
        if os.name == 'posix':
            parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
    except OSError as error:
        if published:
            raise PolicyError('snapshot was replaced but directory durability could not be confirmed; inspect it before reloading') from error
        raise
    finally:
        if not published:
            Path(temporary).unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.config.stat().st_size > MAXIMUM:
            raise PolicyError('snapshot configuration is too large')
        value = snapshot(json.loads(args.config.read_bytes()))
        atomic_write(args.output, value)
    except (OSError, ValueError, KeyError) as error:
        # URLs, keys and response data are deliberately absent from diagnostics.
        detail = str(error) if isinstance(error, PolicyError) else type(error).__name__
        parser.exit(1, 'policy snapshot failed: ' + detail + '\n')
    print(json.dumps({'published': True, 'realms': len(value['realms']), 'automatic_reload': False}))


if __name__ == '__main__':
    main()
