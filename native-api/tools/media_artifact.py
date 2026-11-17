#!/usr/bin/env python3
"""Materialize explicitly supplied API image results without calling a model.

The original API payload is not rewritten. Pillow is required for full decoding.
Remote URLs are disabled unless their exact HTTPS hosts are explicitly allowed.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import http.client
import io
import ipaddress
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import sys
import warnings
from urllib.parse import urljoin, urlsplit

from PIL import Image, UnidentifiedImageError


class MediaError(Exception):
    pass


def bounded_read(stream, maximum):
    data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise MediaError('input_limit')
    return data


def atomic_file(path, data):
    temporary = path.with_name('.' + secrets.token_hex(16) + '.tmp')
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def download_image(url, allowed_hosts, maximum):
    """Pin each connection to an approved public DNS answer; verify TLS SNI."""
    current = url
    for _ in range(4):
        try:
            parsed = urlsplit(current)
            host = (parsed.hostname or '').encode('idna').decode('ascii').lower().rstrip('.')
            if (parsed.scheme != 'https' or parsed.username is not None
                    or parsed.password is not None or parsed.fragment
                    or parsed.port not in (None, 443) or host not in allowed_hosts):
                raise MediaError('url_not_allowed')
            answers = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
            addresses = list(dict.fromkeys(answer[4][0] for answer in answers))
            if not addresses or any(not ipaddress.ip_address(value).is_global for value in addresses):
                raise MediaError('url_non_public_address')
            connection = http.client.HTTPSConnection(host, 443, timeout=20)
            raw_socket = socket.create_connection((addresses[0], 443), timeout=20)
            try:
                connection.sock = ssl.create_default_context().wrap_socket(raw_socket, server_hostname=host)
            except Exception:
                raw_socket.close()
                raise
            try:
                path = parsed.path or '/'
                if parsed.query:
                    path += '?' + parsed.query
                # No model credentials, Cookie, Referer or client headers follow.
                connection.request('GET', path, headers={'Accept': 'image/png,image/jpeg,image/webp'})
                response = connection.getresponse()
                if response.status in (301, 302, 303, 307, 308):
                    location = response.getheader('Location')
                    if not location:
                        raise MediaError('url_redirect')
                    current = urljoin(current, location)
                    continue
                if response.status != 200:
                    raise MediaError('url_http_status')
                if response.getheader('Content-Encoding', 'identity').lower() != 'identity':
                    raise MediaError('url_content_encoding')
                return bounded_read(response, maximum)
            finally:
                connection.close()
        except MediaError:
            raise
        except (OSError, ValueError, http.client.HTTPException):
            # URLs may contain signed tokens. Never include exception text.
            raise MediaError('url_fetch_failed') from None
    raise MediaError('url_redirect_limit')


def decode_payload(value, allowed_hosts, maximum):
    if not isinstance(value, str) or not value:
        raise MediaError('empty_image')
    if value.startswith(('https:', 'http:')):
        return download_image(value, allowed_hosts, maximum)
    if value.startswith('data:'):
        header, separator, value = value.partition(',')
        if (not separator or header.lower() not in (
                'data:image/png;base64', 'data:image/jpeg;base64', 'data:image/webp;base64')):
            raise MediaError('invalid_image_data_url')
    if len(value) > 4 * ((maximum + 2) // 3):
        raise MediaError('image_byte_limit')
    try:
        data = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise MediaError('invalid_base64') from None
    if not data or len(data) > maximum:
        raise MediaError('image_byte_limit')
    return data


def verify_image(data, maximum_pixels):
    formats = {'PNG': ('image/png', '.png'), 'JPEG': ('image/jpeg', '.jpg'), 'WEBP': ('image/webp', '.webp')}
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('error', Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(data)) as image:
                if image.format not in formats:
                    raise MediaError('unsupported_image_format')
                width, height = image.size
                if width < 1 or height < 1 or width * height > maximum_pixels:
                    raise MediaError('image_pixel_limit')
                if getattr(image, 'n_frames', 1) != 1:
                    raise MediaError('animated_image_not_supported')
                detected = image.format
                image.verify()
            with Image.open(io.BytesIO(data)) as image:
                image.load()
            mime, suffix = formats[detected]
            return mime, suffix, width, height
    except MediaError:
        raise
    except (OSError, ValueError, SyntaxError, UnidentifiedImageError,
            Image.DecompressionBombError, Image.DecompressionBombWarning):
        raise MediaError('image_decode_failed') from None


def payloads(data):
    """Read complete JSON or SSE; no model argument or prompt strings are parsed."""
    if data.lstrip().startswith((b'{', b'[')):
        obj = json.loads(data)
        yield obj, failed_payload(obj)
        return
    chunks = []
    event_name = ''
    for line in data.decode('utf-8').splitlines() + ['']:
        if line.startswith('data:'):
            chunks.append(line[5:].removeprefix(' '))
        elif line.startswith('event:'):
            event_name = line[6:].strip()
        elif not line and chunks:
            value = '\n'.join(chunks)
            chunks = []
            if value != '[DONE]':
                obj = json.loads(value)
                yield obj, event_name == 'error' or failed_payload(obj)
            event_name = ''


def failed_payload(obj):
    if not isinstance(obj, dict):
        return False
    response = obj.get('response', obj)
    return (obj.get('type') in ('error', 'response.failed', 'response.incomplete')
            or (isinstance(response, dict) and (
                response.get('status') in ('failed', 'incomplete', 'cancelled')
                or bool(response.get('error')))))


def candidates(value, include_partial=False, path='root', depth=0):
    if depth > 32:
        raise MediaError('structure_depth_limit')
    if isinstance(value, list):
        for index, item in enumerate(value):
            yield from candidates(item, include_partial, f'{path}[{index}]', depth + 1)
        return
    if not isinstance(value, dict):
        return
    kind = value.get('type')
    image = None
    partial = False
    if kind == 'image_generation_call' and value.get('result'):
        partial = value.get('status') not in (None, 'completed')
        if not partial or include_partial:
            image = value['result']
    elif kind == 'response.image_generation_call.partial_image' and include_partial:
        image, partial = value.get('partial_image_b64'), True
    elif '.data[' in path:
        image = value.get('b64_json') or value.get('url')
    elif kind in ('image_url', 'output_image'):
        item = value.get('image_url', value)
        image = item.get('url') if isinstance(item, dict) else item
    elif kind == 'image' and isinstance(value.get('source'), dict):
        source = value['source']
        if source.get('type') == 'base64':
            if source.get('media_type') not in ('image/png', 'image/jpeg', 'image/webp'):
                raise MediaError('unsupported_image_mime')
            image = source.get('data')
        elif source.get('type') == 'url':
            image = source.get('url')
    inline = value.get('inlineData', value.get('inline_data'))
    if isinstance(inline, dict):
        mime = inline.get('mimeType', inline.get('mime_type', ''))
        if mime in ('image/png', 'image/jpeg', 'image/webp'):
            image = inline.get('data')
    if image is not None:
        source = {'path': path}
        if isinstance(value.get('id'), str):
            source['item_id'] = value['id'][:256]
        if kind == 'response.image_generation_call.partial_image':
            source['item_id'] = str(value.get('item_id', ''))[:256]
            source['partial_image_index'] = value.get('partial_image_index')
        yield image, partial, source
    # Only protocol containers, never tools/input/arguments or arbitrary text.
    for key in ('data', 'response', 'output', 'item', 'candidates', 'choices', 'message', 'content', 'parts'):
        if key in value:
            yield from candidates(value[key], include_partial, path + '.' + key, depth + 1)


def materialize(data, output_dir, *, input_format='auto', allowed_hosts=(), max_image_bytes=32 << 20,
                max_total_bytes=64 << 20, max_pixels=40_000_000, max_images=16, include_partial=False):
    output_dir = Path(output_dir).absolute()
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination = output_dir / ('api-media-' + secrets.token_hex(12))
    destination.mkdir(mode=0o700)
    artifacts, errors, seen = [], [], {}
    stream_error, total, attempted = False, 0, 0
    allowed_hosts = {host.encode('idna').decode('ascii').lower().rstrip('.') for host in allowed_hosts}
    try:
        if input_format == 'binary' or (input_format == 'auto' and data.startswith(
                (b'\x89PNG\r\n', b'\xff\xd8', b'RIFF'))):
            records = [(base64.b64encode(data).decode('ascii'), False, {'path': 'binary'})]
        else:
            def collect():
                nonlocal stream_error
                for obj, failed in payloads(data):
                    stream_error |= failed
                    yield from candidates(obj, include_partial)
            records = collect()
        for encoded, partial, source in records:
            attempted += 1
            if attempted > max_images * 4:
                raise MediaError('image_count_limit')
            try:
                image = decode_payload(encoded, allowed_hosts, max_image_bytes)
                digest = hashlib.sha256(image).hexdigest()
                identity = (digest, partial)
                if identity in seen:
                    artifacts[seen[identity]]['source_refs'].append(source)
                    continue
                if len(artifacts) >= max_images or total + len(image) > max_total_bytes:
                    raise MediaError('total_artifact_limit')
                mime, suffix, width, height = verify_image(image, max_pixels)
                path = destination / (secrets.token_hex(16) + suffix)
                atomic_file(path, image)
                total += len(image)
                seen[identity] = len(artifacts)
                artifacts.append({'artifact_id': path.stem, 'path': str(path), 'mime_type': mime,
                                  'width': width, 'height': height, 'bytes': len(image),
                                  'sha256': digest, 'partial': partial, 'decode_verified': True,
                                  'source_refs': [source],
                                  'preview_markdown': f'![API image](<{path}>)'})
            except MediaError as error:
                errors.append({'code': str(error), 'candidate_index': attempted - 1})
    except (json.JSONDecodeError, UnicodeError, RecursionError, TypeError):
        errors.append({'code': 'invalid_protocol_payload'})
    except MediaError as error:
        errors.append({'code': str(error)})
    if stream_error:
        errors.append({'code': 'upstream_stream_incomplete'})
    complete = sum(not item['partial'] for item in artifacts)
    if not complete and not errors:
        errors.append({'code': 'no_final_images'})
    status = 'complete' if complete and not errors else ('partial' if artifacts else 'failed')
    report = {'version': 1, 'status': status, 'artifacts': artifacts, 'errors': errors,
              'final_image_count': complete, 'raw_sha256': hashlib.sha256(data).hexdigest(),
              'raw_bytes': len(data), 'raw_rewritten': False, 'attachment_emitted': False,
              'client_display_verified': False}
    manifest = destination / 'manifest.json'
    atomic_file(manifest, (json.dumps(report, ensure_ascii=False, indent=2) + '\n').encode('utf-8'))
    report['manifest_path'] = str(manifest)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, help='JSON/SSE/image file; otherwise read stdin')
    parser.add_argument('--out-dir', type=Path, required=True)
    parser.add_argument('--format', choices=('auto', 'binary'), default='auto')
    parser.add_argument('--allow-url-host', action='append', default=[])
    parser.add_argument('--max-input-mb', type=int, default=128)
    parser.add_argument('--max-image-mb', type=int, default=32)
    parser.add_argument('--max-total-mb', type=int, default=64)
    parser.add_argument('--max-pixels', type=int, default=40_000_000)
    parser.add_argument('--include-partial', action='store_true')
    args = parser.parse_args()
    if any(value < 1 for value in (args.max_input_mb, args.max_image_mb, args.max_total_mb, args.max_pixels)):
        parser.error('limits must be positive')
    try:
        if args.input:
            with args.input.open('rb') as source:
                data = bounded_read(source, args.max_input_mb << 20)
        else:
            data = bounded_read(sys.stdin.buffer, args.max_input_mb << 20)
        report = materialize(data, args.out_dir, input_format=args.format, allowed_hosts=args.allow_url_host,
                             max_image_bytes=args.max_image_mb << 20, max_total_bytes=args.max_total_mb << 20,
                             max_pixels=args.max_pixels, include_partial=args.include_partial)
        print(json.dumps(report, ensure_ascii=False))
        return 0 if report['status'] == 'complete' else 1
    except (MediaError, OSError, ValueError):
        print(json.dumps({'status': 'failed', 'errors': [{'code': 'input_or_output_failed'}]}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
