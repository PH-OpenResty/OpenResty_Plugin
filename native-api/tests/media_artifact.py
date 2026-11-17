#!/usr/bin/env python3
"""Offline image decoding, media extraction and disclosure boundaries."""
import argparse
import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import ssl
from unittest.mock import Mock
from unittest.mock import patch

from PIL import Image

spec = importlib.util.spec_from_file_location('media', Path(__file__).resolve().parents[1]/'tools/media_artifact.py')
media = importlib.util.module_from_spec(spec)
spec.loader.exec_module(media)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    buffer = io.BytesIO()
    Image.new('RGB', (24, 17), (32, 128, 240)).save(buffer, 'PNG')
    png = buffer.getvalue()
    encoded = base64.b64encode(png).decode()
    checks = []
    def check(name, condition):
        assert condition, name
        checks.append(name)
    with tempfile.TemporaryDirectory(prefix='api-media-test-') as directory:
        root = Path(directory)
        samples = {
            'images': {'data': [{'b64_json': encoded}]},
            'responses': {'output': [{'type': 'image_generation_call', 'id': 'ig_test', 'status': 'completed', 'result': encoded}]},
            'chat': {'choices': [{'message': {'content': [{'type': 'image_url', 'image_url': {'url': 'data:image/png;base64,'+encoded}}]}}]},
            'gemini': {'candidates': [{'content': {'parts': [{'inlineData': {'mimeType': 'image/png', 'data': encoded}}]}}]},
            'messages': {'content': [{'type': 'tool_result', 'tool_use_id': 'tool_test', 'content': [{'type': 'image', 'source': {'type': 'base64', 'media_type': 'image/png', 'data': encoded}}]}]},
        }
        for name, value in samples.items():
            raw = json.dumps(value).encode()
            report = media.materialize(raw, root)
            item = report['artifacts'][0]
            check(name+' decodes original image bytes', report['status']=='complete' and Path(item['path']).read_bytes()==png)
            check(name+' reports actual size and digest', (item['width'],item['height'])==(24,17) and item['sha256']==hashlib.sha256(png).hexdigest())
            check(name+' separates file from attachment and display', Path(item['path']).is_absolute() and not report['attachment_emitted'] and not report['client_display_verified'])
            check(name+' preserves original payload digest', report['raw_sha256']==hashlib.sha256(raw).hexdigest() and not report['raw_rewritten'])
        image = samples['responses']['output'][0]
        events = [
            {'type':'response.image_generation_call.partial_image','partial_image_b64':encoded},
            {'type':'response.output_item.done','item':image},
            {'type':'response.completed','response':samples['responses']},
        ]
        sse = b''.join(('event: '+item['type']+'\r\ndata: '+json.dumps(item)+'\r\n\r\n').encode() for item in events)
        report = media.materialize(sse, root)
        check('SSE deduplicates final item and completed response', report['status']=='complete' and len(report['artifacts'])==1)
        check('deduplicated image retains both source references',len(report['artifacts'][0]['source_refs'])==2 and report['artifacts'][0]['source_refs'][0]['item_id']=='ig_test')
        only_partial = ('data: '+json.dumps(events[0])+'\n\n').encode()
        check('partial-only stream is not a completed image', media.materialize(only_partial, root)['status']=='failed')
        report = media.materialize(only_partial, root, include_partial=True)
        check('explicit preview remains partial', report['status']=='partial' and report['artifacts'][0]['partial'])
        failure = sse + b'event: error\ndata: {"message":"upstream failed"}\n\n'
        check('valid item followed by upstream error is partial success', media.materialize(failure,root)['status']=='partial')
        failed = {'status':'failed', **samples['responses']}
        check('failed JSON response is not promoted to complete', media.materialize(json.dumps(failed).encode(),root)['status']=='partial')
        check('binary image retains exact bytes', media.materialize(png,root)['status']=='complete')
        cases = [
            ('invalid_base64', b'not base64!'),
            ('image_decode_failed', base64.b64encode(png[:40])),
            ('unsupported_image_format', base64.b64encode(b'<svg/>')),
        ]
        for name, value in cases:
            report=media.materialize(json.dumps({'data':[{'b64_json':value.decode()}]}).encode(),root)
            check(name+' does not save a fake image', report['status']=='failed' and not report['artifacts'])
        check('decoded byte limit', not media.materialize(json.dumps(samples['images']).encode(),root,max_image_bytes=8)['artifacts'])
        check('pixel limit', not media.materialize(png,root,max_pixels=4)['artifacts'])
        check('total output budget', not media.materialize(png,root,max_total_bytes=8)['artifacts'])
        check('prompt image-looking text is not extracted', media.materialize(json.dumps({'input':samples['images']}).encode(),root)['status']=='failed')
        url='https://media.example.test/private.png?token=not-for-output'
        raw=json.dumps({'data':[{'url':url}]}).encode()
        report=media.materialize(raw,root)
        check('remote URLs disabled by default', report['errors'][0]['code']=='url_not_allowed')
        check('signed URL is absent from reports', 'not-for-output' not in json.dumps(report) and url not in Path(report['manifest_path']).read_text())
        answers=[(2,1,6,'',('127.0.0.1',443))]
        with patch.object(media.socket,'getaddrinfo',return_value=answers), patch.object(media.socket,'create_connection') as connect:
            report=media.materialize(raw,root,allowed_hosts=['media.example.test'])
            check('allowed hostname cannot resolve to private destination', report['errors'][0]['code']=='url_non_public_address' and not connect.called)
        public=[(2,1,6,'',('93.184.216.34',443))]
        response=Mock(status=200)
        response.getheader.side_effect=lambda name,default=None: default
        response.read.return_value=png
        connection=Mock()
        connection.getresponse.return_value=response
        context=Mock()
        with patch.object(media.socket,'getaddrinfo',return_value=public), patch.object(media.socket,'create_connection') as connect, \
                patch.object(media.ssl,'create_default_context',return_value=context), patch.object(media.http.client,'HTTPSConnection',return_value=connection):
            report=media.materialize(raw,root,allowed_hosts=['media.example.test'])
            check('explicit public URL creates a verified image',report['status']=='complete')
            check('connection uses vetted address rather than repeating DNS',connect.call_args.args==(('93.184.216.34',443),))
            check('TLS keeps original hostname for validation',context.wrap_socket.call_args.kwargs['server_hostname']=='media.example.test')
            check('download forwards no credentials',connection.request.call_args.kwargs['headers']=={'Accept':'image/png,image/jpeg,image/webp'})
        response.status=302
        response.getheader.side_effect=lambda name,default=None: 'https://other.example.test/x' if name=='Location' else default
        with patch.object(media.socket,'getaddrinfo',return_value=public), patch.object(media.socket,'create_connection') as connect, \
                patch.object(media.ssl,'create_default_context',return_value=context), patch.object(media.http.client,'HTTPSConnection',return_value=connection):
            report=media.materialize(raw,root,allowed_hosts=['media.example.test'])
            check('redirect cannot leave registered hosts',report['status']=='failed' and connect.call_count==1)
        response.getheader.side_effect=lambda name,default=None: 'https://media.example.test/redirect' if name=='Location' else default
        with patch.object(media.socket,'getaddrinfo',side_effect=[public,answers]), patch.object(media.socket,'create_connection') as connect, \
                patch.object(media.ssl,'create_default_context',return_value=context), patch.object(media.http.client,'HTTPSConnection',return_value=connection):
            report=media.materialize(raw,root,allowed_hosts=['media.example.test'])
            check('redirect DNS rebinding cannot reach private addresses',report['errors'][0]['code']=='url_non_public_address' and connect.call_count==1)
        context.wrap_socket.side_effect=ssl.SSLCertVerificationError('fixture certificate mismatch')
        with patch.object(media.socket,'getaddrinfo',return_value=public), patch.object(media.socket,'create_connection'), \
                patch.object(media.ssl,'create_default_context',return_value=context):
            check('TLS verification failure never saves an image',media.materialize(raw,root,allowed_hosts=['media.example.test'])['status']=='failed')
        for value in ('http://media.example.test/x','https://'+'fixture:fixture'+'@media.example.test/x','https://media.example.test:444/x'):
            report=media.materialize(json.dumps({'data':[{'url':value}]}).encode(),root,allowed_hosts=['media.example.test'])
            check('reject URL authority '+str(len(checks)),report['status']=='failed')
        check('artifact directories contain no partial temporary files',not list(root.glob('api-media-*/*.tmp')) and not list(root.glob('api-media-*/.*.tmp')))
    result={'passed':True,'check_count':len(checks),'checks':checks,'real_vendor_api_calls':0,'production_modified':False}
    args.report.parent.mkdir(parents=True,exist_ok=True)
    args.report.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'passed':True,'check_count':len(checks)}))


if __name__=='__main__':main()
