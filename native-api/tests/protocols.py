#!/usr/bin/env python3
"""Real proxy transport for tool calls, signatures, media and explicit aliases."""
import argparse
import base64
import hashlib
import http.client
import io
import json
from pathlib import Path
import random
import subprocess
import tempfile
import threading
from urllib.parse import urlsplit

from PIL import Image
import integration as fixture


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--prefix', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--static', action='store_true')
    args = parser.parse_args()
    output = io.BytesIO()
    Image.frombytes('RGB',(1024,1024),random.Random(7318).randbytes(1024*1024*3)).save(output,'PNG')
    png = output.getvalue()
    encoded = base64.b64encode(png).decode()
    documents = {
        'responses': {'output':[{'type':'function_call','id':'fc_opaque','call_id':'call_opaque',
            'name':'weather','arguments':'{"city":"上海"}'},{'type':'unknown_future_tool','signature':'opaque+/='}],
            'usage':{'input_tokens':4,'output_tokens':7},'future':{'unchanged':True}},
        'chat': {'choices':[{'index':0,'message':{'role':'assistant','tool_calls':[
            {'id':'call_a','type':'function','function':{'name':'a','arguments':'{"x":1}'}},
            {'id':'call_b','type':'function','function':{'name':'b','arguments':'{"x":2}'}}]},'finish_reason':'tool_calls'}]},
        'gemini': {'candidates':[{'content':{'role':'model','parts':[{'functionCall':{'name':'a','id':'g_a','args':{'x':1}},
            'thoughtSignature':'opaque-signature+/='}]},'finishReason':'STOP'}],'usageMetadata':{'totalTokenCount':9}},
        'messages': {'type':'message','content':[{'type':'thinking','thinking':'fixture','signature':'opaque-thinking'},
            {'type':'tool_use','id':'tool_a','name':'a','input':{'x':1}}],'stop_reason':'tool_use'},
        'images': {'data':[{'b64_json':encoded}]},
    }
    wire = {name: json.dumps(value,ensure_ascii=False,separators=(',',':')).encode() for name,value in documents.items()}
    events = {
        'responses': [{'type':'response.output_item.added','item':documents['responses']['output'][0]},
            {'type':'response.function_call_arguments.delta','call_id':'call_opaque','delta':'{"city":"'},
            {'type':'response.function_call_arguments.delta','call_id':'call_opaque','delta':'上海"}'},
            {'type':'future.unknown','opaque':'signature'},{'type':'response.completed','response':documents['responses']}],
        'chat': [{'choices':[{'delta':{'tool_calls':[{'index':0,'id':'call_a','function':{'name':'a','arguments':'{"x":'}}]}}]},
            {'choices':[{'delta':{'tool_calls':[{'index':0,'function':{'arguments':'1}'}}]},'finish_reason':'tool_calls'}]},
            {'choices':[],'usage':{'total_tokens':11}}],
        'gemini': [documents['gemini'], {'candidates':[{'content':{'parts':[{'inlineData':{'mimeType':'image/png','data':base64.b64encode(png[:40]).decode()}}]}}]}],
        'messages': [{'type':'content_block_start','index':1,'content_block':{'type':'tool_use','id':'tool_a','name':'a','input':{}}},
            {'type':'content_block_delta','index':1,'delta':{'type':'input_json_delta','partial_json':'{"x":'}},
            {'type':'content_block_delta','index':1,'delta':{'type':'input_json_delta','partial_json':'1}'}},
            {'type':'content_block_stop','index':1},{'type':'message_stop'}],
    }
    for name, values in events.items():
        wire[name+'-sse'] = b''.join(('event: '+item.get('type','message')+'\r\ndata: '+
            json.dumps(item,ensure_ascii=False)+'\r\n\r\n').encode() for item in values)+b'data: [DONE]\n\n'
    seen = threading.Event()
    original = fixture.Origin
    class Origin(original):
        def respond(self):
            case = self.headers.get('X-Wire-Fixture')
            if case not in wire:
                return super().respond()
            if self.headers.get('Transfer-Encoding','').lower()=='chunked':
                chunks=[]
                while True:
                    size=int(self.rfile.readline().split(b';',1)[0],16)
                    if not size:
                        while self.rfile.readline() not in (b'\r\n',b'\n',b''):pass
                        break
                    chunks.append(self.rfile.read(size));assert self.rfile.read(2)==b'\r\n';seen.set()
                body=b''.join(chunks)
            else:
                length=int(self.headers.get('Content-Length','0'))
                body=self.rfile.read(min(length,65536));seen.set();body+=self.rfile.read(length-len(body))
            result=wire[case]
            self.send_response(200)
            self.send_header('Content-Type','text/event-stream' if case.endswith('-sse') else 'application/json')
            self.send_header('Content-Length',str(len(result)))
            self.send_header('X-Request-Hash',hashlib.sha256(body).hexdigest())
            self.end_headers()
            # HTTP segment boundaries deliberately cut UTF-8 and JSON escapes.
            size=7 if case.endswith('-sse') else 65536
            for offset in range(0,len(result),size):
                self.wfile.write(result[offset:offset+size]);self.wfile.flush()
        do_POST=respond
        do_GET=respond
    fixture.Origin=Origin
    rules='''scdn_api_endpoint responses POST /scoped-responses plain;
 scdn_api_endpoint responses POST /scoped-responses/compact plain;
 scdn_api_endpoint responses GET /v1/responses/* plain;
 scdn_api_endpoint images POST /images/edits plain;
 scdn_api_endpoint images POST /v1/images/edits/async plain;
 scdn_api_endpoint images GET /v1/images/tasks/* plain;
 scdn_api_endpoint generic POST /vendor/* plain;
 scdn_api_endpoint messages POST /vendor/messages plain;'''
    rules+='\n scdn_api_endpoint responses POST /maximum-site '+('A'*96)+';'
    class Review(fixture.Review):
        def sites(self,origin_host='model.example.test'):
            extra='site '+('A'*96)+' { host maximum-site.example.test; upstream http://pooled-origin; cache off; }\n'
            return super().sites(origin_host).replace('site plain',extra+'site plain',1)
        def config(self):
            return super().config().replace('client_body_buffer_size 32k;',
                'client_body_buffer_size 32k; client_max_body_size 16m;').replace(
                'scdn_api_zone api_counters 64k;','scdn_api_zone api_counters 64k;\n '+rules).replace(
                'add_header X-Kind','add_header X-Protocol $scdn_api_protocol always;\n  add_header X-Kind')
    checks=[]
    def check(name,value):
        assert value,name
        checks.append(name)
    with tempfile.TemporaryDirectory(prefix='api-protocols-') as directory:
        review=Review(Path(directory),args.prefix,args.static)
        try:
            review.start()
            paths={'responses':'/v1/responses','chat':'/v1/chat/completions',
                   'gemini':'/v1beta/models/example:streamGenerateContent?alt=sse','messages':'/v1/messages'}
            for name,path in paths.items():
                for streaming in (False,True):
                    case=name+('-sse' if streaming else '')
                    # Contains tool results and opaque fields; larger than inspect budget.
                    body=json.dumps({'model':'fixture','input':[{'type':'function_call_output','call_id':'call_opaque',
                        'output':{'signature':'keep+/=','text':'x'*80000}}],'messages':[{'role':'tool','tool_call_id':'call_a','content':'ok'}],
                        'contents':[{'parts':[{'functionResponse':{'id':'g_a','name':'a','response':{'ok':True}},'thoughtSignature':'keep+/='}]}],
                        'unknown_future':{'value':1}}).encode()
                    status,headers,data=review.request(path,'POST',body,{'X-Wire-Fixture':case,'Content-Type':'application/json','Accept-Encoding':'gzip'})
                    check(case+' AI protocol selected before body inspection',status==200 and headers.get('x-kind')=='ai' and headers.get('x-protocol')==name)
                    check(case+' exact raw output including unknown fields and signatures',data==wire[case])
                    check(case+' exact tool result input',headers.get('x-request-hash')==hashlib.sha256(body).hexdigest())
                    check(case+' uncached uncompressed',headers.get('x-skip')=='1' and not headers.get('content-encoding'))
            upload=b'--fixture\r\nContent-Disposition: form-data; name="image"; filename="fixture.png"\r\nContent-Type: image/png\r\n\r\n'+png+b'\r\n--fixture--\r\n'
            for path in ('/v1/images/generations','/v1/images/edits','/v1/images/variations','/prefix/v1/images/edits?size=large'):
                status,headers,data=review.request(path,'POST',upload,{'X-Wire-Fixture':'images','Content-Type':'multipart/form-data; boundary=fixture','Accept-Encoding':'gzip'})
                check(path+' selects image AI profile',status==200 and headers.get('x-protocol')=='images' and headers.get('x-kind')=='ai')
                check(path+' multi MiB image JSON exact',data==wire['images'] and not headers.get('content-encoding'))
                check(path+' original multipart upload exact',headers.get('x-request-hash')==hashlib.sha256(upload).hexdigest())
            for chunked in (False,True):
                seen.clear()
                connection=http.client.HTTPConnection('127.0.0.1',review.http,timeout=10)
                connection.putrequest('POST','/v1/images/edits',skip_host=True)
                for key,value in {'Host':'www.example.test','Content-Type':'multipart/form-data; boundary=fixture','X-Wire-Fixture':'images',
                    **({'Transfer-Encoding':'chunked'} if chunked else {'Content-Length':str(len(upload))})}.items():connection.putheader(key,value)
                connection.endheaders()
                first,rest=upload[:128*1024],upload[128*1024:]
                def send(value):connection.send((f'{len(value):x}\r\n'.encode()+value+b'\r\n') if chunked else value)
                send(first);arrived=seen.wait(1)
                send(rest)
                if chunked:connection.send(b'0\r\n\r\n')
                response=connection.getresponse();data=response.read();headers=dict((k.lower(),v) for k,v in response.getheaders());connection.close()
                check('streaming upload reaches origin before finish '+str(chunked),arrived)
                check('streaming upload body exact '+str(chunked),headers.get('x-request-hash')==hashlib.sha256(upload).hexdigest() and data==wire['images'])
            for path,method,protocol in [('/scoped-responses','POST','responses'),('/scoped-responses/compact','POST','responses'),('/images/edits','POST','images'),
                    ('/v1/images/edits/async','POST','images'),('/v1/images/tasks/task_1','GET','images'),
                    ('/v1/responses/resp_1','GET','responses'),('/vendor/messages','POST','messages'),('/vendor/other','POST','generic')]:
                status,headers,_=review.request(path,method,b'opaque' if method=='POST' else None,{'X-Wire-Fixture':'responses','Content-Type':'application/octet-stream'})
                check('registered method/site alias '+path,status==200 and headers.get('x-protocol')==protocol and headers.get('x-reason')=='configured_endpoint')
            status,headers,_=review.request('/maximum-site','POST',b'opaque',{'X-Wire-Fixture':'responses'},host='maximum-site.example.test')
            check('maximum Config site identifier length is supported',status==200 and headers.get('x-protocol')=='responses')
            for path,method,host in [('/scoped-responses','GET','www.example.test'),('/scoped-responses','POST','tls.example.test'),
                    ('/v1/images/edits-extra','POST','www.example.test'),('/vendor','POST','www.example.test')]:
                status,headers,_=review.request(path,method,b'opaque' if method=='POST' else None,{'X-Wire-Fixture':'responses','Content-Type':'application/octet-stream'},host=host)
                check('no overbroad classification '+path+method+host,status==200 and headers.get('x-protocol')=='none' and headers.get('x-kind')!='ai')
            config=review.config()
            for invalid in ('scdn_api_endpoint unknown POST /invalid;', 'scdn_api_endpoint responses BAD /invalid;',
                    'scdn_api_endpoint responses POST /bad*path;', 'scdn_api_endpoint responses POST /scoped-responses plain;',
                    'scdn_api_endpoint responses POST /invalid '+('A'*97)+';'):
                bad=Path(directory)/'invalid.conf';bad.write_text(config.replace('scdn_api_zone api_counters 64k;', 'scdn_api_zone api_counters 64k; '+invalid))
                result=subprocess.run([str(review.nginx),'-t','-p',directory+'/', '-c',str(bad)],capture_output=True)
                check('invalid or ambiguous route rejected '+str(len(checks)),result.returncode!=0 and b'scdn_api_endpoint' in result.stderr)
        finally:
            review.close()
            fixture.Origin=original
    result={'passed':True,'check_count':len(checks),'checks':checks,'png_bytes':len(png),'image_json_bytes':len(wire['images']),
            'real_vendor_api_calls':0,'production_modified':False}
    args.report.parent.mkdir(parents=True,exist_ok=True)
    args.report.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'passed':True,'check_count':len(checks)}))


if __name__=='__main__':main()
