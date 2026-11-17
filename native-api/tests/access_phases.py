#!/usr/bin/env python3
"""Original location access checks precede Edge and standalone API dispatch."""
import argparse
import http.client
import json
from pathlib import Path
import tempfile
import integration as fixture


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--prefix',type=Path,required=True)
    parser.add_argument('--report',type=Path,required=True);parser.add_argument('--static',action='store_true');args=parser.parse_args()
    calls=[]
    original=fixture.Origin
    class Origin(original):
        def respond(self):calls.append(self.path);return super().respond()
        do_GET=respond
        do_POST=respond
    fixture.Origin=Origin
    class Review(fixture.Review):
        def __init__(self,*arguments):
            self.solo=fixture.unused_port();super().__init__(*arguments)
        def config(self):
            text=super().config().replace('  scdn_edge on;','''  scdn_edge on;
  location = /acl { deny all; }
  location = /basic { auth_basic "fixture"; auth_basic_user_file /tmp/scdn-unused-auth-fixture; }
  location = /v1/images/edits { deny all; }''')
            solo=f'''server {{ listen 127.0.0.1:{self.solo}; scdn_api on;
 scdn_api_dynamic_location @solo; scdn_api_ai_location @solo;
 location / {{ scdn_api_dispatch on; deny all; }}
 location = /allowed {{ scdn_api_dispatch on; }}
 location = /basic {{ scdn_api_dispatch on; auth_basic "fixture"; auth_basic_user_file /tmp/scdn-unused-auth-fixture; }}
 location @solo {{ proxy_pass http://127.0.0.1:{self.origins[0].server_port}; proxy_http_version 1.1; }} }}'''
            index=text.rfind('}')
            return text[:index]+solo+'\n'+text[index:]
    checks=[]
    def check(name,value):assert value,name;checks.append(name)
    with tempfile.TemporaryDirectory(prefix='api-access-phases-') as directory:
        review=Review(Path(directory),args.prefix,args.static)
        try:
            review.start();before=len(calls)
            for path,method,expected in [('/acl','GET',403),('/basic','GET',401),('/v1/images/edits','POST',403)]:
                body=b'fixture upload' if method=='POST' else None
                status,_,_=review.request(path,method,body)
                check('Edge preserves entry access '+path,status==expected)
            check('Edge rejected traffic never reaches origin',len(calls)==before)
            for path,expected in [('/v1/responses',403),('/basic',401)]:
                connection=http.client.HTTPConnection('127.0.0.1',review.solo,timeout=5)
                connection.request('POST',path,b'{"model":"fixture","input":"protected"}',{'Content-Type':'application/json'})
                response=connection.getresponse();response.read();connection.close()
                check('standalone API preserves entry access '+path,response.status==expected)
            check('standalone rejected traffic never reaches origin',len(calls)==before)
            connection=http.client.HTTPConnection('127.0.0.1',review.solo,timeout=5)
            body=b'{"model":"fixture","input":"allowed"}'
            connection.request('POST','/allowed',body,{'Content-Type':'application/json'})
            response=connection.getresponse();response.read();connection.close()
            check('standalone allowed API still reaches origin',response.status==200 and calls[-1]=='/allowed')
        except Exception:
            for name in ('error.log','process.log'):
                path=Path(directory)/name
                if path.exists():print(path.read_text(errors='replace')[-4000:])
            raise
        finally:review.close();fixture.Origin=original
    args.report.parent.mkdir(parents=True,exist_ok=True)
    args.report.write_text(json.dumps({'passed':True,'check_count':len(checks),'checks':checks,'production_modified':False},indent=2)+'\n')
    print(json.dumps({'passed':True,'check_count':len(checks)}))


if __name__=='__main__':main()
