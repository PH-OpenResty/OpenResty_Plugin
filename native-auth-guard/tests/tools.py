#!/usr/bin/env python3
"""Snapshot authentication/faults and real pinned upstream patch applicability."""
import argparse
import concurrent.futures
from email.message import Message
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import urllib.request
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def module(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--report',type=Path,required=True)
    parser.add_argument('--upstream-root',type=Path);parser.add_argument('--gofmt',default=shutil.which('gofmt'))
    args=parser.parse_args();checks=[]
    def check(name,value):assert value,name;checks.append(name)
    def rejects(name,callback):
        try:callback()
        except (ValueError,OSError,KeyError):checks.append(name);return
        raise AssertionError(name)
    tool=module('snapshot_policy','native-auth-guard/tools/snapshot_policy.py')
    adapter=module('prepare_upstream','native-auth-guard/adapters/prepare_upstream.py')
    policy={'adapter':'sub2api','revision':'fixture-v1','registration_enabled':True,'email_verify_enabled':True,
        'strict_email':True,'precreate_required':True,'email_alias_restriction':False,'allowed_domains':['example.com'],'denied_domains':[]}
    with tempfile.TemporaryDirectory(prefix='auth-tools-') as directory:
        root=Path(directory);key=os.urandom(32);key_file=root/'realm.key';key_file.write_bytes(key);key_file.chmod(0o600)
        check('private binary realm key is read without transformation',tool.read_key(key_file)==key)
        key_file.write_bytes(key.hex().encode()+b'\n');check('private hex realm key is supported',tool.read_key(key_file)==key)
        if os.name=='posix':
            key_file.chmod(0o644);rejects('group/world readable key is refused',lambda:tool.read_key(key_file));key_file.chmod(0o600)
        check('exact and wildcard domains are retained',tool.domains(['example.com','*.enterprise.example'])==['*.enterprise.example','example.com'])
        for value in (['*'],['com'],['example.com/evil'],['example.com\n'],['☃.example'],['a..example']):
            rejects('invalid domain list '+repr(value),lambda value=value:tool.domains(value))
        for flag in ('strict_email','precreate_required'):
            rejects(flag+' cannot silently weaken registration',lambda flag=flag:tool.normalize_policy({**policy,flag:False},'sub2api'))
        empty=tool.normalize_policy({**policy,'allowed_domains':[]},'sub2api')
        check('empty upstream allowlist stays empty instead of allow-all',not empty['allowed_domains'])
        config={'version':1,'node_id':'edge-a','password_file':'/etc/scdn/weak.sha256','realms':[
            {'id':'one','adapter':'sub2api','key_file':str(key_file),'exporter_url':'http://127.0.0.1/policy'}]}
        value=tool.snapshot(config,lambda *_:policy)
        check('snapshot includes minimal typed settings and freshness',value['realms'][0]['checked_at']>0 and 'exporter_url' not in value['realms'][0])
        rejects('duplicate realms are refused',lambda:tool.snapshot({**config,'realms':config['realms']*2},lambda *_:policy))
        output=root/'snapshot.json';output.write_bytes(b'old snapshot')
        with patch.object(tool.os,'fsync',side_effect=OSError('fixture disk failure')):
            rejects('pre-rename disk failure is surfaced',lambda:tool.atomic_write(output,value))
        check('failed durable write preserves the last published snapshot',output.read_bytes()==b'old snapshot')
        tool.atomic_write(output,value);check('atomic publication contains complete valid JSON',json.loads(output.read_bytes())==value)
        class Response:
            status=200
            def __enter__(self):return self
            def __exit__(self,*_):pass
            def read(self,_):return json.dumps(policy).encode()
        class Opener:
            stale=False
            def open(self,request,**_):
                response=Response();response.headers=Message()
                stamp=request.get_header('X-scdn-auth-time');nonce=request.get_header('X-scdn-auth-nonce')
                binding=(stamp+'\n'+nonce+'\none').encode()
                if self.stale:binding=b'old-request-binding'
                response.headers['X-SCDN-Auth-Policy']=tool.mac(key,'policy-response',binding+b'\n'+response.read(0))
                return response
        opener=Opener();check('response MAC is tied to this fetch nonce',tool.fetch('http://127.0.0.1/policy','one',key,opener)==policy)
        opener.stale=True;rejects('old signed policy cannot appear fresh',lambda:tool.fetch('http://127.0.0.1/policy','one',key,opener))
        for url in ('http://example.com/policy','https://'+'user:credential@'+'example.com/policy','https://example.com/policy?key=value'):
            rejects('unsafe exporter URL '+url.split(':')[0],lambda url=url:tool.fetch(url,'one',key,opener))
        locks=json.loads((ROOT/'native-auth-guard/adapters/upstream-lock.json').read_text())
        for application,lock in locks.items():
            source=root/application;source.mkdir()
            def acquire(item):
                path=item['path']
                if args.upstream_root:
                    raw=(args.upstream_root/application/path).read_bytes()
                else:
                    with urllib.request.urlopen(f"https://raw.githubusercontent.com/{lock['repository']}/{lock['commit']}/{path}",timeout=30) as response:raw=response.read(1<<20)
                target=source/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:list(pool.map(acquire,lock['files']))
            prepared=adapter.prepare(application,source,args.gofmt)
            patch_path=root/(application+'.patch');patch_path.write_bytes(prepared.encode())
            # Give git a standalone disposable index so no parent checkout can
            # change path interpretation or cause ignored fixture paths to skip.
            subprocess.run(['git','init','-q',str(source)],check=True)
            result=subprocess.run(['git','apply','--check',str(patch_path)],cwd=source,capture_output=True,text=True)
            check(application+' patch applies to actual fixed upstream source',result.returncode==0)
            check(application+' patch contains a real pre-insert application hook','authguard.RequireCreate(' in prepared)
            check(application+' application key is configured through files only','SCDN_AUTH_GUARD_CONFIG' in prepared and 'RootAuth' not in prepared)
            target=source/lock['files'][0]['path'];target.write_bytes(target.read_bytes()+b'\n// divergent checkout\n')
            rejects(application+' divergent source is not patched',lambda:adapter.prepare(application,source,args.gofmt))
    result={'passed':True,'check_count':len(checks),'checks':checks,'upstream_application_build':False,'upstream_deployed':False}
    args.report.parent.mkdir(parents=True,exist_ok=True);args.report.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'passed':True,'check_count':len(checks)}))


if __name__=='__main__':main()
