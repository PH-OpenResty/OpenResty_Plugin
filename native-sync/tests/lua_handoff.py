#!/usr/bin/env python3
"""Native Sync/Edge owns site/TLS, while unchanged Lua WAF/rate engines still run."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
from cryptography.hazmat.primitives import hashes
from distribution import Review as DistributionReview, identity

ROOT = Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('handoff',ROOT/'tools/stage-lua-handoff.py')
handoff=importlib.util.module_from_spec(spec);spec.loader.exec_module(handoff)


class Review(DistributionReview):
    def __init__(self, root, prefix, static):
        self.policy = 'waf on; waf_threshold 5; waf_group sqli; rate_limit off;'
        super().__init__(root,prefix,static)
        self.luajit = prefix.parent/'luajit/bin/luajit'
        legacy=root/'legacy';shutil.copytree(ROOT/'native-sync/tests/fixtures/legacy-security',legacy)
        self.legacy=legacy;self.lua=root/'lua'
        for name in handoff.RETIRED:
            for suffix in ['.lua','.ljbc']:
                target=legacy/(name+suffix);target.parent.mkdir(parents=True,exist_ok=True)
                target.write_text('error("retired implementation must not run")')
        (legacy/'lib/customer.lua').write_text('return {retained=true}\n')
        originals={str(p.relative_to(legacy)):hashlib.sha256(p.read_bytes()).hexdigest() for p in legacy.rglob('*') if p.is_file()}
        staged=handoff.stage(legacy,self.lua,self.luajit)
        self.check('staging leaves the original Lua tree byte-for-byte unchanged', originals ==
            {str(p.relative_to(legacy)):hashlib.sha256(p.read_bytes()).hexdigest() for p in legacy.rglob('*') if p.is_file()})
        self.check('only native-owned implementations and their bytecode are retired',
            all(not (self.lua/(name+suffix)).exists() for name in handoff.RETIRED for suffix in ['.lua','.ljbc'])
            and (self.lua/'lib/customer.lua').read_bytes()==(legacy/'lib/customer.lua').read_bytes())
        self.check('WAF, limiter and rule engine sources are preserved unchanged',all(
            (self.lua/p).read_bytes()==(legacy/p).read_bytes() for p in staged['retained_files']))

    def sites(self, origin=0, extra='', enabled='on'):
        static_root=self.root/'static';static_root.mkdir(exist_ok=True)
        (static_root/'fixture.txt').write_text('native-authorized-subrequest')
        extra += f' site static_fixture {{host static.example.test; root {static_root}; cache off; waf on; waf_group sqli;}}'
        text=super().sites(origin,extra,enabled)
        return text.replace('site alpha {','site alpha { '+self.policy)

    def config(self,name,directives,servers):
        if name.startswith('node-'):
            servers=servers.replace(f'root {self.root};', 'root $scdn_edge_root;')
            directives += '\n' + (ROOT/'compat/examples/security-http.conf').read_text().replace('/etc/scdn-node/lua',str(self.root/'lua')).replace('64m','1m')
            servers=servers.replace('scdn_edge_tls on;', 'scdn_edge_tls on; scdn_edge_tls_fallback on;')
            servers=servers.replace('location @scdn_edge_proxy {', '''location = /internal-security {
                content_by_lua_block { local reply=ngx.location.capture("/fixture.txt"); ngx.status=reply.status; ngx.print(reply.body) }
            }
            location @scdn_edge_proxy {''')
            if name=='node-a':
                servers=servers.replace('scdn_edge on;', 'scdn_edge on;\n' + (ROOT/'compat/examples/security-server.conf').read_text())
        return super().config(name,directives,servers)

    def run(self):
        self.start(); initial=self.applied();self.applied(1)
        self.check('new native-synchronized Host works without any Lua registry',self.call(0)[2]==b'a:/asset')
        self.check('Lua WAF blocks SQL injection using the native request policy',self.call(0,'/?q=union%20select%20password%20from%20users')[0]==403)
        self.check('same-site internal subrequest inherits the verified native policy',
            self.call(0,'/internal-security',host='static.example.test')[2]==b'native-authorized-subrequest')
        self.check('native security gate fails closed when the Lua adapter is absent',self.call(1)[0]==503)
        self.check('native TLS serves the synchronized certificate without Lua SNI',self.call(0,tls=True)[3]==self.site_cert.fingerprint(hashes.SHA256()).hex())
        # Unknown SNI completes with the configured bootstrap identity. HTTP Host
        # admission still rejects it; no insecure client acceptance is claimed.
        context=ssl.create_default_context(cafile=str(self.root/'ca.crt'));context.check_hostname=False
        with context.wrap_socket(socket.create_connection(('127.0.0.1',self.tls_ports[0]),timeout=5),server_hostname='unknown.example.test') as conn:
            conn.sendall(b'GET / HTTP/1.0\r\nHost: unknown.example.test\r\n\r\n')
            response=conn.recv(4096)
        self.check('native default TLS fallback retains unknown Host rejection',b' 403 ' in response)
        self.policy='waf off; rate_limit off;'
        self.update(self.sites(extra=f'site newly_added {{host new.example.test; upstream http://127.0.0.1:{self.origins[0].server_port}; cache off; waf on; waf_group sqli;}}'))
        off=self.applied(after=int(initial['sequence']))
        self.check('native policy disable takes effect without updating Lua data files',self.call(0,'/?q=union%20select%20password%20from%20users')[0]==200)
        self.check('new site is admitted and protected by retained WAF immediately',self.call(0,host='new.example.test')[0]==200 and
            self.call(0,'/?q=union%20select%20password%20from%20users',host='new.example.test')[0]==403)
        self.policy='waf off; rate_limit 1 0;'
        self.update(self.sites());rate=self.applied(after=int(off['sequence']))
        statuses=[self.call(0)[0] for _ in range(6)]
        self.check('retained rate limiter uses synchronized policy and returns 429',200 in statuses and 429 in statuses)
        self.check('deleted native Host cannot survive in a Lua registry',self.call(0,host='new.example.test')[0]==403)
        self.policy='waf on; waf_group missing_fixture_group; rate_limit off;'
        self.update(self.sites());missing=self.applied(after=int(rate['sequence']))
        self.check('missing retained WAF rules fail closed instead of silently disabling protection',self.call(0)[0]==503)
        self.policy='waf on; waf_threshold 5; waf_group sqli; rate_limit off;'
        self.update(self.sites());current=self.applied(after=int(missing['sequence']))
        _,rotated=identity(self.root,'rotated-business',self.ca_key,self.ca,server=True)
        (self.root/'business.crt').write_bytes((self.root/'rotated-business.crt').read_bytes())
        (self.root/'business.key').write_bytes((self.root/'rotated-business.key').read_bytes())
        self.applied(after=int(current['sequence']))
        self.check('native certificate rotation works with retained Lua WAF',self.call(0,tls=True)[3]==rotated.fingerprint(hashes.SHA256()).hex())
        # Exercise the one-time converter, including existing source Host/SNI.
        legacy=self.root/'trusted-site.lua'
        legacy.write_text(f'''return {{name="converted",server_names={{"converted.example.test"}},upstream="127.0.0.1:{self.origins[0].server_port}",
origin_host="origin.example.test",cache={{layer="l2"}},waf={{enabled=true,groups={{"sqli","xss"}},threshold=7}},
rate_limit={{enabled=true,req_per_sec=12,burst=3}},locations={{{{prefix="/assets/",upstream="127.0.0.1:{self.origins[0].server_port}",origin_host="assets.example.test",cache="l1"}}}}}}''')
        converted=subprocess.check_output([str(self.luajit),str(ROOT/'compat/lua/export_sites.lua'),str(legacy)],text=True)
        self.check('conversion retains security policy and origin Host overrides',all(x in converted for x in
            ['waf on;','waf_threshold 7;','waf_group "sqli";','rate_limit 12 3;','origin_host "origin.example.test";','origin_host "assets.example.test";']))
        self.update(converted);self.applied(after=int(self.state()['sequence']))
        self.check('converted native source publishes successfully and protects the new Host',self.call(0,host='converted.example.test')[0]==200 and
            self.call(0,'/?q=union%20select%20password%20from%20users',host='converted.example.test')[0]==403)
        baseline=self.state()['sequence']
        for index,invalid in enumerate(['waf on;','waf on; waf_group ../sqli;','waf off; waf off;','waf_threshold 0;','rate_limit 0 1;','rate_limit 3 -1;']):
            self.policy=invalid;self.update(self.sites())
            self.until(lambda:self.state(master=True)['sync_state']=='source_rejected','invalid security policy')
            self.check('invalid security policy cannot replace the active version: '+invalid,self.state()['sequence']==baseline)
            # Return to a known good source between cases so rejection is fresh.
            self.update(converted + f'\n# boundary reset {index}\n')
            baseline=self.applied(after=int(baseline))['sequence']
        self.check('native-owned Lua implementations were not regenerated',not (self.lua/'lib/registry.lua').exists() and not (self.lua/'lib/sni.lua').exists())
        return self.checks


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--prefix',type=Path,required=True)
    p.add_argument('--static',action='store_true');p.add_argument('--report',type=Path);args=p.parse_args()
    prefix=args.prefix/'nginx' if (args.prefix/'nginx/sbin/nginx').exists() else args.prefix
    with tempfile.TemporaryDirectory(prefix='lua-handoff-test-') as temporary:
        review=Review(Path(temporary),prefix,args.static)
        try:
            checks=review.run()
            if args.report:args.report.write_text(json.dumps({'passed':len(checks),'checks':checks},indent=2)+'\n')
            print(f'{len(checks)} native/Lua handoff checks passed',flush=True)
        except Exception:
            for path in review.root.glob('node-*/error.log'):print(path.read_text()[-5000:],flush=True)
            raise
        finally:review.close()


if __name__=='__main__':main()
