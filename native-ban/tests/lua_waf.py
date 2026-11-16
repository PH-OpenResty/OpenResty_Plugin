#!/usr/bin/env python3
"""The retained real Lua WAF reports through native Ban into all BPF nodes."""
import argparse
import json
from pathlib import Path
import shutil
import tempfile
from runtime import ROOT,Test,write

class Review(Test):
    def custom_nginx(self,node,configuration):
        if node!='node-a':return configuration
        root=self.root/node
        if not self.static:
            configuration=f'load_module {self.prefix}/modules/ngx_http_scdn_config_module.so;\n'+configuration
            configuration=configuration.replace(f'load_module {self.prefix}/modules/ngx_http_scdn_sync_module.so;',
                '\n'.join(f'load_module {self.prefix}/modules/ngx_http_scdn_{name}_module.so;' for name in ('api','edge','sync')))
        configuration=configuration.replace('thread_pool scdn_sync_ban', 'thread_pool scdn_config_reader threads=1 max_queue=2;\nthread_pool scdn_sync_ban')
        config=root/'sites.conf'
        write(config,f'sites {{ site lua-site {{ host www.example.test; root {root}/html; cache off; waf on; waf_group sqli; rate_limit off; }} }}',0o644)
        directives=f'''scdn_config_zone cfg 128k; scdn_config_watch {config}; scdn_edge_zone counters 2m;
            lua_package_path "{self.root}/lua/?.lua;;"; lua_shared_dict ratelimit_dict 1m;
            server {{ listen 8082; scdn_edge on; scdn_ban on; scdn_ban_scope $scdn_edge_site;
                access_by_lua_block {{ require("lib.security_guard").run() }}
                location / {{ root $scdn_edge_root; }} }}'''
        return configuration.replace('http { access_log off;', 'http { access_log off; '+directives)

    def run(self):
        self.setup()
        shutil.copytree(ROOT/'native-sync/tests/fixtures/legacy-security',self.root/'lua')
        shutil.copyfile(ROOT/'compat/lua/lib/security_guard.lua',self.root/'lua/lib/security_guard.lua')
        for node,(ns,config) in self.configs.items():
            config['trusted_rules'].append({'source':'waf','reason':'942100'})
            index={'authority':10,'node-a':11,'node-b':12}[node]
            config['services'].append({'ip':f'192.0.2.{index}','protocol':'tcp','port':8082})
            write(self.root/node/'policy.json',json.dumps(config))
            self.launch_agent(node)
        for node in self.configs:self.launch_nginx(node)
        self.until(lambda:self.status('authority')['cluster_state']=='ALL_APPLIED','initial cluster')
        self.until(lambda:self.request('node-a',port=8082)[0]==200,'native policy and retained Lua')
        self.check('retained Lua WAF and native Ban admit ordinary traffic',True)
        self.check('actual retained WAF rule rejects SQL injection',self.request('node-a','/?q=union%20select%20password%20from%20users',port=8082)[0]==403)
        self.until(lambda:any(r['layer']==7 and r['reason']=='942100' and r['scope']=='lua-site' for r in self.records('node-a')),'WAF rule evidence')
        self.check('security_guard submits the actual rule ID and native site scope',True)
        for _ in range(4):self.request('node-a',port=8082)
        self.until(lambda:all(self.request(node)[0]==0 for node in self.configs),'real WAF to cluster BPF')
        self.check('retained WAF plus repeated L7 hits produces real L3 DROP on every node',True)
        return self.checks

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--prefix',required=True,type=Path);parser.add_argument('--agent-build',required=True,type=Path);parser.add_argument('--static',action='store_true');parser.add_argument('--report',type=Path,required=True);args=parser.parse_args()
    prefix=args.prefix/'nginx' if (args.prefix/'nginx/sbin/nginx').exists() else args.prefix
    with tempfile.TemporaryDirectory(prefix='ban-lua-waf-') as directory:
        root=Path(directory);root.chmod(0o755);review=Review(root,prefix,args.agent_build,args.static)
        try:
            checks=review.run();args.report.write_text(json.dumps({'passed':len(checks),'checks':checks},indent=2)+'\n')
        except Exception:
            for path in root.rglob('*.txt'):print(path.parent.name,path.name,path.read_text(errors='replace')[-5000:].replace(review.token,'[redacted]'))
            raise
        finally:review.close()

if __name__=='__main__':main()
