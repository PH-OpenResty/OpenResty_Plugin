#!/usr/bin/env python3
"""Real volatile Node restart, IPC resequencing and authoritative resync."""
import argparse
import json
import os
from pathlib import Path
import tempfile

from runtime import Test as BaseTest, command
from integration import write

class Test(BaseTest):
    def custom_nginx(self,node,configuration):
        text=super().custom_nginx(node,configuration)
        return text.replace('worker_processes 2;','worker_processes 1;') if node=='node-a' else text

    def run(self):
        self.setup()
        ns,config=self.configs['node-a']
        config['storage']={'mode':'memory'}
        write(self.root/'node-a/policy.json',json.dumps(config))
        for node in self.configs:self.launch_agent(node)
        for node in self.configs:self.launch_nginx(node)
        self.until(lambda:all(self.request(n)[0]==200 for n in self.configs),'initial live snapshot')
        self.check('volatile Node reports memory mode and no disk durability',self.status('node-a')['storage']['mode']=='memory'
            and self.status('node-a')['storage']['durable']==0)
        self.check('authority retains persistent storage',self.status('authority')['storage']['mode']=='persistent')
        state=self.root/'node-a/state'
        self.check('volatile Node has no AOF or checkpoint files',not list(state.glob('ban-store*')))
        self.check('WAF creates a local volatile L7 decision',self.request('node-a','/waf')[0]==403)
        first=self.until(lambda:next((r for r in self.records('node-a') if r['ip']=='192.0.2.100' and r['layer']==7),None),'initial L7')
        entries=self.status('node-a')['storage']['entries']
        self.request('node-a','/waf')
        # One Worker and a second accepted event prove it consumed the first
        # ACK. An unknown producer cannot accidentally resume at sequence one.
        self.until(lambda:self.status('node-a')['storage']['entries']>=entries+3,'second event from existing producer')
        workers=command('ip','netns','exec',ns,'pgrep','-P',str(self.nginx['node-a'].pid)).split()
        self.agents['node-a'].terminate();self.agents['node-a'].wait(timeout=8);self.launch_agent('node-a')
        self.until(lambda:self.status('node-a')['cluster_revision']!='0' and self.request('node-a')[0]==200,'memory reset and authoritative resync')
        self.check('local volatile L7 state is intentionally absent after restart',not any(r['ban_id']==first['ban_id'] for r in self.records('node-a')))
        self.check('Nginx workers survive the volatile store reset',command('ip','netns','exec',ns,'pgrep','-P',str(self.nginx['node-a'].pid)).split()==workers)
        self.request('node-a','/waf')
        second=self.until(lambda:next((r for r in self.records('node-a') if r['ip']=='192.0.2.100' and r['layer']==7),None),'resequence existing worker producer')
        self.check('existing Worker producer resumes without a sequence gap',second['ban_id']!=first['ban_id'])
        self.check('volatile audit sessions retain their separate history',bool(list((self.root/'node-a/logs').glob('*.session-*.jsonl'))))
        self.request('node-b','/cc')
        self.until(lambda:all(any(r['layer']==3 and r['ip']=='192.0.2.100' for r in self.records(n)) for n in self.configs),'global L3')
        previous=next(r for r in self.records('node-a') if r['layer']==3 and r['ip']=='192.0.2.100')
        self.agents['node-a'].terminate();self.agents['node-a'].wait(timeout=8);self.launch_agent('node-a')
        restored=self.until(lambda:next((r for r in self.records('node-a') if r['layer']==3 and r['ip']=='192.0.2.100'),None),'global snapshot restores volatile Node')
        self.check('fresh Master snapshot restores global IPs after memory loss',restored['ban_id']==previous['ban_id'])
        self.check('resync preserves the original fixed expiry',restored['expires']==previous['expires'])
        self.check('restored IP is enforced by the real Node kernel',self.request('node-a')[0]==0)
        self.agents['authority'].terminate();self.agents['authority'].wait(timeout=8)
        self.agents['node-a'].terminate();self.agents['node-a'].wait(timeout=8);self.launch_agent('node-a')
        import time
        time.sleep(2.2)
        self.check('offline volatile restart keeps the original pinned kernel protection',self.status('node-a')['cluster_revision']=='0' and self.request('node-a')[0]==0)
        self.launch_agent('authority')
        current=self.until(lambda:next((r for r in self.records('node-a') if r['layer']==3 and r['ip']=='192.0.2.100'),None),'authority returns after volatile reset')
        self.check('authority recovery restores the same ban and absolute expiry',current['ban_id']==previous['ban_id'] and current['expires']==previous['expires'])
        self.check('volatile mode still writes no state journal after resync',not list(state.glob('ban-store*')))
        authority=json.loads(json.dumps(self.configs['authority'][1]));authority['storage']={'mode':'memory'}
        write(self.root/'invalid-authority.json',json.dumps(authority))
        import subprocess
        check=subprocess.run([str(self.build/'scdn-ban-agent'),'--config',str(self.root/'invalid-authority.json'),'--check'],capture_output=True,text=True)
        self.check('authority configuration rejects loss of its monotonic history',check.returncode!=0 and 'authority_requires_persistent_storage' in check.stderr)
        process=self.agents['node-a'];process.terminate();process.wait(timeout=8)
        legacy=state/'state.sqlite';legacy.write_bytes(b'preserved legacy fixture');legacy.chmod(0o600)
        check=subprocess.run(['ip','netns','exec',ns,str(self.build/'scdn-ban-agent'),'--config',str(self.root/'node-a/policy.json')],capture_output=True,text=True,timeout=5)
        self.check('legacy state is rejected without silently overwriting or deleting it',check.returncode!=0
            and 'legacy_state_requires_offline_migration' in check.stderr and legacy.read_bytes()==b'preserved legacy fixture')
        return self.checks

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--prefix',required=True,type=Path)
    parser.add_argument('--agent-build',required=True,type=Path);parser.add_argument('--static',action='store_true');parser.add_argument('--report',type=Path)
    args=parser.parse_args()
    if os.geteuid()!=0:raise SystemExit('real kernel checks require root')
    prefix=args.prefix/'nginx' if (args.prefix/'nginx/sbin/nginx').exists() else args.prefix
    with tempfile.TemporaryDirectory(prefix='ban-memory-') as directory:
        root=Path(directory);root.chmod(0o755);test=Test(root,prefix,args.agent_build,args.static)
        try:
            checks=test.run()
            if args.report:args.report.write_text(json.dumps(dict(passed=len(checks),checks=checks),indent=2)+'\n')
        except Exception:
            for path in root.rglob('*-output.txt'):print(path.read_text(errors='replace')[-5000:].replace(test.token,'[redacted]'))
            raise
        finally:test.close()

if __name__=='__main__':main()
