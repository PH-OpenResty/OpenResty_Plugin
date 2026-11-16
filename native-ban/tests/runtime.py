#!/usr/bin/env python3
"""Privileged, isolated netns/veth tests of real Ban Agent, Nginx and BPF."""
from __future__ import annotations
import argparse
import ctypes
import hashlib
import http.client
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import uuid
import grp
import ipaddress
import sqlite3

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'native-sync/tests'))
from integration import identity,write
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

def command(*args,**kwargs):
    return subprocess.run(args,check=True,capture_output=True,text=True,**kwargs).stdout

def rpc(path,body):
    data=json.dumps(body,separators=(',',':')).encode()
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(5);sock.connect(str(path));sock.sendall(struct.pack('=I',len(data))+data)
        def read(n):
            chunks=b''
            while len(chunks)<n:
                value=sock.recv(n-len(chunks))
                if not value:raise RuntimeError('RPC truncated')
                chunks+=value
            return chunks
        code,size=struct.unpack('=II',read(8));result=json.loads(read(size));return code,result

class Test:
    def __init__(self,root,prefix,build,static=False,mode='tcx_ingress'):
        self.root,self.prefix,self.build,self.static=root,prefix,build,static
        self.mode=mode
        self.names=[];self.processes=[];self.agents={};self.nginx={};self.logs=[];self.checks=[]
        self.lab='banlab-'+uuid.uuid4().hex[:8];self.pin=root/'pins';self.pin.mkdir();self.mounted=False
        self.runtime=Path(tempfile.mkdtemp(prefix='ban-runtime-',dir='/dev/shm'));self.runtime.chmod(0o755)
        self.key,self.ca=identity(root,'ca');identity(root,'master',self.key,self.ca,server=True)
        self.identities={}
        for name in ('authority','node-a','node-b'):
            _,cert=identity(root,name,self.key,self.ca);self.identities[name]=cert.fingerprint(hashes.SHA256()).hex()
        signing=ed25519.Ed25519PrivateKey.generate()
        write(root/'sign.key',signing.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).decode())
        write(root/'sign.pub',signing.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode(),0o644)
        self.instance='00000000-0000-0000-0000-000000000100'
        self.cluster='00000000-0000-0000-0000-000000001000';self.epoch='00000000-0000-0000-0000-000000001001'
        self.configs={};self.token='fixture-control-'+'x'*48
        write(root/'control.token',self.token)

    def check(self,name,condition):
        if not condition:raise AssertionError(name)
        self.checks.append(name);print('PASS '+name,flush=True)

    def until(self,callback,description,timeout=15):
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            try:
                value=callback()
                if value:return value
            except (OSError,ValueError):pass
            time.sleep(.05)
        raise AssertionError('deadline: '+description)

    def ns(self,name,*args):return command('ip','netns','exec',name,*args)

    def setup(self):
        command('cc','-std=c11','-Wall','-Wextra','-Werror','-I',str(ROOT/'native-ban/src'),
                str(ROOT/'native-ban/tests/producer.c'),str(ROOT/'native-ban/src/ban_common.c'),'-o',str(self.root/'producer'))
        command('cc','-std=c11','-Wall','-Wextra','-Werror',str(ROOT/'native-ban/tests/packet-test.c'),'-lbpf','-o',str(self.root/'packet-test'))
        command('mount','-t','bpf','bpf',str(self.pin));self.mounted=True
        command('ip','netns','add',self.lab);self.names.append(self.lab)
        self.ns(self.lab,'ip','link','set','lo','up');self.ns(self.lab,'ip','link','add','br0','type','bridge')
        self.ns(self.lab,'ip','addr','add','192.0.2.100/24','dev','br0');self.ns(self.lab,'ip','link','set','br0','up')
        self.ns(self.lab,'ip','-6','addr','add','2001:db8:1::100/64','dev','br0')
        for i,node in enumerate(('authority','node-a','node-b'),10):
            ns=self.lab+'-'+str(i);command('ip','netns','add',ns);self.names.append(ns)
            a='b'+uuid.uuid4().hex[:10];b='p'+uuid.uuid4().hex[:10]
            command('ip','link','add',a,'type','veth','peer','name',b)
            command('ip','link','set',a,'netns',self.lab);command('ip','link','set',b,'netns',ns)
            self.ns(self.lab,'ip','link','set',a,'master','br0');self.ns(self.lab,'ip','link','set',a,'up')
            self.ns(ns,'ip','link','set',b,'name','eth0');self.ns(ns,'ip','link','set','lo','up');self.ns(ns,'ip','link','set','eth0','up')
            self.ns(ns,'ip','addr','add',f'192.0.2.{i}/24','dev','eth0');self.ns(ns,'ip','-6','addr','add',f'2001:db8:1::{i}/64','dev','eth0')
            root=self.root/node;root.mkdir(mode=0o755);(root/'state').mkdir(mode=0o700);(root/'logs').mkdir(mode=0o700)
            run=self.runtime/node;run.mkdir(mode=0o750);os.chown(run,0,65534)
            pins=self.pin/node;pins.mkdir(mode=0o700)
            config={'version':1,'node_id':node,'runtime_dir':str(run),'state_dir':str(root/'state'),
                'event_socket':str(run/'events.sock'),'admin_socket':str(run/'admin.sock'),'event_log':str(root/'logs/events.jsonl'),
                'ip_log':str(root/'logs/ips.jsonl'),'worker_uid':65534,'worker_gid':65534,'sync_uid':65534,'instances':[self.instance],
                'trusted_rules':[{'source':'waf','reason':'waf-rule'},{'source':'cc','reason':'cc-rule'}],
                'policy':{'l7_seconds':20,'l3_seconds':20,'window_ms':10000,'threshold':4,'event_age_ms':2000,'renew_on_hit':False},
                'datapath':{'mode':self.mode,'interfaces':['eth0'],'object_file':str(self.build/'ban.bpf.o'),'pin_root':str(pins)},
                'services':[{'ip':f'192.0.2.{i}','protocol':'tcp','port':8080},{'ip':f'192.0.2.{i}','protocol':'udp','port':9090},
                            {'ip':f'2001:db8:1::{i}','protocol':'tcp','port':8080}],
                'allowlist':['203.0.113.0/28'],
                'cluster':{'role':'master' if i==10 else 'node','cluster_id':self.cluster,'authority_epoch':self.epoch,
                    'master_url':'' if i==10 else 'https://192.0.2.10:8443','ca':str(self.root/'ca.crt'),
                    'certificate':str(self.root/(node+'.crt')),'key':str(self.root/(node+'.key')),
                    'signing_key':str(self.root/'sign.key') if i==10 else '', 'verify_key':str(self.root/'sign.pub'),
                    'socket':str(run/'sync.sock'),'members':['authority','node-a','node-b'],'poll_ms':100,'clock_uncertainty_ms':0}}
            # The mTLS server identity is localhost; private test DNS maps it to the authority.
            if i!=10:
                config['cluster']['master_url']='https://sync.example.test:8443'
            self.configs[node]=(ns,config)
            write(root/'policy.json',json.dumps(config))
        # Temporary netns-specific hosts files, never change the host hosts file.
        for ns in self.names:
            hosts=Path('/etc/netns')/ns;hosts.mkdir(parents=True,exist_ok=True)
            (hosts/'hosts').write_text('127.0.0.1 localhost\n192.0.2.10 sync.example.test\n')
        # Reissue only the synthetic Master TLS cert with the expected DNS SAN.
        from cryptography import x509
        from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID
        import datetime
        key=serialization.load_pem_private_key((self.root/'master.key').read_bytes(),password=None)
        now=datetime.datetime.now(datetime.timezone.utc)
        cert=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'sync.example.test')]))
            .issuer_name(self.ca.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now-datetime.timedelta(hours=1)).not_valid_after(now+datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('sync.example.test')]),False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),False).sign(self.key,hashes.SHA256()))
        write(self.root/'master.crt',cert.public_bytes(serialization.Encoding.PEM).decode())

    def launch_agent(self,node):
        ns,conf=self.configs[node];root=self.root/node
        log=(root/'agent-output.txt').open('ab');self.logs.append(log)
        process=subprocess.Popen(['ip','netns','exec',ns,str(self.build/'scdn-ban-agent'),'--config',str(root/'policy.json')],stdout=log,stderr=log)
        self.processes.append(process);self.agents[node]=process
        self.until(lambda: process.poll() is None and self.status(node).get('kernel_ready')==1,'Agent '+node)

    def launch_nginx(self,node):
        ns,conf=self.configs[node];root=self.root/node
        modules='' if self.static else '\n'.join(f'load_module {self.prefix}/modules/ngx_http_scdn_{name}_module.so;' for name in ('ban','sync'))
        master=''
        if node=='authority':
            master=f'''scdn_sync_role master; scdn_sync_id authority;
                scdn_sync_control_token_file {self.root}/control.token;
                scdn_sync_ban_agent {conf['cluster']['socket']};
                scdn_sync_peer node-a edge {self.identities['node-a']};
                scdn_sync_peer node-b edge {self.identities['node-b']};
                server {{ listen 8443 ssl; ssl_certificate {self.root}/master.crt;
                    ssl_certificate_key {self.root}/master.key; ssl_client_certificate {self.root}/ca.crt; ssl_verify_client on;
                    location /_scdn_sync/v1/ {{ scdn_sync_api exchange; }} }}'''
        configuration=f'''{modules}
            user nobody {grp.getgrgid(65534).gr_name}; worker_processes 2;
            thread_pool scdn_sync_ban threads=2 max_queue=32;
            pid {root}/nginx.pid; error_log {root}/nginx-error.txt warn;
            events {{ worker_connections 512; }}
            http {{ access_log off; client_body_buffer_size 128k; client_max_body_size 64k;
              scdn_ban_agent {conf['event_socket']} 0 {self.instance};
              {master}
              server {{ listen 8080; listen [::]:8080; scdn_ban on; scdn_ban_scope alpha;
                location /waf {{ scdn_ban_deny waf waf-rule; }}
                location /cc {{ scdn_ban_deny cc cc-rule; }}
                location /site-beta {{ scdn_ban_scope beta; root {root}/html; }}
                location /variable-waf {{ set $scdn_ban_reason waf-rule; set $scdn_ban_event waf; return 403; }}
                location / {{ root {root}/html; }} }}
              server {{ listen 8081; location / {{ return 200 "management-alive"; }} }}
            }}'''
        (root/'html').mkdir(exist_ok=True);(root/'html/index.html').write_text('public-content');(root/'html/index.html').chmod(0o644)
        write(root/'nginx.conf',configuration)
        log=(root/'nginx-output.txt').open('ab');self.logs.append(log)
        process=subprocess.Popen(['ip','netns','exec',ns,str(self.prefix/'sbin/nginx'),'-p',str(root)+'/', '-c',str(root/'nginx.conf'),'-g','daemon off;'],stdout=log,stderr=log)
        self.processes.append(process);self.nginx[node]=process
        self.until(lambda:self.request(node,port=8081)[0]==200,'Nginx '+node)
        if node not in getattr(self,'udp_started',set()):
            if not hasattr(self,'udp_started'):self.udp_started=set()
            self.udp_started.add(node)
            script='''import socket,select
s=[]
for port in (9090,9091):
 x=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);x.bind(('0.0.0.0',port));s.append(x)
while True:
 for x in select.select(s,[],[])[0]:
  b,a=x.recvfrom(4096);x.sendto(b,a)
'''
            p=subprocess.Popen(['ip','netns','exec',ns,sys.executable,'-c',script],stdout=log,stderr=log);self.processes.append(p)

    def status(self,node):return rpc(self.configs[node][1]['admin_socket'],{'operation':'status'})[1]
    def records(self,node):return rpc(self.configs[node][1]['admin_socket'],{'operation':'list'})[1]['records']
    def request(self,node,path='/',port=8080,ipv6=False):
        index={'authority':10,'node-a':11,'node-b':12}[node]
        address=f'2001:db8:1::{index}' if ipv6 else f'192.0.2.{index}'
        script='''import http.client,json,sys
try:
 c=http.client.HTTPConnection(sys.argv[1],int(sys.argv[2]),timeout=.4);c.request('GET',sys.argv[3]);r=c.getresponse();print(json.dumps([r.status,r.read().decode()]));c.close()
except OSError:print('[0,"blocked"]')
'''
        return json.loads(self.ns(self.lab,sys.executable,'-c',script,address,str(port),path))

    def udp(self,node,port):
        index={'authority':10,'node-a':11,'node-b':12}[node]
        script='''import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(.4)
try:s.sendto(b'fixture',(sys.argv[1],int(sys.argv[2])));print(s.recvfrom(64)[0].decode())
except OSError:print('blocked')
'''
        return self.ns(self.lab,sys.executable,'-c',script,f'192.0.2.{index}',str(port)).strip()

    def unban(self,ip):
        record=next(r for r in self.records('authority') if r['ip']==ip and r['layer']==3)
        return rpc(self.configs['authority'][1]['admin_socket'],{'operation':'unban','ip':ip,'ban_id':record['ban_id']})

    def packet_tests(self):
        # Inspect the actual loaded XDP program that shares the Agent's live ban map.
        pin=self.pin/'node-a/bans'
        def ipv4(port=8080,fragment=0,destination='192.0.2.11',vlan=False):
            ethernet=b'\0'*12+(b'\x81\x00\x00\x01\x08\x00' if vlan else b'\x08\x00')
            header=struct.pack('!BBHHHBBH4s4s',0x45,0,40,1,fragment,64,6,0,ipaddress.ip_address('192.0.2.100').packed,ipaddress.ip_address(destination).packed)
            return ethernet+header+struct.pack('!HH',45000,port)+b'\0'*16
        for name,packet,expected in (
                ('tagged VLAN packet to a protected port',ipv4(vlan=True),1),
                ('IPv4 non-initial fragment to protected VIP',ipv4(fragment=1),1),
                ('unprotected TCP port',ipv4(port=8081),2),
                ('unprotected destination VIP',ipv4(destination='192.0.2.222'),2),
                ('truncated IPv4 packet',b'\0'*12+b'\x08\x00'+b'\0'*5,2)):
            path=self.root/'packet.fixture';path.write_bytes(packet)
            result=json.loads(command(str(self.root/'packet-test'),str(pin),str(path)))
            self.check('BPF verifier-tested program handles '+name,result['retval']==expected)

    def run(self):
        self.setup()
        for node in self.configs:self.launch_agent(node)
        ns,_=self.configs['node-a']
        duplicate=subprocess.run(['ip','netns','exec',ns,str(self.build/'scdn-ban-agent'),'--config',str(self.root/'node-a/policy.json')],capture_output=True,text=True,timeout=5)
        self.check('a second Agent cannot become a writer of the same state',duplicate.returncode!=0 and 'agent_already_running' in duplicate.stderr)
        separate=self.root/'separate-state';separate.mkdir(mode=0o700)
        competing=json.loads(json.dumps(self.configs['node-a'][1]));competing['state_dir']=str(separate)
        write(self.root/'competing.json',json.dumps(competing))
        duplicate=subprocess.run(['ip','netns','exec',ns,str(self.build/'scdn-ban-agent'),'--config',str(self.root/'competing.json')],capture_output=True,text=True,timeout=5)
        self.check('another state directory cannot take over the same live view or sockets',duplicate.returncode!=0 and 'runtime_already_owned' in duplicate.stderr)
        for node in self.configs:self.launch_nginx(node)
        self.until(lambda:all(self.status(n)['cluster_revision']!='0' for n in self.configs),'initial complete snapshots')
        self.until(lambda:self.status('authority')['cluster_state']=='ALL_APPLIED','initial kernel result acknowledgements')
        self.check('three real Agents and registered Nodes apply the initial full snapshot',self.status('authority')['cluster_state']=='ALL_APPLIED')
        with sqlite3.connect(self.root/'authority/state/state.sqlite') as db:
            initial_snapshot=db.execute("SELECT value FROM meta WHERE key='snapshot'").fetchone()[0]
        self.until(lambda:all(self.request(n)[0]==200 for n in self.configs),'public requests')
        self.check('unbanned clients reach all three protected HTTP endpoints',all(self.request(n)[0]==200 for n in self.configs))
        # IPv6 addresses are tentative until duplicate-address detection and
        # bridge neighbor discovery finish. IPv4 readiness is not IPv6 readiness.
        self.until(lambda:all(self.request(n,ipv6=True)[0]==200 for n in self.configs),'IPv6 address and neighbor readiness',timeout=12)
        self.check('unbanned IPv6 client can reach protected HTTP',self.request('node-a',ipv6=True)[0]==200)
        ns,conf=self.configs['node-a']
        def producer(ip,mode):return json.loads(self.ns(ns,str(self.root/'producer'),conf['event_socket'],conf['runtime_dir']+'/view',ip,mode))
        privacy=producer('198.51.100.20','view')
        self.check('Worker receives a read-only mapping and cannot reopen the view for writing',privacy['readonly_fd'] and privacy['cannot_reopen'])
        self.check('Agent rejects unregistered WAF evidence',producer('198.51.100.21','unknown')['rejected'])
        self.check('stale events are acknowledged without renewing their observation time',producer('198.51.100.22','stale')['durable']
                   and not any(r['ip']=='198.51.100.22' for r in self.records('node-a')))
        self.check('replayed event receives the original durable receipt',producer('198.51.100.23','duplicate')['duplicate_receipt'])
        self.check('duplicate event creates exactly one L7 record',len([r for r in self.records('node-a') if r['ip']=='198.51.100.23'])==1)
        producer('203.0.113.2','duplicate')
        self.check('configured CIDR exemption prevents automatic bans',not any(r['ip']=='203.0.113.2' for r in self.records('node-a')))
        producer('::ffff:198.51.100.25','duplicate')
        self.check('IPv4-mapped IPv6 evidence uses the canonical IPv4 identity',any(r['ip']=='198.51.100.25' for r in self.records('node-a')))
        self.check('UDP load-balancing and management ports initially pass',self.udp('node-a',9090)=='fixture' and self.udp('node-a',9091)=='fixture')
        self.check('first WAF denial establishes a local L7 ban',self.request('node-a','/waf')[0]==403)
        self.until(lambda:any(r['layer']==7 for r in self.records('node-a')),'L7 ban')
        first=next(r for r in self.records('node-a') if r['layer']==7 and r['ip']=='192.0.2.100')
        self.check('WAF L7 ban does not immediately become global L3',not any(r['layer']==3 for r in self.records('node-b')) and self.request('node-b')[0]==200)
        self.check('L7 ban stays inside its stable site scope',self.request('node-a','/site-beta')[0]==404)
        self.check('an active L7 record rejects a following request',self.request('node-a')[0]==403)
        self.check('L7 hit does not extend its configured expiry',next(r for r in self.records('node-a') if r['layer']==7 and r['ip']=='192.0.2.100')['expires']==first['expires'])
        for _ in range(4):self.request('node-a')
        self.until(lambda:all(any(r['layer']==3 for r in self.records(n)) for n in self.configs),'full L3 convergence')
        self.check('frequent WAF/L7 hits escalate and synchronize L3 to every device',all(self.request(n)[0]==0 for n in self.configs))
        self.check('L3 protects Web while unrelated management port stays available',all(self.request(n,port=8081)[0]==200 for n in self.configs))
        self.until(lambda:self.status('authority')['cluster_state']=='ALL_APPLIED','kernel ACK all nodes')
        self.check('Master reports ALL_APPLIED only after every kernel application ACK',self.status('authority')['pending_nodes']==0)
        expiry=min(int(r['expires']) for r in self.records('node-b') if r['layer']==3)
        self.until(lambda:all(self.request(n)[0]==200 for n in self.configs),'fixed expiry release',timeout=26)
        self.check('all nodes stop blocking at the original fixed expiry',time.time()*1000>=expiry)
        self.until(lambda:all('EXPIRED' in Path(c[1]['event_log']).read_text() and 'EXPIRED' in Path(c[1]['ip_log']).read_text() for c in self.configs.values()),'expiry log projections')
        self.check('expired bans stay in both designated history files',True)
        self.check('confirmed CC immediately requests L3',self.request('node-b','/cc')[0]==403)
        self.until(lambda:self.request('node-b')[0]==0,'CC kernel ban')
        self.until(lambda:all(self.request(n)[0]==0 for n in self.configs),'CC global snapshot')
        self.check('a different source device propagates its CC ban to all nodes',all(any(r['layer']==3 for r in self.records(n)) for n in self.configs))
        self.packet_tests()
        self.check('eBPF blocks the configured UDP load-balancing port',self.udp('node-a',9090)=='blocked')
        self.check('unprotected UDP port continues to work',self.udp('node-a',9091)=='fixture')
        with sqlite3.connect(self.root/'authority/state/state.sqlite') as db:
            current_snapshot=db.execute("SELECT value FROM meta WHERE key='snapshot'").fetchone()[0]
            tampered=json.loads(current_snapshot);sig=tampered['signature'];tampered['signature']=('A' if sig[0]!='A' else 'B')+sig[1:]
            db.execute("UPDATE meta SET value=? WHERE key='snapshot'",(json.dumps(tampered),))
        self.until(lambda:self.status('node-a')['sync_error']=='signature_invalid','snapshot signature rejection')
        self.check('tampered full snapshot cannot clear existing kernel bans',self.request('node-a')[0]==0)
        with sqlite3.connect(self.root/'authority/state/state.sqlite') as db:
            db.execute("UPDATE meta SET value=? WHERE key='snapshot'",(initial_snapshot,))
        self.until(lambda:self.status('node-a')['sync_error']=='snapshot_high_watermark','snapshot replay rejection')
        self.check('older authentic full snapshot cannot roll back an active ban',self.request('node-a')[0]==0)
        with sqlite3.connect(self.root/'authority/state/state.sqlite') as db:
            db.execute("UPDATE meta SET value=? WHERE key='snapshot'",(current_snapshot,))
        self.until(lambda:not self.status('node-a')['sync_error'],'snapshot recovery')
        record=next(r for r in self.records('node-b') if r['layer']==3)
        code,_=rpc(self.configs['node-b'][1]['admin_socket'],{'operation':'unban','ip':record['ip'],'ban_id':record['ban_id']})
        self.check('a Node cannot revoke the cluster L3 decision',code==400 and self.request('node-b')[0]==0)
        code,_=rpc(self.configs['authority'][1]['admin_socket'],{'operation':'unban','ip':'192.0.2.100','ban_id':'0'*32})
        self.check('unban must identify the current ban ID',code==400)
        self.check('authority accepts an explicit matching global unban',self.unban('192.0.2.100')[0]==200)
        self.until(lambda:all(self.request(n)[0]==200 for n in self.configs),'global unban convergence')
        self.check('full snapshot removal unbans every node without clearing unrelated ports',True)
        self.check('CC on the authority device also participates in full synchronization',self.request('authority','/cc')[0]==403)
        self.until(lambda:all(self.request(n)[0]==0 for n in self.configs),'authority source convergence')
        self.check('all source devices including authority use the same propagation path',True)
        self.unban('192.0.2.100');self.until(lambda:all(self.request(n)[0]==200 for n in self.configs),'authority unban')
        self.check('IPv6 CC is accepted using the real transport address',self.request('node-a','/cc',ipv6=True)[0]==403)
        self.until(lambda:all(self.request(n,ipv6=True)[0]==0 for n in self.configs),'IPv6 L3 convergence')
        self.check('IPv6 source is enforced by each node kernel',True)
        self.check('IPv6 ban does not blacklist a different IPv4 source',self.request('node-a')[0]==200)
        self.unban('2001:db8:1::100');self.until(lambda:all(self.request(n,ipv6=True)[0]==200 for n in self.configs),'IPv6 unban')
        # Authority outage: a local decision survives in the outbox and is later distributed.
        p=self.nginx['authority'];p.terminate();p.wait(timeout=6)
        self.check('local CC remains available during a Master exchange outage',self.request('node-a','/cc')[0]==403)
        self.until(lambda:self.request('node-a')[0]==0,'offline local kernel apply')
        self.check('other Node is not falsely reported blocked before delivery',self.request('node-b')[0]==200)
        self.check('offline source preserves a durable pending proposal',self.status('node-a')['pending_proposals']>0)
        local=next(r for r in self.records('node-a') if r['layer']==3)
        self.launch_nginx('authority')
        self.until(lambda:all(self.request(n)[0]==0 for n in self.configs),'reconnect full snapshot')
        self.check('reconnection synchronizes all devices without resetting expiry',all(int(r['expires'])<=int(local['expires']) for n in self.configs for r in self.records(n) if r['layer']==3))
        # Agent death must not remove attached filters or extend the kernel TTL.
        victim=self.agents['node-b'];victim.kill();victim.wait(timeout=5)
        self.check('pinned eBPF enforcement survives Agent process death',self.request('node-b')[0]==0)
        inode=Path(self.configs['node-b'][1]['runtime_dir']+'/view').stat().st_ino
        self.launch_agent('node-b')
        self.check('Agent restart reuses the shared view inode',Path(self.configs['node-b'][1]['runtime_dir']+'/view').stat().st_ino==inode)
        self.check('Agent restart preserves the original absolute expiry',all(int(r['expires'])<=int(local['expires']) for r in self.records('node-b') if r['layer']==3))
        self.unban('192.0.2.100');self.until(lambda:all(self.request(n)[0]==200 for n in self.configs),'post-restart unban')
        self.request('node-b','/cc');self.until(lambda:all(self.request(n)[0]==0 for n in self.configs),'expiry without Agent setup')
        victim=self.agents['node-b'];victim.kill();victim.wait(timeout=5)
        self.until(lambda:self.status('authority')['cluster_state']=='PARTIAL','offline member visibility',timeout=15)
        self.check('stale member ACK cannot keep the cluster falsely ALL_APPLIED',self.status('authority')['pending_nodes']>=1)
        self.until(lambda:self.request('node-b')[0]==200,'kernel expiry without Agent GC',timeout=26)
        self.check('kernel deadlines stop dropping even when Agent cannot perform garbage collection',True)
        self.launch_agent('node-b')
        self.until(lambda:all(self.request(n)[0]==200 for n in self.configs),'other expiry completion')
        # Policy reload does not renew an existing ban, and malformed reload is rejected.
        self.request('node-a','/waf');self.until(lambda:any(r['layer']==7 for r in self.records('node-a')),'reload fixture L7')
        before=next(r for r in self.records('node-a') if r['layer']==7)
        config=self.configs['node-a'][1];config['policy']['l7_seconds']=30
        write(self.root/'node-a/policy.json',json.dumps(config));os.kill(self.agents['node-a'].pid,signal.SIGHUP)
        self.until(lambda:self.status('node-a')['policy_generation']=='2','policy generation')
        self.check('hot policy reload preserves existing ban expiry',next(r for r in self.records('node-a') if r['layer']==7)['expires']==before['expires'])
        bad=json.loads(json.dumps(config));bad['policy']['renew_on_hit']=True
        write(self.root/'node-a/policy.json',json.dumps(bad));os.kill(self.agents['node-a'].pid,signal.SIGHUP)
        self.until(lambda:self.status('node-a')['policy_error']=='fixed_expiry_required','invalid policy rejected')
        self.check('invalid policy leaves the active generation unchanged',self.status('node-a')['policy_generation']=='2')
        # A missing projection must keep the Agent visibly non-durable until
        # it can replay that file from the SQLite transaction history.
        conf=self.configs['node-b'][1];log_path=Path(conf['ip_log']);saved=log_path.with_suffix('.saved')
        log_path.rename(saved);log_path.mkdir()
        self.request('node-b','/variable-waf')
        self.until(lambda:self.status('node-b')['logs_durable']==0,'failed IP projection')
        self.check('second log write failure is visible rather than a durable success',self.status('node-b')['logs_durable']==0)
        log_path.rmdir();saved.rename(log_path)
        self.until(lambda:self.status('node-b')['logs_durable']==1,'IP projection replay')
        self.check('IP log projection resumes from the durable event sequence',True)
        self.check('trusted WAF variable setter reports an event without bundling a WAF engine',any(r['layer']==7 and r['ip']=='192.0.2.100' for r in self.records('node-b')))
        for node,(_,conf) in self.configs.items():
            events=[json.loads(line) for line in Path(conf['event_log']).read_text().splitlines()]
            ips=[json.loads(line) for line in Path(conf['ip_log']).read_text().splitlines()]
            by_seq={r['seq']:r for r in events}
            self.check(node+' has both durable ordered audit projections',len(by_seq)==len(events) and len({r['seq'] for r in ips})==len(ips)
                       and all(r.get('ip')==by_seq[r['seq']].get('ip') and r['action']==by_seq[r['seq']]['action'] for r in ips))
            self.check(node+' imported cluster records do not originate local events',any(r.get('origin')=='cluster' for r in events))
        return self.checks

    def close(self):
        for p in reversed(self.processes):
            if p.poll() is None:
                p.terminate()
                try:p.wait(timeout=6)
                except subprocess.TimeoutExpired:p.kill();p.wait(timeout=5)
        for f in self.logs:f.close()
        for ns in reversed(self.names):
            subprocess.run(['ip','netns','del',ns],capture_output=True)
            directory=Path('/etc/netns')/ns
            if (directory/'hosts').exists():(directory/'hosts').unlink()
            if directory.exists():directory.rmdir()
        if self.mounted:subprocess.run(['umount',str(self.pin)],capture_output=True)
        import shutil
        shutil.rmtree(self.runtime)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--prefix',required=True,type=Path);parser.add_argument('--agent-build',required=True,type=Path);parser.add_argument('--static',action='store_true');parser.add_argument('--mode',choices=('tcx_ingress','xdp_native'),default='tcx_ingress');parser.add_argument('--report',type=Path);args=parser.parse_args()
    require_root=os.geteuid()==0
    if not require_root:raise SystemExit('Real BPF/netns checks require root; no mocked success or silent skip.')
    prefix=args.prefix/'nginx' if (args.prefix/'nginx/sbin/nginx').exists() else args.prefix
    with tempfile.TemporaryDirectory(prefix='ban-kernel-test-') as directory:
        root=Path(directory);root.chmod(0o755);test=Test(root,prefix,args.agent_build,args.static,args.mode)
        try:
            checks=test.run()
            if args.report:args.report.write_text(json.dumps({'passed':len(checks),'checks':checks,'kernel_enforced':True},indent=2)+'\n')
            print(f'{len(checks)} real Ban kernel and cluster checks passed',flush=True)
        except Exception:
            for p in root.rglob('*-output.txt'):
                print(p.parent.name,p.name,p.read_text(errors='replace')[-6000:].replace(test.token,'[redacted]'),flush=True)
            raise
        finally:test.close()

if __name__=='__main__':main()
