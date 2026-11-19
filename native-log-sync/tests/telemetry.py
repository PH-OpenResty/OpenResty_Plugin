#!/usr/bin/env python3
"""Deterministic /proc/socket metrics, null/freshness and offline spooling."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import time
import socket
import struct
import threading


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--build',type=Path,required=True)
    parser.add_argument('--report',type=Path,required=True)
    args=parser.parse_args();binary=args.build/'scdn-log-sync';checks=[]
    def check(name,value):assert value,name;checks.append(name)
    with tempfile.TemporaryDirectory(prefix='scdn-log-telemetry-') as directory:
        root=Path(directory);state=root/'state';state.mkdir(mode=0o700);proc=root/'proc';proc.mkdir()
        def put(name,value):
            path=proc/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(value)
        put('stat','cpu  100 0 50 850 0 0 0 0\n')
        put('meminfo','MemTotal: 1000000 kB\nMemAvailable: 750000 kB\n')
        put('loadavg','0.5 0.2 0.1 1/10 1\n')
        put('sys/kernel/random/boot_id','synthetic-boot\n')
        put('net/dev','header\nheader\n lo: 10 0 0 0 0 0 0 0 20 0 0 0 0 0 0 0\n eth0: 1000 0 0 0 0 0 0 0 2000 0 0 0 0 0 0 0\n')
        put('net/snmp','Tcp: InSegs OutSegs RetransSegs CurrEstab\nTcp: 10 12 2 1\nUdp: InDatagrams OutDatagrams NoPorts InErrors\nUdp: 4 5 0 0\n')
        put('net/netstat','TcpExt: SyncookiesSent ListenDrops\nTcpExt: 3 4\n')
        put('net/snmp6','Udp6InDatagrams 6\n')
        put('100/status','Name:\tnginx\nPPid:\t1\n');put('101/status','Name:\tnginx\nPPid:\t100\n')
        for pid in [100,101]:(proc/str(pid)/'fd').mkdir()
        (proc/'101/fd/3').symlink_to('socket:[42]');(proc/'101/fd/4').symlink_to('socket:[43]')
        header='sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n'
        put('net/tcp',header+'0: 0100007F:0050 0200007F:FF00 01 0:0 0:0 0 0 0 42 0\n1: 0100007F:0051 0:0 0A 0:0 0:0 0 0 0 99 0\n')
        put('net/tcp6',header)
        put('net/udp',header+'0: 0100007F:01BB 0:0 07 0:0 0:0 0 0 0 43 0\n')
        put('net/udp6',header)
        pid=root/'nginx.pid';pid.write_text('100\n')
        sites=root/'sites.conf';sites.write_text('sites { site alpha { host alpha.example.test; enabled on; } site beta { host beta.example.test; enabled off; } }')
        packet=root/'packets.json';packet.write_text(json.dumps({'time_ms':int(time.time()*1000),'session':'synthetic','ingress':{'tcp_packets':2,'tcp_ack':1,'tcp_syn':1,'udp_packets':3},'egress':{}}))
        config={'node':'test_node','state_dir':str(state),'line_bytes':262144,'batch_bytes':4*1024*1024,
            'sources':[{'id':'logs','paths':[str(root/'input.jsonl')]}],
            'sinks':[{'id':'es','type':'elasticsearch','endpoint':'http://127.0.0.1:1','allow_http':True}],
            'telemetry':{'proc_root':str(proc),'pid_file':str(pid),'cache_path':str(root),'sites_file':str(sites),
                'packet_file':str(packet),'interval_ms':100,'rotate_bytes':65536,'spool_bytes':1048576}}
        path=root/'config.json';path.write_text(json.dumps(config))
        def sample():
            result=subprocess.run([str(binary),'--sample',str(path)],capture_output=True,text=True,timeout=10)
            assert result.returncode==0,result.stderr
            return json.loads(result.stdout)
        value=sample()
        check('host CPU baseline and memory are read without fabricated rates',value['cpu_pct'] is None and value['mem_pct']==25)
        check('host interface counters exclude loopback explicitly',value['net_rx']==1000 and value['net_tx']==2000)
        check('Nginx TCP sockets are restricted to master and worker inode ownership',value['connections']['nginx_tcp_sockets']==1 and value['connections']['host_tcp_sockets']==2)
        check('UDP sockets are distinct from connected sockets and QUIC sessions',value['connections']['nginx_udp_sockets']==1 and value['connections']['nginx_udp_connected_sockets']==0 and value['connections']['nginx_quic_sessions'] is None)
        check('SNMP, IPv6 and TcpExt counters retain their actual names',value['network_protocols']['TcpExt_ListenDrops']==4 and value['network_protocols']['Udp6InDatagrams']==6)
        check('site inventory filters disabled sites while preserving host metadata',value['sites']==['alpha'] and value['site_hosts']==['alpha.example.test'])
        check('fresh per-port packet snapshot is present',value['health']['packets']==1 and value['packets']['ingress']['tcp_syn']==1)
        check('unconfigured Sync and Ban are unavailable rather than healthy zero',value['sync_ok'] is None and value['ban_ready'] is None and value['kernel_drop_counter'] is None)
        packet.write_text(json.dumps({'time_ms':1,'session':'old'}));value=sample()
        check('stale packet sampler becomes unavailable rather than zero',value['health']['packets']==0 and value['packets'] is None)
        ban=socket.socket(socket.AF_UNIX);ban.bind(str(root/'ban.sock'));ban.listen(8);ban.settimeout(.2)
        stopped=threading.Event()
        def ban_loop():
            while not stopped.is_set():
                try:client,_=ban.accept()
                except socket.timeout:continue
                with client:
                    def read(n):
                        data=b''
                        while len(data)<n:
                            chunk=client.recv(n-len(data))
                            if not chunk:raise OSError('short request')
                            data+=chunk
                        return data
                    size=struct.unpack('=I',read(4))[0];request=json.loads(read(size))
                    value={'kernel_ready':1} if request['operation']=='status' else {'records':[{'ip':'192.0.2.1','scope':'fixture','layer':3,'ban_id':'synthetic','expires':1}]}
                    payload=json.dumps(value).encode();client.sendall(struct.pack('=II',200,len(payload))+payload)
        thread=threading.Thread(target=ban_loop,daemon=True);thread.start()
        config['telemetry']['ban_socket']=str(root/'ban.sock');path.write_text(json.dumps(config))
        value=sample()
        check('real Ban IPC integer readiness and active records follow the existing Agent contract',value['ban_ready']==1 and value['active_bans']==1 and value['health']['ban']==1)
        check('active Ban records preserve scope and private-address classification',json.loads(value['ban_records'])[0]['internal']==1)
        process=subprocess.Popen([str(binary),'--run',str(path)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            deadline=time.monotonic()+8
            while time.monotonic()<deadline:
                segments=list(state.glob('telemetry-*.jsonl'))
                if segments and sum(p.stat().st_size for p in segments)>20000:break
                time.sleep(.1)
            lines=[json.loads(line) for p in segments for line in p.read_text().splitlines()]
            check('metric samples spool durably while the backend is unavailable',len(lines)>=2 and (state/'telemetry-state.json').exists())
            check('independent sampler records backend health and durable source progress',all('collection'in row and 'health'in row for row in lines))
        finally:
            process.terminate();process.wait(timeout=8)
            stopped.set();thread.join(timeout=2);ban.close()
        check('background service shuts down promptly on SIGTERM',process.returncode==0)
    args.report.parent.mkdir(parents=True,exist_ok=True)
    args.report.write_text(json.dumps({'passed':True,'check_count':len(checks),'checks':checks},indent=2)+'\n')
    print(json.dumps({'passed':True,'check_count':len(checks)}))


if __name__=='__main__':main()
