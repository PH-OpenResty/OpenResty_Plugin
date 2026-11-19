#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
import socket
import os
import subprocess
import tempfile
import time

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--build',type=Path,required=True);parser.add_argument('--report',type=Path,required=True)
    args=parser.parse_args();checks=[]
    def check(name,value):assert value,name;checks.append(name)
    result=subprocess.run([str(args.build/'packet-tests'),str(args.build/'packet.bpf.o')],capture_output=True,text=True)
    check('real kernel BPF parser, flags, IPv4, IPv6, VLAN and negative packets',result.returncode==0)
    with tempfile.TemporaryDirectory(prefix='scdn-log-netmon-') as d:
        root=Path(d);listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1)
        udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp.bind(('127.0.0.1',0))
        config={'node':'test_node','interfaces':['lo'],'ports':[listener.getsockname()[1],udp.getsockname()[1]],
            'bpf_object':str(args.build/'packet.bpf.o'),'output':str(root/'packets.json'),'interval_ms':100}
        pid=root/'nginx.pid';pid.write_text(str(os.getpid())+'\n');config['nginx_pid_file']=str(pid)
        path=root/'netmon.json';path.write_text(json.dumps(config))
        process=subprocess.Popen([str(args.build/'scdn-log-netmon'),'--config',str(path)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            deadline=time.monotonic()+10
            while time.monotonic()<deadline and not (root/'packets.json').exists() and process.poll() is None:time.sleep(.1)
            check('passive packet sampler starts without TC/XDP attachment',process.poll() is None and (root/'packets.json').exists())
            client=socket.create_connection(listener.getsockname());server,_=listener.accept();client.sendall(b'fixture');server.recv(7);server.sendall(b'ack');client.recv(3)
            sender=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sender.sendto(b'fixture',udp.getsockname());udp.settimeout(2);udp.recv(64)
            client.close();server.close();sender.close()
            deadline=time.monotonic()+5
            while time.monotonic()<deadline:
                value=json.loads((root/'packets.json').read_text())
                if value['ingress']['udp_packets']>=1 and value['ingress']['tcp_syn']>=1 and value['egress']['tcp_syn_ack']>=1:break
                time.sleep(.1)
            check('actual TCP SYN and SYN-ACK are counted by direction',value['ingress']['tcp_syn']>=1 and value['egress']['tcp_syn_ack']>=1)
            check('actual TCP ACK flag packets are counted',value['ingress']['tcp_ack']>=1)
            check('actual UDP traffic has datagram counters',value['ingress']['udp_packets']>=1)
            check('privileged helper preserves the configured process-tree socket scope',value['privileged_sample']['connections']['nginx_tcp_sockets'] is not None)
        finally:
            process.terminate();process.wait(timeout=5);listener.close();udp.close()
        check('closing the packet sampler removes its private capture sockets',process.returncode==0)
    args.report.parent.mkdir(parents=True,exist_ok=True)
    args.report.write_text(json.dumps({'passed':True,'check_count':len(checks)+11,'checks':checks,'kernel_parser_checks':11},indent=2)+'\n')
    print(json.dumps({'passed':True,'check_count':len(checks)+11}))

if __name__=='__main__':main()
