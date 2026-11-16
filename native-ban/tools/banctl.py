#!/usr/bin/env python3
"""Optional local administration client; Agent/Nginx/BPF do not require Python."""
import argparse
import json
import socket
import struct

parser=argparse.ArgumentParser()
parser.add_argument('--socket',required=True)
parser.add_argument('operation',choices=('status','list','unban','snapshot','checkpoint'))
parser.add_argument('--ip')
parser.add_argument('--ban-id')
args=parser.parse_args()
request={'operation':args.operation}
if args.operation=='unban':
    if not args.ip or not args.ban_id:parser.error('unban requires --ip and --ban-id')
    request.update(ip=args.ip,ban_id=args.ban_id)
payload=json.dumps(request,separators=(',',':')).encode()
with socket.socket(socket.AF_UNIX) as connection:
    connection.settimeout(5);connection.connect(args.socket)
    connection.sendall(struct.pack('=I',len(payload))+payload)
    def read(n):
        value=b''
        while len(value)<n:
            chunk=connection.recv(n-len(value))
            if not chunk:raise RuntimeError('truncated Agent reply')
            value+=chunk
        return value
    status,size=struct.unpack('=II',read(8))
    if size>4*1024*1024:raise RuntimeError('oversized Agent reply')
    result=json.loads(read(size))
    print(json.dumps(result,ensure_ascii=False,indent=2))
    raise SystemExit(status!=200)
