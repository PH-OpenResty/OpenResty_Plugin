#!/usr/bin/env python3
from pathlib import Path
import json
ROOT=Path(__file__).resolve().parents[1]
source={'type':'grafana-clickhouse-datasource','uid':'scdn-native-clickhouse'}
panels=[]
fields=[
 ('Nginx TCP 套接字','connections','nginx_tcp_sockets','short'),
 ('Nginx TCP 已建立','connections','nginx_tcp_established','short'),
 ('Nginx TCP 监听','connections','nginx_tcp_listen','short'),
 ('Nginx TCP SYN_SENT','connections','nginx_tcp_syn_sent','short'),
 ('Nginx TCP SYN_RECV · 已归属套接字','connections','nginx_tcp_syn_recv','short'),
 ('Nginx UDP 套接字','connections','nginx_udp_sockets','short'),
 ('Nginx connected UDP 套接字','connections','nginx_udp_connected_sockets','short'),
 ('主机 TCP 套接字','connections','host_tcp_sockets','short'),
 ('主机 UDP 套接字','connections','host_udp_sockets','short'),
 ('入站 TCP SYN 包累计','packets',('ingress','tcp_syn'),'short'),
 ('出站 TCP SYN-ACK 包累计','packets',('egress','tcp_syn_ack'),'short'),
 ('入站 TCP ACK 包累计','packets',('ingress','tcp_ack'),'short'),
 ('入站 UDP 数据报累计','packets',('ingress','udp_packets'),'short'),
 ('入站 TCP SYN 包速率','packet_pps',('ingress','tcp_syn'),'pps'),
 ('入站 TCP ACK 包速率','packet_pps',('ingress','tcp_ack'),'pps'),
 ('入站 UDP 数据报速率','packet_pps',('ingress','udp_packets'),'pps'),
 ('主机 TCP 重传累计','host_protocols','Tcp_RetransSegs','short'),
 ('主机监听队列丢弃累计','host_protocols','TcpExt_ListenDrops','short')]
for i,(title,column,path,unit) in enumerate(fields):
 keys=path if isinstance(path,tuple) else (path,)
 expression='JSONExtract('+column+', '+', '.join("'"+key+"'" for key in keys)+", 'Nullable(Float64)')"
 sql="SELECT time, node AS metric, "+expression+" AS value FROM scdn.network_samples WHERE time >= fromUnixTimestamp64Milli(${__from}) AND time <= fromUnixTimestamp64Milli(${__to}) ORDER BY time"
 panels.append({'id':i+1,'type':'timeseries','title':title,'datasource':source,
  'gridPos':{'x':(i%2)*12,'y':(i//2)*8,'w':12,'h':8},
  'description':'连接按 Nginx PID 树归属；报文按指定网卡/监听端口归属。UDP 套接字不等同 QUIC 会话；采集缺失或初次速率显示无数据。',
  'targets':[{'refId':'A','datasource':source,'editorType':'sql','pluginVersion':'4.23.5','format':0,'rawSql':sql}],
  'fieldConfig':{'defaults':{'unit':unit,'noValue':'采集不可用'},'overrides':[]},
  'options':{'legend':{'displayMode':'list','placement':'bottom'}}})
board={'uid':'scdn-native-network','title':'SCDN 原生 TCP / UDP 实时观测','schemaVersion':40,'version':1,
 'timezone':'browser','refresh':'5s','time':{'from':'now-30m','to':'now'},'panels':panels,'templating':{'list':[]}}
(ROOT/'grafana/scdn-native-network.json').write_bytes((json.dumps(board,ensure_ascii=False,indent=2)+'\n').encode())
print('Generated 18 network panels.')
