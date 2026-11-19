#!/usr/bin/env python3
"""Generate portable typed views over the lossless JSON event store."""
from pathlib import Path
import json

ROOT=Path(__file__).resolve().parents[1]
base='''CREATE DATABASE IF NOT EXISTS scdn;
CREATE TABLE IF NOT EXISTS scdn.logs
(
 event_id FixedString(64), timestamp DateTime64(3, 'UTC'), received_at DateTime64(3, 'UTC') DEFAULT now64(3), node LowCardinality(String),
 source LowCardinality(String), kind LowCardinality(String), path String, generation String,
 offset UInt64, end_offset UInt64, raw_base64 String, terminated UInt8, fragment UInt8,
 archive UInt8, message String, format LowCardinality(String), fields_json String, normalized_json String,
 INDEX by_timestamp timestamp TYPE minmax GRANULARITY 1
)
ENGINE = ReplacingMergeTree
PARTITION BY cityHash64(node) % 16 ORDER BY (node, event_id);
CREATE VIEW IF NOT EXISTS scdn.events AS SELECT * FROM scdn.logs FINAL;
'''
access={
 'site':'String','host':'String','ip':'String','ip_family':'UInt8','internal':'UInt8','uri':'String',
 'method':'String','status':'UInt16','bytes':'UInt64','duration_ms':'Float64','origin_ms':'Float64',
 'origin_seen':'UInt8','cache':'String','cache_layer':'String','country':'String','asn':'UInt32',
 'asn_org':'String','operator':'String','protocol':'String','blocked':'UInt8','block_reason':'String','request_id':'String'}
bans={'ip':'String','internal':'UInt8','ban_id':'String','scope':'String','layer':'UInt8','action':'String',
      'source':'String','reason':'String','origin':'String','applied':'UInt8'}
samples={
 'sync_ok':'Nullable(UInt8)','sync_sequence':'String','ban_ready':'Nullable(UInt8)','active_bans':'Nullable(UInt32)',
 'sites':'Array(String)','site_hosts':'Array(String)','ban_records':'String','cpu_pct':'Nullable(Float64)',
 'load1':'Nullable(Float64)','cpu_count':'Nullable(UInt16)','mem_total':'Nullable(UInt64)',
 'mem_available':'Nullable(UInt64)','mem_pct':'Nullable(Float64)','net_rx':'Nullable(UInt64)','net_tx':'Nullable(UInt64)',
 'rx_bps':'Nullable(Float64)','tx_bps':'Nullable(Float64)','cache_disk_total':'Nullable(UInt64)',
 'cache_disk_free':'Nullable(UInt64)','cache_disk_pct':'Nullable(Float64)',
 **{'api_'+kind:'Nullable(UInt64)' for kind in ['web','api','ai','stream','grpc','websocket']},
 'native_requests':'Nullable(UInt64)','native_bytes':'Nullable(UInt64)','source_clock_skew_ms':'Int64',
 'kernel_drop_counter':'Nullable(UInt64)','kernel_drop_delta':'Nullable(UInt64)','kernel_drop_pps':'Nullable(Float64)'}

def select_fields(fields,column):
 return [f"JSONExtract({column}, '{name}', '{kind}') AS {name}" for name,kind in fields.items()]

sql=base
for name,fields,kind,time_expr in [
 ('access',access,'access',"coalesce(parseDateTime64BestEffortOrNull(JSONExtractString(normalized_json, 'time'), 3, 'UTC'), timestamp)"),
 ('bans',bans,'ban',"fromUnixTimestamp64Milli(toInt64OrZero(JSONExtractString(normalized_json, 'time_ms'))))")]:
 if name=='bans':time_expr=time_expr[:-1]
 selections=['event_id',time_expr+' AS time','node']+select_fields(fields,'normalized_json')
 sql+=f"CREATE VIEW IF NOT EXISTS scdn.{name} AS SELECT\n "+',\n '.join(selections)+f"\nFROM scdn.logs FINAL WHERE kind='{kind}' AND normalized_json!='';\n"
selections=["fromUnixTimestamp64Milli(JSONExtractInt(fields_json, 'time')) AS time",'node']+select_fields(samples,'fields_json')
selections += ["JSONExtractRaw(fields_json, 'nginx_stats') AS nginx_stats", "fields_json AS raw_sample"]
selections=["dateDiff('millisecond', fromUnixTimestamp64Milli(JSONExtractInt(fields_json, 'time')), received_at) AS source_clock_skew_ms"
            if value.endswith(' AS source_clock_skew_ms') else value for value in selections]
sql+='CREATE VIEW IF NOT EXISTS scdn.node_samples AS SELECT\n '+',\n '.join(selections)+"\nFROM scdn.logs FINAL WHERE kind='metrics' AND format='json';\n"
sql+='''CREATE TABLE IF NOT EXISTS scdn.node_inventory
(node String, address String, role String, enabled UInt8)
ENGINE = ReplacingMergeTree ORDER BY node;
CREATE VIEW IF NOT EXISTS scdn.collection_health AS SELECT
 fromUnixTimestamp64Milli(JSONExtractInt(fields_json, 'time')) AS time, node, 'direct' AS mode,
 JSONExtract(fields_json, 'collection', 'success', 'UInt8') AS success,
 JSONExtract(fields_json, 'collection', 'inserted', 'UInt64') AS inserted,
 JSONExtract(fields_json, 'collection', 'invalid', 'UInt64') AS invalid,
 JSONExtract(fields_json, 'collection', 'source_files', 'UInt32') AS source_files,
 JSONExtract(fields_json, 'collection', 'completed_files', 'UInt32') AS completed_files,
 JSONExtract(fields_json, 'collection', 'error', 'String') AS error
FROM scdn.logs FINAL WHERE kind='metrics' AND format='json';
CREATE VIEW IF NOT EXISTS scdn.network_samples AS SELECT
 fromUnixTimestamp64Milli(JSONExtractInt(fields_json, 'time')) AS time, node,
 JSONExtractRaw(fields_json, 'connections') AS connections,
 JSONExtractRaw(fields_json, 'network_protocols') AS host_protocols,
 JSONExtractRaw(fields_json, 'packets') AS packets,
 JSONExtractRaw(fields_json, 'packet_pps') AS packet_pps,
 JSONExtractRaw(fields_json, 'health') AS health
FROM scdn.logs FINAL WHERE kind='metrics' AND format='json';
'''
(ROOT/'schema/clickhouse.sql').write_bytes(sql.encode())
properties={name:{'type':'keyword' if kind=='String' else 'double' if 'Float'in kind else 'long'} for name,kind in {**access,**bans}.items()}
properties.update(event_id={'type':'keyword'},node={'type':'keyword'},time={'type':'keyword'},time_ms={'type':'keyword'})
template={'index_patterns':['scdn-logs*'],'template':{'mappings':{'dynamic':'strict','properties':{
 'event_id':{'type':'keyword'},'timestamp':{'type':'date','format':'strict_date_optional_time||yyyy-MM-dd HH:mm:ss.SSS'},
 **{k:{'type':'keyword'} for k in ['node','source','kind','path','generation','format']},
 **{k:{'type':'long'} for k in ['offset','end_offset','terminated','fragment','archive']},
 'message':{'type':'text'},'raw_base64':{'type':'keyword','index':False,'doc_values':False},
 'fields_json':{'type':'keyword','index':False,'doc_values':False},
 'normalized_json':{'type':'keyword','index':False,'doc_values':False},
 'fields':{'type':'flattened','ignore_above':1024},'normalized':{'dynamic':False,'properties':properties}
}}}}
metric_properties={name:{'type':'keyword' if kind in ['String','Array(String)'] else 'double' if 'Float'in kind else 'long'} for name,kind in samples.items()}
metric_properties.update(time={'type':'date','format':'epoch_millis'},
    connections={'type':'object','dynamic':True},network_protocols={'type':'object','dynamic':True},
    health={'type':'object','dynamic':True},packets={'type':'object','dynamic':False,'properties':{
        'session':{'type':'keyword'},'scope':{'type':'keyword'},'time_ms':{'type':'date','format':'epoch_millis'},
        **{direction:{'type':'object','properties':{key:{'type':'long'} for key in ['tcp_packets','tcp_bytes','tcp_ack','tcp_syn','tcp_syn_ack','tcp_syn_only','tcp_fin','tcp_rst','udp_packets','udp_bytes']}} for direction in ['ingress','egress']}}},
    packet_pps={'type':'object','dynamic':True},collection={'type':'object','dynamic':True})
template['template']['mappings']['properties']['metrics']={'type':'object','dynamic':False,'properties':metric_properties}
template['template']['mappings']['properties']['@timestamp']={'type':'date'}
template['template']['mappings']['properties']['received_at']={'type':'date'}
template['template']['settings']={'index.default_pipeline':'scdn-log-sync'}
for mapping in [*properties.values(),*metric_properties.values()]:
 if mapping.get('type')=='keyword':mapping['ignore_above']=2048
(ROOT/'schema/elasticsearch-template.json').write_bytes((json.dumps(template,indent=2)+'\n').encode())
pipeline={'description':'Use original event time, with a safe ingestion-time fallback.',
 'processors':[
  {'set':{'field':'received_at','value':'{{{_ingest.timestamp}}}'}},
  {'script':{'if':"ctx.kind == 'metrics' && ctx.metrics != null && ctx.metrics.time instanceof Number",
             'source':"ctx.metrics.source_clock_skew_ms = java.time.Instant.parse(ctx.received_at).toEpochMilli() - ((Number)ctx.metrics.time).longValue()"}},
  {'date':{'if':"ctx.kind == 'access' && ctx.normalized != null && ctx.normalized.time != null",'field':'normalized.time','target_field':'@timestamp','formats':['ISO8601','yyyy-MM-dd HH:mm:ss.SSS','UNIX_MS','UNIX'],'ignore_failure':True}},
  {'date':{'if':"ctx.kind == 'ban' && ctx.normalized != null && ctx.normalized.time_ms != null",'field':'normalized.time_ms','target_field':'@timestamp','formats':['UNIX_MS'],'ignore_failure':True}},
  {'date':{'if':"ctx.kind == 'metrics' && ctx.metrics != null && ctx.metrics.time != null",'field':'metrics.time','target_field':'@timestamp','formats':['UNIX_MS'],'ignore_failure':True}},
  {'date':{'if':"ctx['@timestamp'] == null",'field':'timestamp','target_field':'@timestamp','formats':['ISO8601','yyyy-MM-dd HH:mm:ss.SSS']}}
 ]}
(ROOT/'schema/elasticsearch-pipeline.json').write_bytes((json.dumps(pipeline,indent=2)+'\n').encode())
print('Generated ClickHouse views and Elasticsearch mapping template.')
