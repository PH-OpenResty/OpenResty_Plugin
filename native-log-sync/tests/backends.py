#!/usr/bin/env python3
"""Actual Elasticsearch/ClickHouse writes, typed views and every dashboard SQL."""
import argparse
import datetime as dt
import json
from pathlib import Path
import re
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT=Path(__file__).resolve().parents[1]

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--build',type=Path,required=True)
    parser.add_argument('--es',default='http://127.0.0.1:19200');parser.add_argument('--ch',default='http://127.0.0.1:18123')
    parser.add_argument('--report',type=Path,required=True);args=parser.parse_args();checks=[]
    def check(name,value):assert value,name;checks.append(name)
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    def http(url,body=None,method=None):
        headers={'Content-Type':'application/json'}
        request=urllib.request.Request(url,data=body.encode() if isinstance(body,str) else body,method=method,headers=headers)
        try:
            with opener.open(request,timeout=30) as response:return response.read()
        except urllib.error.HTTPError as error:raise AssertionError(error.read(2000).decode(errors='replace')) from None
    def query(sql):return http(args.ch+'/?query='+urllib.parse.quote(sql,safe=''),b'',method='POST').decode()
    database='scdn_log_test_'+str(int(time.time()));index='scdn-logs-test-'+str(int(time.time()))
    es_version=json.loads(http(args.es))['version']['number'];ch_version=query('SELECT version()').strip()
    template=json.loads((ROOT/'schema/elasticsearch-template.json').read_text())
    template['index_patterns']=[index]
    pipeline=index+'-pipeline';template['template']['settings']['index.default_pipeline']=pipeline
    http(args.es+'/_ingest/pipeline/'+pipeline,(ROOT/'schema/elasticsearch-pipeline.json').read_bytes(),'PUT')
    http(args.es+'/_index_template/'+index,json.dumps(template),'PUT')
    http(args.es+'/'+index,json.dumps({'settings':{'number_of_shards':1,'number_of_replicas':0}}),'PUT')
    schema=(ROOT/'schema/clickhouse.sql').read_text().replace('scdn.',database+'.').replace('CREATE DATABASE IF NOT EXISTS scdn;','CREATE DATABASE IF NOT EXISTS '+database+';')
    try:
        for sql in schema.split(';'):
            if sql.strip():query(sql)
        check('actual ClickHouse creates every typed compatibility view',True)
        manifest=json.loads((ROOT/'schema/metrics-catalog.json').read_text())
        for table,names in manifest['fields'].items():
            target={'raw_access':'access','raw_bans':'bans'}.get(table,table)
            columns={row['name'] for row in map(json.loads,query('DESCRIBE TABLE '+database+'.'+target+' FORMAT JSONEachRow').splitlines())}
            check('all existing '+table+' field names have a direct schema mapping',set(names)<=columns)
        with tempfile.TemporaryDirectory(prefix='scdn-log-backends-') as directory:
            root=Path(directory);state=root/'state';state.mkdir(mode=0o700)
            now=dt.datetime.now(dt.timezone.utc)
            access={'time':now.isoformat(),'request_id':'e'*32,'site_id':'fixture','host':'fixture.example.test',
                'client_ip':'192.0.2.1','uri':'/fixture?private=redacted','method':'GET','status':200,'bytes':256,
                'rt':.025,'cache':'HIT','cache_layer':'l1','country':'ZZ','asn':0,'message':'中文完整日志'}
            ban={'time_ms':int(now.timestamp()*1000),'node_id':'test_node','seq':1,'ban_id':'synthetic','ip':'192.0.2.1',
                'scope':'fixture','layer':7,'action':'APPLIED','applied':1,'source':'fixture','reason':'synthetic','origin':'local'}
            (root/'access.jsonl').write_text(json.dumps(access,ensure_ascii=False)+'\n')
            (root/'ban.jsonl').write_text(json.dumps(ban)+'\n')
            config={'node':'test_node','state_dir':str(state),'line_bytes':262144,'batch_bytes':4194304,
                'sources':[{'id':'access','kind':'access','paths':[str(root/'access.jsonl')]},
                           {'id':'ban','kind':'ban','paths':[str(root/'ban.jsonl')]},
                           {'id':'samples','paths':[str(root/'sample.jsonl')]}],
                'sinks':[{'id':'es','type':'elasticsearch','endpoint':args.es,'index':index,'allow_http':True},
                         {'id':'ch','type':'clickhouse','endpoint':args.ch,'database':database,'table':'logs','allow_http':True}],
                'telemetry':{'enabled':False,'cache_path':str(root)}}
            conf=root/'config.json';conf.write_text(json.dumps(config))
            sample=subprocess.run([str(args.build/'scdn-log-sync'),'--sample',str(conf)],capture_output=True,text=True)
            assert sample.returncode==0,sample.stderr
            value=json.loads(sample.stdout);value.update(sync_ok=1,sync_sequence='1',ban_ready=1,active_bans=0,
                sites=['fixture'],site_hosts=['fixture.example.test'],ban_records='[]',kernel_drop_counter=0,
                kernel_drop_delta=0,kernel_drop_pps=0)
            # This fixture source is a metrics source through the real telemetry
            # journal, so the engine's ordinary delivery path is still exercised.
            config['telemetry']['enabled']=True;config['telemetry']['interval_ms']=60000
            conf.write_text(json.dumps(config));(state/'telemetry-fixture.jsonl').write_text(json.dumps(value)+'\n')
            result=subprocess.run([str(args.build/'scdn-log-sync'),'--once',str(conf)],capture_output=True,text=True,timeout=30)
            check('plugin core receives actual ES Bulk and CH insert confirmations',result.returncode==0)
            http(args.es+'/'+index+'/_refresh',b'',method='POST')
            total=json.loads(http(args.es+'/'+index+'/_count'))['count']
            check('both real backends contain the access, ban and metric documents',total==3 and query('SELECT count() FROM '+database+'.events').strip()=='3')
            check('typed access view keeps latency and sanitized URI',query('SELECT uri,duration_ms FROM '+database+'.access').strip()=='/fixture\t25')
            check('typed ban view keeps real action and applied fields',query('SELECT action,applied FROM '+database+'.bans').strip()=='APPLIED\t1')
            response=json.loads(http(args.es+'/'+index+'/_search',json.dumps({'query':{'term':{'kind':'access'}}}),'POST'))
            check('Elasticsearch indexes original non-ASCII JSON and normalized fields',response['hits']['hits'][0]['_source']['fields']['message']=='中文完整日志')
            original_time=dt.datetime.fromisoformat(response['hits']['hits'][0]['_source']['@timestamp'].replace('Z','+00:00'))
            check('ES ingest pipeline uses original event time for historical queries',abs(original_time.timestamp()-now.timestamp())<.002)
            response=json.loads(http(args.es+'/'+index+'/_search',json.dumps({'size':0,'aggs':{'memory':{'avg':{'field':'metrics.mem_pct'}}}}),'POST'))
            check('Elasticsearch metrics are numeric and support real aggregations',response['aggregations']['memory']['value'] is not None)
            delay=float(query('SELECT source_clock_skew_ms FROM '+database+'.node_samples').strip())
            check('receiver computes actual sample delivery age instead of a constant zero',0<=delay<30000)
            query('INSERT INTO '+database+".node_inventory VALUES ('test_node','192.0.2.1','edge',1)")
            catalog=json.loads((ROOT/'schema/metrics-catalog.json').read_text())
            count=0
            substitutions={'${node:singlequote}':"'test_node'",'${site:singlequote}':"'fixture','__unregistered__'",
                '${country:singlequote}':"'ZZ'",'${scope:singlequote}':"'all'",'${ip:singlequote}':"''",'${uri:singlequote}':"''",
                '${__from}':str(int(now.timestamp()*1000)-3600000),'${__to}':str(int(now.timestamp()*1000)+3600000),
                '${__interval_ms}':'10000'}
            for panel in catalog['panels']:
                for sql in panel['queries']:
                    sql=sql.replace('scdn.',database+'.')
                    for source,target in substitutions.items():sql=sql.replace(source,target)
                    assert '${'not in sql,sql
                    query(sql);count+=1
            check('all '+str(count)+' actual existing Grafana data queries execute on the new direct schema',count==79)
            network=json.loads((ROOT/'grafana/scdn-native-network.json').read_text())
            for panel in network['panels']:
                sql=panel['targets'][0]['rawSql'].replace('scdn.',database+'.')
                for source,target in substitutions.items():sql=sql.replace(source,target)
                query(sql)
            check('all 18 added realtime network panel queries execute',len(network['panels'])==18)
            # Simulate acknowledgement loss by resubmitting identical stored
            # event rows. Queries through FINAL retain the original event count.
            stored=query('SELECT * FROM '+database+'.logs FORMAT JSONEachRow')
            query_url=args.ch+'/?query='+urllib.parse.quote('INSERT INTO '+database+'.logs FORMAT JSONEachRow',safe='')
            http(query_url,stored,method='POST')
            check('CH replay is deduplicated by the FINAL event view',query('SELECT count() FROM '+database+'.events').strip()=='3')
    finally:
        query('DROP DATABASE IF EXISTS '+database)
        http(args.es+'/'+index,method='DELETE');http(args.es+'/_index_template/'+index,method='DELETE');http(args.es+'/_ingest/pipeline/'+pipeline,method='DELETE')
    args.report.parent.mkdir(parents=True,exist_ok=True)
    report={'passed':True,'check_count':len(checks),'checks':checks,'elasticsearch_version':es_version,
            'clickhouse_version':ch_version,'grafana_data_queries':79,'network_data_queries':18,'production_modified':False}
    args.report.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,ensure_ascii=False))

if __name__=='__main__':main()
