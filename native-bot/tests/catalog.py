#!/usr/bin/env python3
"""Validate policy compilation and failure-preserving source publication."""
import argparse
import importlib.util
import json
from pathlib import Path
import tempfile
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('catalog',ROOT/'native-bot/tools/build_catalog.py')
catalog=importlib.util.module_from_spec(spec);spec.loader.exec_module(catalog)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--report',type=Path,required=True);args=parser.parse_args()
    entries=catalog.load(ROOT/'docs/security-seeds/bot-catalog.seed.json')
    ranges=catalog.load(ROOT/'docs/security-seeds/bot-ip-ranges.seed.json')
    checks=[]
    def check(name,value):assert value,name;checks.append(name)
    data,summary=catalog.compile_policy(entries,ranges)
    check('all identified catalog entries compile',summary['entries']==29 and summary['patterns']==44)
    check('source addresses retain classification boundaries',summary['prefixes']==1590 and b'scdn_bot_ip censys 66.132.159.0/24;' in data)
    check('FOFA remains candidate UA evidence',b'scdn_bot_feed fofa candidate 0 ' in data)
    check('unidentified engines do not acquire fabricated UA',b'Bravebot' not in data and b'scdn_bot_entry brave ' not in data)
    check('seed inputs do not pretend to be newly fetched',b' published ' not in data and b'scdn_bot_feed googlebot seed 0 ' in data)
    def rejected(name,function):
        try:function()
        except (catalog.PolicyError,ValueError):check(name,True)
        else:raise AssertionError(name)
    rejected('duplicate JSON key',lambda:json.loads('{"id":1,"id":2}',object_pairs_hook=catalog.unique_pairs))
    rejected('noncanonical subnet',lambda:catalog.canonical_prefixes(['203.0.113.5/24']))
    rejected('configuration newline injection',lambda:catalog.quote('x\nscdn_bot off;'))
    rejected('empty custom rule',lambda:catalog.compile_policy(entries,ranges,custom=[{'id':'empty'}]))
    rejected('invalid scope',lambda:catalog.compile_policy(entries,ranges,site='bad;site'))
    rejected('duplicate rule ID',lambda:catalog.compile_policy(entries,ranges,custom=[{'id':'censys','ua':[{'type':'token','value':'x'}]}]))
    source=next(value for value in ranges['sources'] if value['id']=='bing')
    body=json.dumps({'prefixes':[{'ipv4Prefix':value} for value in source['prefixes']]}).encode()
    with patch.object(catalog,'fetch',return_value=body):
        updated=catalog.refresh_source(source)
        check('validated update gets a real retrieval timestamp',updated['checked_at']>0 and updated['prefixes']==source['prefixes'])
    with patch.object(catalog,'fetch',return_value=b'{"prefixes":[]}'):
        rejected('empty source cannot replace a valid list',lambda:catalog.refresh_source(source))
    shrink=json.dumps({'prefixes':[{'ipv4Prefix':source['prefixes'][0]}]}).encode()
    with patch.object(catalog,'fetch',return_value=shrink):
        rejected('unexpected shrink requires explicit operator override',lambda:catalog.refresh_source(source))
    broad=json.dumps({'prefixes':[{'ipv4Prefix':'0.0.0.0/0'}]+[{'ipv4Prefix':value} for value in source['prefixes'][1:]]}).encode()
    with patch.object(catalog,'fetch',return_value=broad):
        rejected('same-count source cannot silently expand to all addresses',lambda:catalog.refresh_source(source))
    broad=json.dumps({'prefixes':[{'ipv4Prefix':'8.0.0.0/8'}]+[{'ipv4Prefix':value} for value in source['prefixes'][1:]]}).encode()
    with patch.object(catalog,'fetch',return_value=broad):
        rejected('address-space expansion requires review even at same count',lambda:catalog.refresh_source(source))
    rejected('unregistered feed URL is not used',lambda:catalog.refresh_source({'id':'untrusted'}))
    with tempfile.TemporaryDirectory(prefix='bot-catalog-') as directory:
        path=Path(directory)/'bots.conf';path.write_bytes(b'previous')
        with patch.object(catalog.os,'replace',side_effect=OSError('fixture')):
            try:catalog.atomic_output(path,data)
            except catalog.PublishError as error:check('rename failure preserves active include',not error.published and path.read_bytes()==b'previous')
            else:raise AssertionError('rename fault did not fail')
        with patch.object(catalog.os,'fsync',side_effect=[None,OSError('fixture')]):
            try:catalog.atomic_output(path,data)
            except catalog.PublishError as error:check('post-rename failure truthfully reports replacement',error.published and path.read_bytes()==data)
            else:raise AssertionError('directory sync fault did not fail')
        check('failed publication removes temporary files',not list(Path(directory).glob('.bot-*.tmp')))
        catalog.atomic_output(path,data)
        check('valid policy publishes exact output bytes',path.read_bytes()==data)
    result={'passed':True,'check_count':len(checks),'checks':checks,'network_requests':0,'production_modified':False}
    args.report.parent.mkdir(parents=True,exist_ok=True);args.report.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'passed':True,'check_count':len(checks)}))


if __name__=='__main__':main()
