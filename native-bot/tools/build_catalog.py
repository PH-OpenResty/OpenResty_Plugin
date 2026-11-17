#!/usr/bin/env python3
"""Compile reviewed Bot policy into a literal, bounded Nginx include.

No network is used by default. --refresh fetches only the fixed official feeds
listed below, validates every prefix and preserves output on any failure.
"""
from __future__ import annotations
import argparse
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import time
from urllib.parse import urljoin, urlsplit

ROOT = Path(__file__).resolve().parents[2]
FEEDS = {
    'google-common':'https://developers.google.com/static/crawling/ipranges/common-crawlers.json',
    'google-special':'https://developers.google.com/static/crawling/ipranges/special-crawlers.json',
    'google-user':'https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers.json',
    'google-user-google':'https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers-google.json',
    'bing':'https://www.bing.com/toolbox/bingbot.json',
    'duckduckgo':'https://duckduckgo.com/duckduckbot.json',
    'apple':'https://search.developer.apple.com/applebot.json',
    'yahoo':'https://s.yimg.com/bo/crawling/ipranges/common-crawlers.json',
    'mojeek':'https://www.mojeek.com/mojeekbot.json',
    'seznam':'https://search.seznam.cz/ipranges/seznambot.json',
    'so360':'https://www.so.com/help/spider_ip.html',
    'openai-search':'https://openai.com/searchbot.json',
    'openai-training':'https://openai.com/gptbot.json',
    'openai-user':'https://openai.com/chatgpt-user.json',
    'openai-ads':'https://openai.com/adsbot.json',
    'anthropic-shared':'https://claude.com/crawling/bots.json',
    'censys':'https://docs.censys.com/docs/opt-out-of-data-collection.md',
}


class PolicyError(Exception): pass
class PublishError(PolicyError):
    def __init__(self,published):self.published=published


def unique_pairs(pairs):
    result={}
    for key,value in pairs:
        if key in result: raise PolicyError('duplicate_json_key')
        result[key]=value
    return result


def load(path):
    raw=Path(path).read_bytes()
    if len(raw)>8<<20:raise PolicyError('policy_file_limit')
    return json.loads(raw,object_pairs_hook=unique_pairs)


def name(value):
    if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,95}',value):raise PolicyError('invalid_name')
    return value


def quote(value):
    if not isinstance(value,str) or not value or len(value)>256 or any(ord(c)<32 or ord(c)>126 for c in value):raise PolicyError('invalid_literal')
    # Custom directive arguments are literal; no complex-value expansion runs.
    return '"'+value.replace('\\','\\\\').replace('"','\\"')+'"'


def canonical_prefixes(values):
    if not isinstance(values,list) or not values or len(values)>16384:raise PolicyError('prefix_count')
    networks={ipaddress.ip_network(value,strict=True) for value in values}
    return [str(value) for value in sorted(networks,key=lambda n:(n.version,int(n.network_address),n.prefixlen))]


def fetch(url, maximum=8<<20):
    original=urlsplit(url)
    current=url
    for _ in range(4):
        parsed=urlsplit(current)
        if parsed.scheme!='https' or parsed.hostname!=original.hostname or parsed.port not in (None,443) or parsed.username or parsed.password or parsed.fragment:
            raise PolicyError('feed_redirect_not_allowed')
        addresses=list(dict.fromkeys(row[4][0] for row in socket.getaddrinfo(parsed.hostname,443,type=socket.SOCK_STREAM)))
        if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):raise PolicyError('feed_non_public_address')
        connection=http.client.HTTPSConnection(parsed.hostname,443,timeout=25)
        raw_socket=socket.create_connection((addresses[0],443),timeout=25)
        try:
            connection.sock=ssl.create_default_context().wrap_socket(raw_socket,server_hostname=parsed.hostname)
        except Exception:
            raw_socket.close();raise
        try:
            path=parsed.path or '/'
            if parsed.query:path+='?'+parsed.query
            connection.request('GET',path,headers={'User-Agent':'SCDN-Bot-Feed/0.1','Accept-Encoding':'identity'})
            response=connection.getresponse()
            if response.status in (301,302,303,307,308):
                location=response.getheader('Location')
                if not location:raise PolicyError('feed_redirect')
                current=urljoin(current,location);continue
            if response.status!=200 or response.getheader('Content-Encoding','identity').lower()!='identity':raise PolicyError('feed_http_status_or_encoding')
            data=response.read(maximum+1)
            if len(data)>maximum:raise PolicyError('feed_byte_limit')
            return data
        finally:connection.close()
    raise PolicyError('feed_redirect_limit')


def refresh_source(source, accept_large_change=False):
    source_id=source['id']
    if source_id not in FEEDS:raise PolicyError('unknown_official_feed')
    raw=fetch(FEEDS[source_id]);text=raw.decode('utf-8')
    if source['retrieval_format']=='json':
        doc=json.loads(text,object_pairs_hook=unique_pairs)
        values=[value for item in doc['prefixes'] for key,value in item.items() if key in ('ipv4Prefix','ipv6Prefix')]
        if len(values)!=len(doc['prefixes']):raise PolicyError('invalid_feed_schema')
    elif source_id=='so360':
        values=[value+'0/24' for value in re.findall(r'\b((?:\d{1,3}\.){3})\*',text)]
    elif source_id=='censys':
        blocks=re.findall(r'```[^\n]*\n(.*?)```',text,re.S)
        values=[line.strip() for block in blocks for line in block.splitlines() if '/' in line and not line.strip().startswith('AS')]
    else:raise PolicyError('unsupported_feed_format')
    prefixes=canonical_prefixes(values)
    if any(ipaddress.ip_network(value).prefixlen < (8 if ':' not in value else 32) for value in prefixes):
        raise PolicyError('unreasonably_broad_feed_prefix')
    previous=len(source['prefixes'])
    if not accept_large_change:
        if len(prefixes)*2<previous or len(prefixes)>max(16,previous*4):raise PolicyError('feed_change_requires_review')
        for version in (4,6):
            old=[ipaddress.ip_network(value) for value in source['prefixes'] if ipaddress.ip_network(value).version==version]
            new=[ipaddress.ip_network(value) for value in prefixes if ipaddress.ip_network(value).version==version]
            before=sum(value.num_addresses for value in ipaddress.collapse_addresses(old))
            after=sum(value.num_addresses for value in ipaddress.collapse_addresses(new))
            if (before and (after*2<before or after>before*4)) or (not before and after):
                raise PolicyError('feed_address_space_change_requires_review')
    return {**source,'prefixes':prefixes,'checked_at':int(time.time()),'source_sha256':hashlib.sha256(raw).hexdigest()}


def compile_policy(catalog, ranges, site=None, custom=None, maximum_age=86400):
    sources={}
    for source in ranges['sources']:
        if source['id'] in sources:raise PolicyError('duplicate_feed_id')
        sources[source['id']]={**source,'prefixes':canonical_prefixes(source['prefixes'])}
    entries=list(catalog['entries'])
    for rule in custom or []:
        entries.append({'id':rule['id'],'category':'custom','default_action':rule.get('action','deny'),
                        'ua_patterns':rule.get('ua',[]),'ip_feed_id':None,'prefixes':rule.get('ip_cidrs',[]),
                        'site_id':rule.get('site_id'),'ua_evidence':'manual'})
    if len(entries)>256 or not 1<=maximum_age<=2592000:raise PolicyError('entry_count_or_maximum_age')
    lines=['# Generated literal policy; source matching never bypasses authentication.']
    seen=set();pattern_count=prefix_count=node_budget=0
    kinds={'product_token':'token','bounded_phrase':'phrase','token':'token','phrase':'phrase',
           'exact':'exact','prefix':'prefix','contains':'contains'}
    for entry in entries:
        identifier=name(entry['id']);category=name(entry['category'])
        if identifier in seen:raise PolicyError('duplicate_entry_id')
        seen.add(identifier)
        action=entry['default_action']
        if action not in ('continue','observe','deny'):raise PolicyError('invalid_action')
        scope=entry.get('site_id') or site
        lines.append('scdn_bot_entry '+identifier+' '+category+' '+action+(' '+name(scope) if scope else '')+';')
        for pattern in entry['ua_patterns']:
            kind=kinds.get(pattern['type'])
            if not kind:raise PolicyError('unsupported_pattern_type')
            value=quote(pattern['value']);pattern_count+=1;node_budget+=len(pattern['value'])
            lines.append('scdn_bot_ua '+identifier+' '+kind+' '+value+';')
        feed=sources.get(entry.get('ip_feed_id'))
        if entry.get('ip_feed_id') and feed is None:raise PolicyError('unknown_feed_reference')
        values=feed['prefixes'] if feed else entry.get('prefixes',[])
        if values:
            for prefix in canonical_prefixes(values):
                lines.append('scdn_bot_ip '+identifier+' '+prefix+';');prefix_count+=1
        if not values and not entry['ua_patterns']:raise PolicyError('empty_rule')
        if feed:
            checked=int(feed.get('checked_at',0))
            mode='published' if checked else 'seed'
        else:
            checked=0;mode='candidate' if 'compatibility' in entry['ua_evidence'] or 'operator_candidate' in entry['ua_evidence'] else 'manual'
        lines.append(f'scdn_bot_feed {identifier} {mode} {checked} {maximum_age};')
    if pattern_count>512 or prefix_count>16384 or node_budget>=32768:raise PolicyError('compiled_policy_budget')
    return ('\n'.join(lines)+'\n').encode('ascii'),{'entries':len(entries),'patterns':pattern_count,'prefixes':prefix_count}


def atomic_output(path,data):
    path=Path(path)
    if not path.is_absolute():raise PolicyError('output_path_must_be_absolute')
    temporary=path.with_name('.bot-'+secrets.token_hex(12)+'.tmp')
    published=False
    try:
        descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(descriptor,'wb') as output:
            output.write(data);output.flush();os.fsync(output.fileno())
        os.replace(temporary,path)
        published=True
        if os.name!='nt':
            descriptor=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
            try:os.fsync(descriptor)
            finally:os.close(descriptor)
    except OSError:
        raise PublishError(published) from None
    finally:
        try:temporary.unlink(missing_ok=True)
        except OSError:pass


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--catalog',type=Path,default=ROOT/'docs/security-seeds/bot-catalog.seed.json')
    parser.add_argument('--ranges',type=Path,default=ROOT/'docs/security-seeds/bot-ip-ranges.seed.json')
    parser.add_argument('--rules',type=Path)
    parser.add_argument('--site')
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--max-age',type=int,default=86400)
    parser.add_argument('--refresh',action='store_true')
    parser.add_argument('--accept-large-change',action='store_true')
    args=parser.parse_args()
    try:
        catalog,ranges=load(args.catalog),load(args.ranges)
        if args.refresh:ranges={**ranges,'sources':[refresh_source(source,args.accept_large_change) for source in ranges['sources']]}
        custom=load(args.rules) if args.rules else None
        data,summary=compile_policy(catalog,ranges,args.site,custom,args.max_age)
        atomic_output(args.out,data)
        print(json.dumps({'passed':True,**summary,'sha256':hashlib.sha256(data).hexdigest(),'refreshed':args.refresh}))
        return 0
    except PublishError as error:
        print(json.dumps({'passed':False,'reason':'policy_publication_failed','previous_output_preserved':not error.published,
                          'output_replaced':error.published,'directory_durability_confirmed':False}))
        return 1
    except (PolicyError,ValueError,KeyError,TypeError,OSError,RecursionError,http.client.HTTPException):
        print(json.dumps({'passed':False,'reason':'policy_validation_or_update_failed','previous_output_preserved':True}))
        return 1


if __name__=='__main__':raise SystemExit(main())
