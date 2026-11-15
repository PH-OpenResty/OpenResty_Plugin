#!/usr/bin/env python3
"""Validate design artifacts only; does not exercise Ban transport or BPF."""
from __future__ import annotations

import copy
import ipaddress
import json
from pathlib import Path
import subprocess
import tempfile
import tomllib

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]


def main():
    schema = json.loads((ROOT / 'design/policy.schema.json').read_text())
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    policy = tomllib.loads((ROOT / 'examples/ban-policy.toml.example').read_text())
    validator.validate(policy)
    assert policy['node_id'] != policy['cluster']['cluster_id']
    assert policy['cluster']['snapshot_max_ips'] <= policy['capacity']['max_l3_bans']
    assert policy['cluster']['max_snapshot_bytes'] >= 192 + 160 * policy['cluster']['snapshot_max_ips']
    for service in policy['services']:
        assert service['tcp_ports'] or service['udp_ports']
        for address in service['addresses']:
            ipaddress.ip_address(address)
    for subnet in policy['allowlist']['exempt_ip_bans']:
        ipaddress.ip_network(subnet)
    for change in ({'enabled': False}, {'mode': 'delta_only'}, {'target_nodes': 'selected'},
                   {'ack_requires_kernel': False}, {'master_url': 'http://sync.example.com'},
                   {'snapshot_max_ips': 0}, {'poll_ms': 0}, {'unknown': True}):
        invalid = copy.deepcopy(policy)
        invalid['cluster'].update(change)
        assert not validator.is_valid(invalid), change
    authority = copy.deepcopy(policy)
    authority['cluster']['role'] = 'authority'
    assert not validator.is_valid(authority)
    authority['cluster']['snapshot_signing_key'] = '/etc/scdn-ban/private/authority.key'
    validator.validate(authority)
    events = [json.loads(line) for line in (ROOT / 'examples/ban-cluster-events.jsonl.example').read_text().splitlines()]
    ips = [json.loads(line) for line in (ROOT / 'examples/ban-cluster-ips.jsonl.example').read_text().splitlines()]
    by_sequence = {event['seq']: event for event in events}
    assert events[0]['expires_utc'] == events[1]['expires_utc']
    assert events[0]['cluster_state'] == 'PARTIAL' and events[0]['pending_nodes'] == 1
    for record in ips:
        event = by_sequence[record['source_seq']]
        assert event['kernel_confirmed'] and event['origin'] == 'cluster_snapshot'
        for key in ('global_ban_id', 'event_id', 'revision', 'source_device', 'expires_utc'):
            assert event[key] == record[key]
        assert not record['republish_as_local']
        assert ipaddress.ip_address(record['ip']).is_global is False
    source = '\n'.join(f'#include "{name}"' for name in (
        'scdn_ban_wire.h', 'scdn_ban_map.h', 'scdn_ban_view.h', 'scdn_ban_cluster.h'))
    with tempfile.TemporaryDirectory(prefix='ban-design-check-') as directory:
        path = Path(directory) / 'check.c'
        path.write_text(source + '\nint main(void) { return 0; }\n')
        subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-pedantic',
                        '-I', str(ROOT / 'design'), '-fsyntax-only', str(path)], check=True)
    print('Ban v2 design schema, example constraints, negative cases and four C ABI headers passed.')
    print('No running Ban Agent, replication protocol or eBPF enforcement was tested.')


if __name__ == '__main__':
    main()
