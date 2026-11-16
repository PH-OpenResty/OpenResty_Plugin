#!/usr/bin/env python3
"""Real Engine/Ban Store/BPF recovery with controlled wall and boot clocks."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[2]

def run(*args, **kw):
    result = subprocess.run(args, capture_output=True, text=True, **kw)
    if result.returncode: raise RuntimeError(result.stdout + result.stderr)
    return result

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--agent-build', required=True, type=Path)
    parser.add_argument('--sanitize', action='store_true')
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    checks = []
    with tempfile.TemporaryDirectory(prefix='ban-recovery-') as temporary:
        root = Path(temporary)
        flags = ['-fsanitize=address,undefined', '-fno-omit-frame-pointer'] if args.sanitize else []
        include = ['-I', str(ROOT/'native-ban/src'), '-I', str(ROOT/'native-ban/agent'), '-I', str(ROOT/'native-ban-store/include')]
        run('cc', '-std=c11', '-O1', *flags, *include, '-c', str(ROOT/'native-ban/src/ban_common.c'), '-o', str(root/'common.o'))
        libraries = run('pkg-config', '--cflags', '--libs', 'libbpf', 'json-c', 'libcurl', 'openssl').stdout.split()
        sources = [str(ROOT/'native-ban/agent'/name) for name in ('util.cpp', 'config.cpp', 'kernel.cpp', 'engine.cpp', 'cluster.cpp')]
        sources.append(str(ROOT/'native-ban-store/src/ban_store.cpp'))
        run('c++', '-std=c++17', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-pthread', *flags,
            '-Wl,--wrap=clock_gettime', *include, str(ROOT/'native-ban/tests/recovery.cpp'), *sources,
            str(root/'common.o'), *libraries, '-o', str(root/'recovery'))
        namespace = 'banrec-' + uuid.uuid4().hex[:10]
        mounted = []; created = False
        try:
            for name, kind in (('pins', 'bpf'), ('runtime', 'tmpfs')):
                path = root/name; path.mkdir()
                run('mount', '-t', kind, kind, str(path)); mounted.append(path)
            run('ip', 'netns', 'add', namespace); created = True
            run('ip', '-n', namespace, 'link', 'add', 'audit0', 'type', 'veth', 'peer', 'name', 'auditpeer')
            for interface in ('lo', 'audit0', 'auditpeer'): run('ip', '-n', namespace, 'link', 'set', interface, 'up')
            run('openssl', 'genpkey', '-algorithm', 'ED25519', '-out', str(root/'sign.key'))
            (root/'sign.key').chmod(0o600)
            run('openssl', 'pkey', '-in', str(root/'sign.key'), '-pubout', '-out', str(root/'sign.pub'))
            for mode in ('remote-fence', 'reboot-fence', 'reboot-clock', 'batch', 'projection', 'quota', 'backlog'):
                base = root/mode; base.mkdir()
                for p in (base/'state', base/'logs', root/'runtime'/mode, root/'pins'/mode): p.mkdir(mode=0o700)
                runtime = root/'runtime'/mode
                config = dict(version=1, node_id='authority', runtime_dir=str(runtime), state_dir=str(base/'state'),
                    event_socket=str(runtime/'event.sock'), admin_socket=str(runtime/'admin.sock'),
                    event_log=str(base/'logs/events.jsonl'), ip_log=str(base/'logs/ips.jsonl'),
                    worker_uid=65534, worker_gid=65534, sync_uid=65534,
                    instances=['00000000-0000-0000-0000-000000000100'], trusted_rules=[dict(source='cc', reason='cc-rule')],
                    policy=dict(l7_seconds=30, l3_seconds=30, window_ms=10000, threshold=4, event_age_ms=10000, renew_on_hit=False),
                    datapath=dict(mode='tcx_ingress', interfaces=['audit0'], object_file=str(args.agent_build/'ban.bpf.o'), pin_root=str(root/'pins'/mode)),
                    services=[dict(ip='192.0.2.10', protocol='tcp', port=8080)], allowlist=[],
                    cluster=dict(role='master', cluster_id='00000000-0000-0000-0000-000000001000',
                        authority_epoch='00000000-0000-0000-0000-000000001001', master_url='', ca='', certificate='', key='',
                        signing_key=str(root/'sign.key'), verify_key=str(root/'sign.pub'), socket=str(runtime/'sync.sock'),
                        members=['authority'], poll_ms=100, clock_uncertainty_ms=0))
                path = base/'policy.json'; path.write_text(json.dumps(config)); path.chmod(0o600)
                result = subprocess.run(['ip', 'netns', 'exec', namespace, str(root/'recovery'), str(path), mode],
                    capture_output=True, text=True, timeout=90)
                if result.returncode: raise AssertionError(mode + ': ' + result.stdout + result.stderr)
                checks.append(mode); print('PASS ' + mode, flush=True)
        finally:
            if created: run('ip', 'netns', 'del', namespace)
            for path in reversed(mounted): run('umount', str(path))
    if args.report: args.report.write_text(json.dumps(dict(passed=len(checks), checks=checks), indent=2) + '\n')

if __name__ == '__main__': main()
