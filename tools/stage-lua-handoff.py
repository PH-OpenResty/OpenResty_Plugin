#!/usr/bin/env python3
"""Build a new Lua tree retaining engines but removing native-owned implementations.

Never mutates the original tree, active configuration, services or native state.
Convert/validate site data before switching to this staged tree. Unknown files
are preserved; remaining references to retired modules reject the stage.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
RETIRED = {
    'lib/route', 'lib/metrics', 'lib/registry', 'lib/native_export', 'lib/sni',
    'lib/admin', 'lib/cluster/control', 'cluster/agent', 'cli/sitectl',
    'src/tier', 'src/flush_l1_to_l2', 'src/config', 'tier', 'flush_l1_to_l2', 'config',
}
STATE = {'cluster/agent.conf', 'cluster/state.json', 'cluster/version', '.admin_token'}


def stage(source, destination, luajit):
    source = source.resolve(strict=True); destination = destination.resolve()
    if destination.exists() or destination.is_relative_to(source) or source.is_relative_to(destination):
        raise ValueError('destination must be new and independent from source')
    files = list(source.rglob('*'))
    if any(p.is_symlink() for p in files): raise ValueError('review symlinks before staging')
    destination.mkdir(mode=0o700, parents=True)
    removed, kept = [], []
    for item in files:
        if not item.is_file(): continue
        name = item.relative_to(source).as_posix()
        legacy = (item.suffix in {'.lua','.ljbc'} and str(Path(name).with_suffix('')).replace('\\','/') in RETIRED)
        legacy |= name in STATE or (name.startswith(('sites/','cluster/sites/')) and item.suffix in {'.lua','.ljbc'})
        legacy |= name == 'lib/security_guard.ljbc'
        if legacy: removed.append(name); continue
        target = destination / name; target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(item, target); kept.append(name)
    target = destination / 'lib/security_guard.lua'; target.parent.mkdir(parents=True,exist_ok=True)
    shutil.copy2(ROOT / 'compat/lua/lib/security_guard.lua', target)
    retired_modules = {name.replace('/', '.') for name in RETIRED if name.startswith('lib/')}
    retired_modules.update({'tier','config','flush_l1_to_l2','cluster.agent'})
    for item in destination.rglob('*.lua'):
        for name in re.findall(r'require\s*\(?\s*[\"\x27]([^\"\x27]+)',item.read_text()):
            if name in retired_modules: raise ValueError('retired dependency in ' + item.relative_to(destination).as_posix())
    subprocess.run([str(luajit), '-bd', str(target), str(target.with_suffix('.ljbc'))],check=True,capture_output=True)
    # The old stop hook copied private cache files. Native Tier keeps L2 itself.
    (destination / 'pre_action.sh').write_text('''#!/bin/sh
set -eu
nginx_bin=${NGINX_BIN:?set NGINX_BIN to the reviewed native runtime}
case "${1:-}" in
    reload) exec "$nginx_bin" -s reload ;;
    stop) exec "$nginx_bin" -s quit ;;
    *) exit 2 ;;
esac
''')
    (destination / 'pre_action.sh').chmod(0o755)
    (destination / 'build.sh').write_text('''#!/bin/sh
set -eu
base=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
luajit_bin=${LUAJIT_BIN:?set LUAJIT_BIN to the reviewed LuaJIT runtime}
find "$base/lib" -name '*.lua' -type f -exec "$luajit_bin" -bd '{}' '{}.build' ";"
find "$base/lib" -name '*.lua.build' -type f | while IFS= read -r file; do
    mv -- "$file" "${file%.lua.build}.ljbc"
done
''')
    (destination / 'build.sh').chmod(0o755)
    retained = [p for p in kept if p not in {'lib/security_guard.lua','build.sh','pre_action.sh'}]
    assert all((source / p).read_bytes() == (destination / p).read_bytes() for p in retained)
    return {'removed_native_owned_files':sorted(removed), 'retained_files':sorted(retained),
        'guard_sha256':hashlib.sha256(target.read_bytes()).hexdigest(), 'original_tree_modified':False,
        'services_modified':False,'activation_required':True}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',type=Path,required=True); p.add_argument('--destination',type=Path,required=True)
    p.add_argument('--luajit',type=Path,required=True); p.add_argument('--report',type=Path,required=True)
    args=p.parse_args();result=stage(args.source,args.destination,args.luajit)
    args.report.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))


if __name__=='__main__':main()
