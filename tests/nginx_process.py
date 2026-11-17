"""Linux process observations shared by the real Nginx integration fixtures."""
from __future__ import annotations

from pathlib import Path
import re
import secrets
import socket
import time

_planned_listeners=set()


def unused_listen_port():
    """Keep planned server listeners outside the client's ephemeral range.

    bind(0) followed by close can choose the same planned port twice or let a
    health/probe connection consume it before the child Nginx binds it.
    """
    try:
        lower,upper=map(int,Path('/proc/sys/net/ipv4/ip_local_port_range').read_text().split())
    except (OSError,ValueError):
        lower,upper=32768,60999
    for _ in range(1024):
        port=1024+secrets.randbelow(65536-1024)
        if lower<=port<=upper or port in _planned_listeners:continue
        with socket.socket() as listener:
            try:listener.bind(('127.0.0.1',port))
            except OSError:continue
        _planned_listeners.add(port)
        return port
    raise AssertionError('no isolated fixture listener port available')


def worker_pids(master_pid):
    children=Path(f'/proc/{master_pid}/task/{master_pid}/children')
    try:
        pids=children.read_text().split()
    except (FileNotFoundError,ProcessLookupError):
        return set()
    workers=set()
    for pid in pids:
        try:
            command=Path(f'/proc/{pid}/cmdline').read_bytes()
        except (FileNotFoundError,ProcessLookupError):
            # A child may exit between reading children and its command line.
            continue
        if b'nginx: worker process' in command:
            workers.add(int(pid))
    return workers


def wait_for_workers(process,expected=2,timeout=10):
    """Return one complete PID snapshot after init, before recording a baseline.

    Nginx names a worker only after ngx_worker_process_init finishes. A status
    response from one worker does not establish that its peers reached here.
    """
    deadline=time.monotonic()+timeout
    while True:
        result=process.poll()
        if result is not None:
            raise AssertionError(f'nginx exited during worker startup (exit {result})')
        workers=worker_pids(process.pid)
        if len(workers)==expected:
            return workers
        remaining=deadline-time.monotonic()
        if remaining<=0:
            raise AssertionError(f'worker startup deadline: expected {expected}, observed {len(workers)}; PIDs {sorted(workers)}')
        time.sleep(min(0.02,remaining))


def dump_runtime_logs(root,limit=6000):
    # Sanitizers write to stderr/stdout; Nginx's configured error log alone
    # can be empty after a worker crashes during initialization.
    for name in ('error.log','stdout.log'):
        path=root/name
        if path.exists():
            print(f'[{name}]\n'+path.read_text(errors='replace')[-limit:],flush=True)


def runtime_log_offsets(root):
    return {name:(root/name).stat().st_size if (root/name).exists() else 0
            for name in ('error.log','stdout.log')}


def assert_clean_startup(root,offsets):
    for name,offset in offsets.items():
        path=root/name
        if not path.exists():continue
        with path.open('rb') as stream:
            stream.seek(offset);text=stream.read().decode('utf-8',errors='replace')
        if (any(marker in text for marker in ('ERROR: AddressSanitizer',
                'AddressSanitizer:DEADLYSIGNAL','runtime error:'))
                or re.search(r'worker process \d+ exited (?:on signal|with (?:fatal )?code)',text)):
            raise AssertionError(f'nginx worker failed during startup; see {name}')
