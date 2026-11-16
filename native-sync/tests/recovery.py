#!/usr/bin/env python3
"""Real publication failures at the receipt/commit boundary and restart recovery."""
import argparse
import hashlib
import json
import os
import signal
import stat
from pathlib import Path
import subprocess
import tempfile
import time
from distribution import Review as DistributionReview
from nginx_process import worker_pids


class Review(DistributionReview):
    def __init__(self, root, prefix, static, library):
        super().__init__(root, prefix, static)
        self.library = library
        version = subprocess.run([str(self.nginx), '-V'],capture_output=True,text=True).stderr
        self.asan = subprocess.check_output(['cc','-print-file-name=libasan.so'],text=True).strip() if 'fsanitize=address' in version else ''

    def launch(self, name, configuration):
        previous = os.environ.get('LD_PRELOAD')
        try:
            if name == 'node-a':
                # Keep the sanitizer runtime first when running instrumented CI.
                os.environ['LD_PRELOAD'] = ':'.join(filter(None,[self.asan,previous,str(self.library)]))
            super().launch(name, configuration)
        finally:
            if previous is None: os.environ.pop('LD_PRELOAD', None)
            else: os.environ['LD_PRELOAD'] = previous


def case(root, prefix, static, library, mode):
    review = Review(root, prefix, static, library)
    try:
        review.start(); initial = review.applied(); review.applied(1)
        state = root / 'node-a-state'
        before = (state / 'active.conf').read_bytes()
        receipt = (state / 'applied.state').read_bytes()
        fault = state / '.fault-mode'; fault.write_text(mode)
        review.update(review.sites(origin=1))
        review.applied(1, after=1)
        if mode == 'crash-before-unlink':
            review.until(lambda:(state/'.fault-fired').exists(), 'transaction crash point')
            review.check('real worker stops after the new receipt is written but before commit',
                (state/'apply.pending').exists() and (state/'applied.state').read_bytes()!=receipt)
            node=review.processes[1]; children=worker_pids(node.pid)
            node.kill(); node.wait(timeout=10)
            for pid in children:
                try: os.kill(pid,signal.SIGKILL)
                except ProcessLookupError: pass
            def exited(pid):
                try: return Path(f'/proc/{pid}/stat').read_text().split(') ',1)[1].startswith('Z')
                except FileNotFoundError: return True
            review.until(lambda:all(exited(pid) for pid in children),'killed fixture Workers released locks')
            # A reboot recreates /run; this fixture's socket lives in persistent
            # /tmp. Remove only its verified dead Unix listener inode.
            control=root/'node-a.sock'
            if control.exists():
                assert stat.S_ISSOCK(control.lstat().st_mode)
                control.unlink()
            master=review.processes[0];master.terminate();master.wait(timeout=10)
            review.launch('node-a',review.node_configs[0])
            review.until(lambda:review.call(0)[2]==b'a:/asset','crash rollback startup')
            review.check('restart after actual process kill restores both prior files',
                (state/'active.conf').read_bytes()==before and (state/'applied.state').read_bytes()==receipt
                and not (state/'apply.pending').exists())
            return review.checks
        if mode.startswith('receipt-'):
            review.until(lambda: review.state()['last_error'] == 'applied_record_failed', 'durable receipt failure')
            review.check(mode + ': actual route and receipt return to the confirmed version',
                review.call(0)[2] == b'a:/asset' and (state/'applied.state').read_bytes() == receipt)
            time.sleep(1.2)
            review.check(mode + ': retry cannot overwrite the original rollback configuration',
                (state/'previous.conf').read_bytes() == before and not (state/'apply.pending').exists()
                and review.state()['applied_revision'] == initial['applied_revision'])
            (root/'fail-probe').write_text('fixture')
            time.sleep(1.2)
            review.check(mode + ': subsequent failed probe never serves unconfirmed content',review.call(0)[2] == b'a:/asset')
            (root/'fail-probe').unlink()
        elif mode == 'pending-unlink':
            review.until(lambda: review.state()['sync_state'] == 'recovery_required', 'unresolved finalization')
            review.check('unlink failure retains recovery material without claiming an applied revision',
                (state/'apply.pending').exists() and review.state()['applied_revision'] is None)
        else:
            review.until(lambda: review.state()['sync_state'] == 'applied' and int(review.state()['sequence']) > 1,
                         'directory commit recovery')
            review.check('visible commit with a directory fsync error preserves the new consistent pair',
                review.call(0)[2] == b'b:/asset' and int.from_bytes((state/'applied.state').read_bytes()[8:16],'big') > 1
                and not (state/'apply.pending').exists())
        fault.unlink()
        review.update(review.sites(origin=1) + '\n# new delivery after storage repair\n')
        review.applied(after=2)
        review.check(mode + ': a later publication succeeds after storage repair', review.call(0)[2] == b'b:/asset')

        if mode == 'receipt-rename':
            # Crash after receipt rename but before marker removal: bootstrap
            # must restore the complete prior pair even though receipt is newer.
            node = review.processes[1]; node.terminate(); node.wait(timeout=10)
            marker = b'SCNDP02\0' + hashlib.sha256(before).digest() + receipt
            marker += hashlib.sha256(marker).digest()
            (state/'previous.conf').write_bytes(before)
            (state/'apply.pending').write_bytes(marker); (state/'apply.pending').chmod(0o600)
            test = subprocess.run([str(review.nginx),'-p',str(root)+'/', '-t','-c',str(review.node_configs[0])],capture_output=True)
            review.check('bootstrap restores old source AND old receipt before parsing configuration',
                test.returncode == 0 and (state/'active.conf').read_bytes() == before
                and (state/'applied.state').read_bytes() == receipt and not (state/'apply.pending').exists())
            # The first-ever application has no old receipt.
            marker = b'SCNDP02\0' + hashlib.sha256(before).digest() + bytes(112)
            marker += hashlib.sha256(marker).digest()
            (state/'apply.pending').write_bytes(marker); (state/'apply.pending').chmod(0o600)
            test = subprocess.run([str(review.nginx),'-p',str(root)+'/', '-t','-c',str(review.node_configs[0])],capture_output=True)
            review.check('bootstrap recovery removes an uncommitted first application receipt',
                test.returncode == 0 and not (state/'applied.state').exists())
            corrupted = bytearray(marker); corrupted[-1] ^= 1
            (state/'apply.pending').write_bytes(corrupted); (state/'apply.pending').chmod(0o600)
            test = subprocess.run([str(review.nginx),'-p',str(root)+'/', '-t','-c',str(review.node_configs[0])],capture_output=True)
            review.check('corrupt transaction marker prevents startup and preserves evidence',
                test.returncode != 0 and (state/'apply.pending').read_bytes() == corrupted)
            marker=b'SCNDP02\0'+hashlib.sha256(before).digest()+receipt
            marker+=hashlib.sha256(marker).digest()
            (state/'apply.pending').write_bytes(marker)
            if os.geteuid()==0:os.chown(state,65534,65534)
            owner=state.stat().st_uid
            test=subprocess.run([str(review.nginx),'-p',str(root)+'/', '-t','-c',str(review.node_configs[0])],capture_output=True)
            review.check('bootstrap recovery preserves the state owner for files and application lock',test.returncode==0 and
                all((state/name).stat().st_uid==owner for name in ['active.conf','applied.state','apply.lock']))
        return review.checks
    except Exception:
        for role in ('node-a','node-b','master'):
            for name in ('error.log','stdout.log'):
                path=root/role/name
                if path.exists(): print(role,name,path.read_text(errors='replace')[-4000:].replace(review.token,'[redacted]'),flush=True)
        raise
    finally: review.close()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--prefix',type=Path,required=True); p.add_argument('--static',action='store_true')
    p.add_argument('--report',type=Path)
    p.add_argument('--case',action='append',choices=['receipt-write','receipt-fsync','receipt-rename','receipt-directory-fsync','pending-unlink','pending-directory-fsync','crash-before-unlink'])
    args=p.parse_args()
    prefix=args.prefix/'nginx' if (args.prefix/'nginx/sbin/nginx').exists() else args.prefix
    checks=[]
    with tempfile.TemporaryDirectory(prefix='sync-recovery-test-') as temporary:
        root=Path(temporary);library=root/'fault.so'
        subprocess.run(['cc','-shared','-fPIC',str(Path(__file__).with_name('fault-receipt.c')),'-ldl','-o',str(library)],check=True)
        for mode in args.case or ['receipt-write','receipt-fsync','receipt-rename','receipt-directory-fsync','pending-unlink','pending-directory-fsync','crash-before-unlink']:
            directory=root/mode; directory.mkdir()
            checks.extend(case(directory,prefix,args.static,library,mode))
    if args.report:args.report.write_text(json.dumps({'passed':len(checks),'checks':checks},indent=2)+'\n')
    print(f'{len(checks)} receipt recovery checks passed',flush=True)


if __name__=='__main__':main()
