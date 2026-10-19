#!/usr/bin/env python3
"""Install reviewed local assets. No downloads or calls to sudo."""
import argparse
import importlib.machinery
import json
import os
from pathlib import Path
import pwd
import sys
import re
import shutil
import subprocess

os.umask(0o022)
BASE = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
module = importlib.machinery.SourceFileLoader('applier', str(BASE / 'clawctl-fleet-apply')).load_module()
p = argparse.ArgumentParser()
p.add_argument('--agent-user', '--user', default=os.environ.get('SUDO_USER', ''))
p.add_argument('--root-prefix', default='')
p.add_argument('--uninstall', action='store_true')
args = p.parse_args()
args.dry_run = False
if (os.geteuid() != 0 and not args.root_prefix) or (args.root_prefix and not args.root_prefix.startswith('/')):
    p.error('run as root; root-prefix must be absolute')
a = module.Applier(args)
units = ('clawctl-fleet-apply.service', 'clawctl-fleet-apply.timer', 'clawctl-fleet-apply.path')
if args.uninstall:
    if not args.root_prefix:
        subprocess.run(['systemctl', 'disable', '--now', 'clawctl-fleet-apply.timer', 'clawctl-fleet-apply.path'], check=True)
        subprocess.run(['systemctl', 'stop', 'clawctl-fleet-apply.service'], check=True)
    for unit in units:
        path = a.path('/etc/systemd/system/' + unit)
        a.safe(path)
        if path.exists() and path.read_text().startswith(module.HEADER):
            path.unlink()
    # Keep host choices, backups, result and installer configuration for rollback.
    if not args.root_prefix:
        subprocess.run(['systemctl', 'daemon-reload'], check=True)
    print('Applier disabled; host settings and state retained')
    raise SystemExit(0)
if not re.fullmatch(r'[a-zA-Z_][a-zA-Z0-9_-]{0,31}', args.agent_user):
    p.error('specify --agent-user with the non-root agent service account')
if args.root_prefix:
    records = [l.split(':') for l in a.path('/etc/passwd').read_text().splitlines()]
    record = next(r for r in records if r[0] == args.agent_user)
    uid, home = int(record[2]), record[5]
else:
    record = pwd.getpwnam(args.agent_user)
    uid, home = record.pw_uid, record.pw_dir
if uid == 0 or not re.fullmatch(r'/[A-Za-z0-9_./-]+', home) or '..' in Path(home).parts:
    p.error('requires a non-root account with a safe absolute home')
try:
    a.execution_allowed(home, uid)
except (OSError, ValueError, KeyError, StopIteration, TypeError):
    p.error('Agent policy refuses host changes; enroll a managed agent before installing the applier')
maintenance = BASE / 'maintenance'
if not maintenance.exists():
    maintenance = BASE.parent.parent / 'maintenance'
if not (maintenance / 'install-timers.sh').is_file():
    p.error('maintenance installer assets missing')
# Copy trusted release assets to a root-owned directory; no root execution from home.
for src in maintenance.rglob('*'):
    if src.is_file():
        if src.is_symlink():
            p.error('symlink asset refused')
        dest = a.path('/usr/local/lib/clawctl-fleet-apply/maintenance/' + str(src.relative_to(maintenance)))
        a.atomic(dest, src.read_bytes(), 0o755 if os.access(str(src), os.X_OK) else 0o644)
a.atomic(a.path('/usr/local/sbin/clawctl-fleet-apply'), (BASE / 'clawctl-fleet-apply').read_bytes(), 0o755)
a.atomic(a.path('/etc/clawctl/fleet-apply.conf'), (json.dumps({'agent_user': args.agent_user}) + '\n').encode())
for unit in units:
    text = (BASE / unit).read_text().replace('@@PROFILE@@', home + '/.config/clawctl/host-profile.json').replace('@@JOBS@@', home + '/.config/clawctl/disk-jobs.json')
    a.drop('/etc/systemd/system/' + unit, text)
state = a.path('/var/lib/clawctl-fleet-apply')
a.safe(state)
state.mkdir(parents=True, exist_ok=True, mode=0o755)
state.chmod(0o755)
a.execution_allowed(home, uid)
if not args.root_prefix:
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    subprocess.run(['systemctl', 'enable', '--now', 'clawctl-fleet-apply.timer', 'clawctl-fleet-apply.path'], check=True)
print('Installed fleet host setup applier')
