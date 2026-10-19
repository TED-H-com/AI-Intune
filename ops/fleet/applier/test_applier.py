import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

os.umask(0o022)
BASE = Path(__file__).resolve().parent


class ApplyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'root'
        self.root.mkdir(mode=0o755)
        (self.root / 'etc').mkdir()
        uid = os.getuid() or 1001
        self.uid = uid
        (self.root / 'etc/passwd').write_text('agent:x:%d:1001::/home/agent:/bin/bash\n' % uid)
        (self.root / 'etc/os-release').write_text('ID=ubuntu\nVERSION_ID="22.04"\n')
        self.bin = Path(self.tmp.name) / 'bin'
        self.bin.mkdir()
        self.calls = Path(self.tmp.name) / 'calls'
        self.state = Path(self.tmp.name) / 'commands.json'
        stub = '''#!/usr/bin/python3
import json,os,sys
from pathlib import Path
name=Path(sys.argv[0]).name
args=sys.argv[1:]
with open(os.environ['CALLS'],'a') as f:f.write(name+' '+' '.join(args)+'\\n')
p=Path(os.environ['COMMAND_STATE'])
s=json.loads(p.read_text()) if p.exists() else {}
if name=='id':print('0');sys.exit(0)
if name=='visudo':sys.exit(int(os.environ.get('VISUDO_FAIL','0')))
if name=='systemctl':
 if args[0]=='is-enabled':print(s.get('enabled','disabled'));sys.exit(0)
 if args[0]=='is-active':print(s.get('active','inactive'));sys.exit(0)
 if args[0]=='enable':s['enabled']='enabled';s['active']='active'
 if args[0]=='disable':s['enabled']='disabled';s['active']='inactive'
if name=='powerprofilesctl':
 if args[0]=='get':print(s.get('power','balanced'))
 else:s['power']=args[1]
if name=='loginctl':
 if args[0]=='show-user':print(s.get('linger','no'))
 else:s['linger']='yes' if args[0]=='enable-linger' else 'no'
p.write_text(json.dumps(s))
'''
        stub = stub.replace("os.environ['CALLS']", repr(str(self.calls))).replace("os.environ['COMMAND_STATE']", repr(str(self.state))).replace("int(os.environ.get('VISUDO_FAIL','0'))", "int(Path(" + repr(str(self.bin / 'visudo-fail')) + ").exists())")
        for cmd in ('systemctl', 'visudo', 'powerprofilesctl', 'loginctl', 'id'):
            path = self.bin / cmd
            path.write_text(stub)
            path.chmod(0o755)
        self.env = dict(os.environ, PATH=str(self.bin) + ':/usr/bin:/bin', CALLS=str(self.calls), COMMAND_STATE=str(self.state))
        agent_dir = self.root / 'home/agent/.config/clawctl'
        agent_dir.mkdir(parents=True)
        self.agent_config = agent_dir / 'agent.json'
        self.agent_config.write_text('{}')
        if os.getuid() == 0:
            os.chown(self.agent_config, uid, uid)
        subprocess.run(['bash', str(BASE / 'install.sh'), '--agent-user', 'agent', '--root-prefix', str(self.root)], env=self.env, check=True, stdout=subprocess.DEVNULL)
        self.profile = self.root / 'home/agent/.config/clawctl/host-profile.json'
        self.profile.parent.mkdir(parents=True, exist_ok=True)
        self.write({})
        package = self.root / 'usr/bin/unattended-upgrade'
        package.parent.mkdir(parents=True)
        package.write_text('fixture')

    def write(self, profile):
        self.profile.write_text(json.dumps(profile))
        if os.getuid() == 0:
            os.chown(self.profile, self.uid, self.uid)

    def run_apply(self, ok=True, extra=()):
        r = subprocess.run(['python3', str(BASE / 'clawctl-fleet-apply'), '--root-prefix', str(self.root), *extra], env=self.env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0 if ok else 1, r.stderr + r.stdout)
        return json.loads(r.stdout)

    def snapshot(self):
        return {str(p.relative_to(self.root)): p.read_bytes() for p in self.root.rglob('*') if p.is_file() and not p.is_symlink() and '/var/lib/clawctl-fleet-apply/' not in str(p)}

    def test_monitor_only_refuses_install_and_every_apply(self):
        self.agent_config.write_text(json.dumps({'execution_policy': {'mode': 'monitor_only', 'revision': 2}}))
        before = self.snapshot()
        calls = self.calls.read_bytes() if self.calls.exists() else b''
        self.run_apply(False)
        result = subprocess.run(['bash', str(BASE / 'install.sh'), '--agent-user', 'agent', '--root-prefix', str(self.root)], env=self.env, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.calls.read_bytes() if self.calls.exists() else b'', calls)
        for policy in [None, {}, {'mode':'unknown','revision':2}, {'mode':'managed','revision':0}]:
            self.agent_config.write_text(json.dumps({'execution_policy': policy}))
            self.run_apply(False)

    def test_apply_idempotence_and_drift(self):
        p = dict(lid_ignore=True, disable_sleep=True, power_profile='performance', wifi_power_save_off=True, journald_max_mb=500, unattended_upgrades=True, scoped_sudoers=True, linger=True, root_disk_clean_timer=True)
        self.write(p)
        out = self.run_apply()
        self.assertTrue(all(v['status'] == 'changed' for v in out['items'].values()), out)
        digest = hashlib.sha256(json.dumps(p, separators=(',', ':')).encode()).hexdigest()
        self.assertEqual(out['profile_digest'], 'sha256:' + digest)
        out = self.run_apply()
        self.assertTrue(all(v['status'] == 'ok' for v in out['items'].values()), out)
        journal = self.root / 'etc/systemd/journald.conf.d/90-clawctl-fleet.conf'
        journal.write_text('# Managed by clawctl-fleet-apply v1\n[Journal]\nSystemMaxUse=100M\n')
        out = self.run_apply()
        self.assertEqual(out['items']['journald_max_mb']['status'], 'changed')
        self.assertIn('500M', journal.read_text())
        self.assertEqual((self.root / 'var/lib/clawctl-fleet-apply/last.json').stat().st_mode & 0o777, 0o644)

    def test_fail_closed(self):
        cases = ['{', '{"unknown":true}', '{"lid_ignore":1}', '{"journald_max_mb":99}', '{"power_profile":"shell"}', '{"lid_ignore":true,"lid_ignore":false}', '{} {}', '[]', '{"lid_ignore":true}' + ' ' * 65536]
        for raw in cases:
            self.profile.write_text(raw)
            before = self.snapshot()
            out = self.run_apply(False)
            self.assertEqual(out['items']['profile']['status'], 'failed')
            self.assertEqual(before, self.snapshot())
            self.assertFalse(self.calls.exists())
        self.write({'lid_ignore': True})
        self.profile.rename(self.profile.with_suffix('.real'))
        self.profile.symlink_to(self.profile.with_suffix('.real'))
        self.run_apply(False)
        self.assertFalse(self.calls.exists())
        self.profile.unlink()
        self.write({'lid_ignore': True})
        passwd = self.root / 'etc/passwd'
        passwd.write_text(passwd.read_text().replace(':%d:' % self.uid, ':%d:' % (self.uid + 1), 1))
        self.run_apply(False)
        self.assertFalse(self.calls.exists())

    def test_false_preserves_unmanaged_and_reverts_owned(self):
        self.write({'lid_ignore': True, 'disable_sleep': True, 'wifi_power_save_off': True, 'scoped_sudoers': True, 'linger': True})
        self.run_apply()
        wifi = self.root / 'etc/NetworkManager/conf.d/90-clawctl-fleet.conf'
        wifi.write_text('# local administrator\nkeep\n')
        self.write({'lid_ignore': False, 'disable_sleep': False, 'wifi_power_save_off': False, 'scoped_sudoers': False, 'linger': False})
        self.run_apply()
        self.assertEqual(wifi.read_text(), '# local administrator\nkeep\n')
        self.assertFalse((self.root / 'etc/systemd/logind.conf.d/90-clawctl-fleet.conf').exists())
        self.assertFalse((self.root / 'etc/sudoers.d/clawctl-fleet-agent').exists())
        self.assertFalse((self.root / 'etc/systemd/system/sleep.target').is_symlink())
        self.assertTrue(all(v['status'] in ('ok', 'unmanaged') for v in self.run_apply()['items'].values()))

    def test_apt_preserves_distro_defaults(self):
        default = self.root / 'etc/apt/apt.conf.d/20auto-upgrades'
        default.parent.mkdir(parents=True)
        body = b'// distro settings\nAPT::Periodic::Unattended-Upgrade "0";\n'
        default.write_bytes(body)
        managed = default.with_name('90-clawctl-fleet-auto-upgrades')
        self.write({'unattended_upgrades': True})
        self.assertEqual(self.run_apply()['items']['unattended_upgrades']['status'], 'changed')
        self.assertIn('APT::Periodic::Unattended-Upgrade "1";', managed.read_text())
        self.assertEqual(self.run_apply()['items']['unattended_upgrades']['status'], 'ok')
        self.write({'unattended_upgrades': False})
        self.assertEqual(self.run_apply()['items']['unattended_upgrades']['status'], 'changed')
        self.assertFalse(managed.exists())
        self.assertEqual(default.read_bytes(), body)
        self.assertFalse(default.with_name(default.name + '.fleet-apply.bak').exists())

    def test_drop_ins_preserve_defaults_and_refuse_unmanaged_own_paths(self):
        cases = (
            ('lid_ignore', True, 'etc/systemd/logind.conf.d', '90-clawctl-fleet.conf'),
            ('wifi_power_save_off', True, 'etc/NetworkManager/conf.d', '90-clawctl-fleet.conf'),
            ('journald_max_mb', 500, 'etc/systemd/journald.conf.d', '90-clawctl-fleet.conf'),
            ('unattended_upgrades', True, 'etc/apt/apt.conf.d', '90-clawctl-fleet-auto-upgrades'),
            ('scoped_sudoers', True, 'etc/sudoers.d', 'clawctl-fleet-agent'),
        )
        for item, value, directory, filename in cases:
            with self.subTest(item=item):
                parent = self.root / directory
                parent.mkdir(parents=True, exist_ok=True)
                default = parent / '10-distro-defaults'
                default.write_text('# distro default\n')
                self.write({item: value})
                self.assertEqual(self.run_apply()['items'][item]['status'], 'changed')
                self.assertEqual(default.read_text(), '# distro default\n')
                own = parent / filename
                own.chmod(0o644)
                own.write_text('# administrator configuration\n')
                self.assertEqual(self.run_apply(False)['items'][item]['status'], 'failed')
                self.assertEqual(own.read_text(), '# administrator configuration\n')

    def test_sleep_preserves_human_masks(self):
        targets = ('sleep.target', 'suspend.target', 'hibernate.target', 'hybrid-sleep.target')
        parent = self.root / 'etc/systemd/system'
        for target in targets:
            (parent / target).symlink_to('/dev/null')
        self.write({'disable_sleep': True})
        self.assertEqual(self.run_apply()['items']['disable_sleep']['status'], 'ok')
        self.write({'disable_sleep': False})
        self.assertEqual(self.run_apply()['items']['disable_sleep']['status'], 'ok')
        for target in targets:
            self.assertEqual(os.readlink(parent / target), '/dev/null')
            self.assertFalse((self.root / 'var/lib/clawctl-fleet-apply' / (target + '.owned')).exists())

    def test_root_timer_repeated_reversal(self):
        for _ in range(2):
            self.write({'root_disk_clean_timer': True})
            self.run_apply()
            self.write({'root_disk_clean_timer': False})
            self.assertEqual(self.run_apply()['items']['root_disk_clean_timer']['status'], 'changed')
            self.assertEqual(self.run_apply()['items']['root_disk_clean_timer']['status'], 'ok')

    def test_sudoers_validation_keeps_old(self):
        self.write({'scoped_sudoers': True})
        self.run_apply()
        path = self.root / 'etc/sudoers.d/clawctl-fleet-agent'
        path.chmod(0o640)
        path.write_text('# Managed by clawctl-fleet-apply v1\n# old reviewed policy\n')
        path.chmod(0o440)
        old = path.read_bytes()
        (self.bin / 'visudo-fail').touch()
        out = self.run_apply(False)
        self.assertEqual(out['items']['scoped_sudoers']['status'], 'failed')
        self.assertEqual(path.read_bytes(), old)

    def test_dry_run_and_unsupported(self):
        self.write({'lid_ignore': True, 'journald_max_mb': 500, 'scoped_sudoers': True})
        before = self.snapshot()
        self.run_apply(extra=('--dry-run',))
        self.assertEqual(before, self.snapshot())
        self.assertFalse((self.root / 'var/lib/clawctl-fleet-apply/last.json').exists())
        self.write({'unattended_upgrades': True})
        (self.root / 'etc/os-release').write_text('ID=ol\n')
        self.assertEqual(self.run_apply()['items']['unattended_upgrades']['status'], 'unsupported')


if __name__ == '__main__':
    unittest.main()
