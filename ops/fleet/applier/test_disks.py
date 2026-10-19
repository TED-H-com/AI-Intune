"""All block devices and host commands are fixtures. Never contacts a device."""
import copy
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace

BASE = Path(__file__).resolve().parent
loader = importlib.machinery.SourceFileLoader('disk_applier', str(BASE / 'clawctl-fleet-apply'))
spec = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)


class DiskTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'root'
        self.root.mkdir(mode=0o755)
        for directory in ('etc', 'proc', 'sys/block/nvme1n1/holders', 'dev/disk/by-id', 'home/agent/.config/clawctl'):
            (self.root / directory).mkdir(parents=True, exist_ok=True, mode=0o755)
        (self.root / 'etc/passwd').write_text('agent:x:1001:1002::/home/agent:/bin/sh\nroot:x:0:0::/root:/bin/sh\nlow:x:999:999::/:/bin/sh\n')
        (self.root / 'etc/clawctl').mkdir()
        (self.root / 'etc/clawctl/fleet-apply.conf').write_text('{"agent_user":"agent"}')
        agent_config = self.root / 'home/agent/.config/clawctl/agent.json'
        agent_config.write_text('{}')
        if os.getuid() == 0:
            os.chown(agent_config, 1001, 1002)
        else:
            passwd = self.root / 'etc/passwd'
            passwd.write_text(passwd.read_text().replace('agent:x:1001:', 'agent:x:%d:' % os.getuid()))
        (self.root / 'etc/fstab').write_text('# original\n')
        (self.root / 'proc/swaps').write_text('Filename Type Size Used Priority\n')
        (self.root / 'dev/nvme1n1').touch()
        (self.root / 'dev/disk/by-id/nvme-Example_example').symlink_to('../../nvme1n1')
        self.job = dict(id='example-job-01', device='/dev/nvme1n1', serial='example', wwn='', size_bytes=2147483648,
                        model='Example', mount_point='/data', fstype='ext4', label='data', owner='agent')
        self.device = dict(name='nvme1n1', path='/dev/nvme1n1', kname='nvme1n1', type='disk', size=2147483648,
                           model='Example', serial='example', wwn=None, rm=False, ro=False, children=[])
        self.fixture = dict(device=self.device, boot=[], signature='', mounted=False, fail='')
        self.bin = Path(self.tmp.name) / 'bin'
        self.bin.mkdir(mode=0o755)
        self.calls = self.bin / 'calls'
        self.config = self.bin / 'fixture.json'
        # All state paths are embedded: command environments deliberately expose only PATH and locale.
        stub = '''#!/usr/bin/python3
import json,sys
from pathlib import Path
base=Path(__file__).parent
name=Path(sys.argv[0]).name
args=sys.argv[1:]
with (base/'calls').open('a') as f:f.write(json.dumps([name]+args)+'\\n')
c=json.loads((base/'fixture.json').read_text())
if c.get('fail')==name:sys.exit(2)
if name=='lsblk':
 d=c['device']
 if (base/'partitioned').exists():d['children']=[dict(path='/dev/nvme1n1p1',type='part')]
 print(json.dumps({'blockdevices':[d] if '--' in args else c['boot']}))
elif name=='wipefs':print(c['signature'])
elif name=='parted':(base/'partitioned').touch()
elif name=='blkid':print('12345678-abcd-1234-abcd-123456789abc')
elif name=='findmnt':
 if '--json' in args:print(json.dumps({'filesystems':[{'uuid':'12345678-abcd-1234-abcd-123456789abc','fstype':c.get('fstype','ext4'),'target':'/data'}]}))
 elif c['mounted']:print('/data')
 else:sys.exit(1)
elif name=='df':print('Filesystem Size Used Avail Use% Mounted on\\n/dev/nvme1n1p1 2G 1M 2G 1% /data')
'''
        for cmd in ('lsblk', 'wipefs', 'blkid', 'parted', 'partprobe', 'udevadm', 'mkfs.ext4', 'mkfs.xfs', 'mount', 'findmnt', 'chown', 'df'):
            p = self.bin / cmd
            p.write_text(stub)
            p.chmod(0o755)
        self.oldpath = os.environ['PATH']
        os.environ['PATH'] = str(self.bin)
        self.addCleanup(os.environ.__setitem__, 'PATH', self.oldpath)
        self.applier = module.Applier(SimpleNamespace(root_prefix=str(self.root), dry_run=False))
        self.applier.agent_uid = os.getuid()
        self.applier.agent_home = '/home/agent'
        self.input = self.root / 'home/agent/.config/clawctl/disk-jobs.json'
        self.dest = self.root / 'var/lib/clawctl-fleet-apply/disk-jobs/example-job-01.json'

    def test_monitor_only_refuses_disk_operations(self):
        policy = self.root / 'home/agent/.config/clawctl/agent.json'
        policy.write_text(json.dumps({'execution_policy': {'mode':'monitor_only','revision':1}}))
        with self.assertRaises(ValueError):
            self.run_jobs()
        self.assertEqual(self.argv(), [])
        self.assertFalse(self.dest.exists())

    def run_jobs(self):
        self.config.write_text(json.dumps(self.fixture))
        self.input.write_text(json.dumps([self.job]))
        self.input.chmod(0o600)
        self.applier.disk_jobs()
        return json.loads(self.dest.read_text()) if self.dest.exists() else None

    def argv(self):
        return [json.loads(l) for l in self.calls.read_text().splitlines()] if self.calls.exists() else []

    def assert_refused(self):
        before = (self.root / 'etc/fstab').read_bytes()
        result = self.run_jobs()
        self.assertEqual(result['state'], 'refused', result)
        self.assertFalse(any(c[0] in ('parted', 'mkfs.ext4', 'mkfs.xfs', 'mount', 'chown') for c in self.argv()))
        self.assertEqual(before, (self.root / 'etc/fstab').read_bytes())

    def test_happy_ext4_and_replay(self):
        self.assertEqual(self.run_jobs()['state'], 'done')
        calls = self.argv()
        self.assertIn(['parted', '-s', '/dev/nvme1n1', 'mklabel', 'gpt', 'mkpart', 'data', 'ext4', '1MiB', '100%'], calls)
        self.assertIn(['mkfs.ext4', '-L', 'data', '/dev/nvme1n1p1'], calls)
        self.assertIn(['chown', '%d:1002' % (os.getuid() or 1001), str(self.root / 'data')], calls)
        self.assertTrue(all('-F' not in c and '-f' not in c for c in calls))
        self.assertIn('UUID=12345678-abcd-1234-abcd-123456789abc /data ext4 defaults,nofail 0 2', (self.root / 'etc/fstab').read_text())
        self.assertEqual((self.root / 'etc/fstab.fleet-apply.bak').read_text(), '# original\n')
        self.run_jobs()
        self.assertEqual(calls, self.argv())
        self.assertEqual((self.root / 'data').stat().st_mode & 0o777, 0o755)

    def test_happy_xfs(self):
        self.job['fstype'] = self.fixture['fstype'] = 'xfs'
        self.assertEqual(self.run_jobs()['state'], 'done')
        self.assertIn(['mkfs.xfs', '-L', 'data', '/dev/nvme1n1p1'], self.argv())

    def test_refuse_device_facts(self):
        cases = dict(serial='other', size=1, model='other', children=[{'type':'part'}],
                     fstype='ext4', uuid='existing', label='existing', pttype='gpt', mountpoints=['/data'], rm=True, ro=True,
                     type='lvm', kname='loop0')
        for key, value in cases.items():
            with self.subTest(key=key):
                self.fixture['device'] = dict(self.device, **{key:value})
                self.assert_refused()
                self.dest.unlink()

    def test_refuse_signature(self):
        self.fixture['signature'] = 'ext4'
        self.assert_refused()

    def test_refuse_swap(self):
        (self.root / 'proc/swaps').write_text('header\n/dev/nvme1n1 partition 1 0 -2\n')
        self.assert_refused()

    def test_refuse_holders(self):
        (self.root / 'sys/block/nvme1n1/holders/dm-0').touch()
        self.assert_refused()

    def test_refuse_boot(self):
        self.fixture['boot'] = [dict(kname='nvme1n1', children=[dict(kname='nvme1n1p1', mountpoints=['/'])])]
        self.assert_refused()

    def test_refuse_flat_boot_chain(self):
        self.fixture['boot'] = [dict(kname='dm-0', pkname='nvme1n1', mountpoints=['/boot']), dict(kname='nvme1n1')]
        self.assert_refused()

    def test_refuse_nonempty_mount(self):
        (self.root / 'data').mkdir()
        (self.root / 'data/file').touch()
        self.assert_refused()

    def test_refuse_mounted_target(self):
        self.fixture['mounted'] = True
        self.assert_refused()

    def test_refuse_fstab_target(self):
        (self.root / 'etc/fstab').write_text('UUID=existing /data ext4 defaults 0 2\n')
        self.assert_refused()

    def test_refuse_owner(self):
        for owner in ('missing', 'low'):
            self.job['owner'] = owner
            self.assert_refused()
            self.dest.unlink()

    def test_refuse_bad_stable_alias(self):
        (self.root / 'dev/disk/by-id/nvme-Example_example').unlink()
        self.assert_refused()

    def test_failed_after_partitioning_no_cleanup_or_retry(self):
        self.fixture['fail'] = 'mkfs.ext4'
        result = self.run_jobs()
        self.assertEqual(result['state'], 'failed')
        self.assertEqual(result['step'], 'filesystem')
        calls = self.argv()
        self.run_jobs()
        self.assertEqual(calls, self.argv())
        self.assertFalse(any(c[0] == 'mount' for c in calls))
        self.assertEqual((self.root / 'etc/fstab').read_text(), '# original\n')

    def test_invalid_input_never_runs_commands(self):
        cases = ['{', '{}', '[{"id":"duplicate","id":"duplicate"}]', '[] []', ' ' * 65537]
        for field in ('force', 'wipe'):
            cases.append(json.dumps([dict(self.job, **{field:True})]))
        for value in ('/etc/data','/','/data/../etc'):
            cases.append(json.dumps([dict(self.job,mount_point=value)]))
        cases.append(json.dumps([dict(self.job,owner='root')]))
        for raw in cases:
            self.input.write_text(raw)
            self.applier.disk_jobs()
            self.assertEqual(self.argv(), [])
        self.input.unlink()
        other = self.input.with_name('other.json')
        other.write_text(json.dumps([self.job]))
        self.input.symlink_to(other)
        self.applier.disk_jobs()
        self.assertEqual(self.argv(), [])

    def test_read_input_ownership_and_directory_links(self):
        self.input.write_text(json.dumps([self.job]))
        self.applier.agent_uid = os.getuid() + 1
        with self.assertRaises(ValueError):
            self.applier.disk_input()
        self.applier.agent_uid = os.getuid()
        original = self.input.parent
        renamed = original.with_name('real-config')
        original.rename(renamed)
        original.symlink_to(renamed, target_is_directory=True)
        with self.assertRaises(OSError):
            self.applier.disk_input()
        self.assertEqual(self.argv(), [])

    def test_refuse_wwn_mismatch(self):
        self.fixture['device'] = dict(self.device, wwn='other')
        self.assert_refused()

    def test_refuse_escaped_fstab_target(self):
        (self.root / 'etc/fstab').write_text('UUID=existing /dat\\141 ext4 defaults 0 2\n')
        self.assert_refused()

    def test_refuse_symlink_mountpoint(self):
        (self.root / 'target').mkdir()
        (self.root / 'data').symlink_to('target')
        self.assert_refused()

    def test_refuse_unavailable_signature_check(self):
        self.fixture['fail'] = 'wipefs'
        self.assert_refused()

    def test_resume_requires_existing_receipt_to_be_kept(self):
        self.dest.parent.mkdir(parents=True)
        self.dest.write_text('{"state":"failed","step":"partition","reason":"Interrupted"}')
        self.assertEqual(self.run_jobs()['state'], 'failed')
        self.assertEqual(self.argv(), [])

    def test_dry_run(self):
        self.applier.args.dry_run = True
        self.assertIsNone(self.run_jobs())
        self.assertFalse(any(c[0] == 'parted' for c in self.argv()))


if __name__ == '__main__':
    unittest.main()
