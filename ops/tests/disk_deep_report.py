#!/usr/bin/env python3
from unittest import mock
import subprocess, sys, errno
import copy, hashlib, importlib.util, json, os, pathlib, tempfile, unittest
spec = importlib.util.spec_from_file_location('deep', pathlib.Path(__file__).resolve().parents[2] / 'internal/scriptcatalog/disk-deep-report-v1.py')
deep = importlib.util.module_from_spec(spec); spec.loader.exec_module(deep)
POLICY = {'protect_paths': [], 'scan_budgets': {'max_items':500, 'max_entries':200000, 'max_seconds':600}}
class DeepTests(unittest.TestCase):
    def test_categories_protection_identity_no_writes(self):
        with tempfile.TemporaryDirectory() as root:
            files = ['app.bak', 'clawctl-agent-backup-old', '.cache/big', 'releases/old/binary', '.codex/sessions/old.json', 'model.gguf', 'first.tar.gz', 'second.tar.gz', 'secret.bak', 'rollback.old', 'repo/.git/config', 'repo/old.bak', '.codex/generated_images/private.old']
            for name in files:
                p=pathlib.Path(root,name);p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b'fixture archive' * 100)
                os.utime(p, ns=(1000000000000000000,1000000000000000000))
            os.link(root+'/app.bak',root+'/hardlink.old')
            os.symlink(root+'/secret.bak',root+'/symlink.bak')
            before={str(p):(p.lstat().st_atime_ns,p.lstat().st_mtime_ns,p.lstat().st_ctime_ns,p.lstat().st_size) for p in pathlib.Path(root).rglob('*')}
            # rglob itself changes directory atime. Snapshot after enumeration.
            before={p:(os.lstat(p).st_atime_ns,os.lstat(p).st_mtime_ns,os.lstat(p).st_ctime_ns,os.lstat(p).st_size) for p in before}
            before[root]=(os.stat(root).st_atime_ns,os.stat(root).st_mtime_ns,os.stat(root).st_ctime_ns,os.stat(root).st_size)
            report=deep.scan(POLICY,500,[root])
            after={p:(os.lstat(p).st_atime_ns,os.lstat(p).st_mtime_ns,os.lstat(p).st_ctime_ns,os.lstat(p).st_size) for p in before}
            self.assertEqual(before,after)
            self.assertEqual(set(before),{root}|{str(p) for p in pathlib.Path(root).rglob('*')})
            for name in files:
                fd=os.open(root+'/'+name,os.O_RDONLY|os.O_NOATIME|os.O_NOFOLLOW)
                try:self.assertEqual(os.read(fd,65536),b'fixture archive'*100)
                finally:os.close(fd)
            paths=[i['private_path'] for i in report['items']]
            self.assertFalse(any('secret' in p or 'rollback' in p or '/repo/' in p or 'generated_images' in p or 'symlink' in p for p in paths))
            self.assertEqual(len([p for p in paths if p.endswith(('app.bak','hardlink.old'))]),1)
            self.assertGreater(report['excluded']['protected']['count'],0)
            self.assertTrue({'app-update-backups','caches-models','release-build-directories','agent-session-stores','duplicate-archives'}.issubset({i['category'] for i in report['items']}))
            duplicates=[i for i in report['items'] if i['category']=='duplicate-archives']
            self.assertEqual(len([i for i in duplicates if i['confidence']=='high']),1)
            self.assertTrue(all(i['content_digest']=='sha256:'+hashlib.sha256(b'fixture archive'*100).hexdigest() for i in duplicates))
            self.assertEqual([i['allocated_bytes'] for i in report['items']],sorted([i['allocated_bytes'] for i in report['items']],reverse=True))
    def test_budgets_and_inaccessible(self):
        with tempfile.TemporaryDirectory() as root:
            for n in range(10):pathlib.Path(root,str(n)+'.bak').write_bytes(b'x')
            report=deep.scan(POLICY,2,[root]);self.assertEqual(len(report['items']),2);self.assertTrue(report['truncated']);self.assertTrue(report['partial'])
            policy=copy.deepcopy(POLICY);policy['scan_budgets']['max_entries']=1
            report=deep.scan(policy,500,[root]);self.assertEqual(report['entries'],1);self.assertTrue(report['truncated'])
            report=deep.scan(POLICY,500,[root+'/missing']);self.assertTrue(report['partial']);self.assertTrue(report['inaccessible_roots'])
    def test_docker_stopped_references_digest_and_unknown_reclaim(self):
        result={'items':[], 'partial':False, 'truncated':False, 'notices':[]}
        used='sha256:'+'1'*64
        unused='sha256:'+'2'*64
        manifest='sha256:'+'3'*64
        calls=[]
        def run(argv, **kwargs):
            calls.append(argv)
            args=argv[3:]
            if args[:3]==['container','ls','-aq']:data='stopped-container'
            elif args[:2]==['container','inspect']:data=used
            elif args[:2]==['image','ls']:
                data='\n'.join(json.dumps(x) for x in [{'ID':used,'Digest':manifest,'Tag':'old'}, {'ID':unused,'Digest':manifest,'Tag':'old'}, {'ID':unused,'Digest':manifest,'Tag':'alias'}])
            elif args[:2]==['image','inspect']:data=json.dumps([{'Id':unused,'Size':1048576}])
            else:raise AssertionError(argv)
            return original_popen([sys.executable, '-c', 'import sys; sys.stdout.write(sys.argv[1])', data], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        original_popen = subprocess.Popen
        with mock.patch.object(deep.subprocess,'Popen',side_effect=run):deep.inventory_docker(result,500,deep.time.monotonic()+60)
        self.assertEqual(len(result['items']),1)
        item=result['items'][0]
        self.assertEqual(item['content_digest'],manifest)
        self.assertEqual(item['allocated_bytes'],0)
        self.assertEqual(item['logical_bytes'],1048576)
        self.assertEqual(item['suggested_action'],'investigate')
        self.assertTrue(all(c[1:3]==['--config','/nonexistent/clawctl-disk-report'] for c in calls))
    def test_docker_bounded_output_kills_overflow_and_timeout(self):
        original_popen = subprocess.Popen
        for code in ["import os,time; os.write(1,b'x'*(3*1024*1024)); time.sleep(30)", "import time; time.sleep(30)"]:
            processes=[]
            def spawn(argv, **kwargs):
                p=original_popen([sys.executable,'-c',code],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
                processes.append(p)
                return p
            result={'items':[], 'partial':False, 'truncated':False, 'notices':[]}
            with mock.patch.object(deep.subprocess,'Popen',side_effect=spawn):
                deep.inventory_docker(result,500,deep.time.monotonic()+0.3)
            self.assertTrue(result['partial'])
            self.assertEqual(result['items'],[])
            self.assertEqual(len(processes),1)
            self.assertIsNotNone(processes[0].poll())
            self.assertLess(processes[0].returncode,0)
            self.assertTrue(processes[0].stdout.closed)
    def test_root_noatime_eperm_skips_without_fallback(self):
        with tempfile.TemporaryDirectory() as root:
            pathlib.Path(root,'old.bak').write_bytes(b'fixture')
            original=deep.os.open
            calls=[]
            def opened(name,flags,*args,**kwargs):
                calls.append((name,flags))
                if name=='.' and flags & os.O_NOATIME:
                    raise PermissionError(errno.EPERM,'no permission')
                return original(name,flags,*args,**kwargs)
            before=os.stat(root).st_atime_ns
            with mock.patch.object(deep.os,'open',side_effect=opened):report=deep.scan(POLICY,500,[root])
            self.assertEqual(report['items'],[])
            self.assertTrue(report['partial'])
            self.assertIn('reviewed-root-1 skipped: no O_NOATIME permission',report['notices'])
            self.assertEqual(before,os.stat(root).st_atime_ns)
            self.assertEqual(sum(name=='.' for name,flags in calls),1)
    def test_protection_normalization_missing_and_alias_noatime(self):
        with tempfile.TemporaryDirectory() as root:
            protected=pathlib.Path(root,'protected');protected.mkdir()
            (protected/'private.bak').write_bytes(b'fixture')
            (pathlib.Path(root)/'public.bak').write_bytes(b'fixture')
            policy=copy.deepcopy(POLICY);policy['protect_paths']=[str(protected)+'/../protected',root+'/missing']
            report=deep.scan(policy,500,[root])
            self.assertEqual([pathlib.Path(i['private_path']).name for i in report['items']],['public.bak'])
            alias=pathlib.Path(root,'alias');alias.symlink_to(protected)
            policy['protect_paths']=[str(alias)]
            class Flags: f_flag=os.ST_NOATIME
            before=alias.lstat().st_atime_ns
            with mock.patch.object(deep.os,'statvfs',return_value=Flags()):
                normalized=deep.normalized_protections(policy)
                self.assertIn(str(protected),normalized['_protection_paths'])
            # On ordinary relatime filesystems aliases must defer rather than be read.
            class NoFlags: f_flag=0
            with mock.patch.object(deep.os,'statvfs',return_value=NoFlags()):report=deep.scan(policy,500,[root])
            self.assertTrue(report['partial']);self.assertEqual(report['items'],[])
            self.assertIn('Protection path resolution failed',report['notices'][-1])
            # Snapshot after the deliberately permitted normalization above.
            alias_before=alias.lstat().st_atime_ns
            with mock.patch.object(deep.os,'statvfs',return_value=NoFlags()):deep.scan(policy,500,[root])
            self.assertEqual(alias_before,alias.lstat().st_atime_ns)
    def test_content_hash_noatime_failure_is_weak(self):
        with tempfile.TemporaryDirectory() as root:
            path=pathlib.Path(root,'old.tar.gz');path.write_bytes(b'archive')
            original=deep.os.open
            def opened(name,flags,*args,**kwargs):
                if name=='old.tar.gz':raise PermissionError(errno.EPERM,'no-atime unavailable')
                return original(name,flags,*args,**kwargs)
            with mock.patch.object(deep.os,'open',side_effect=opened):report=deep.scan(POLICY,500,[root])
            self.assertEqual(len(report['items']),1)
            self.assertEqual(report['items'][0]['evidence_strength'],'weak')
            self.assertNotIn('content_digest',report['items'][0])
            self.assertIn('Archive hashing skipped: no O_NOATIME permission',report['notices'])
    def test_process_noatime_permission_denial_is_explicit(self):
        result={'items':[], 'partial':False, 'notices':[]}
        with mock.patch.object(deep.os,'open',side_effect=PermissionError(errno.EPERM,'no permission')):
            deep.inventory_processes(result,500,deep.time.monotonic()+60)
            self.assertEqual(deep.file_holders(deep.time.monotonic()+60,100,result), (set(),False,0))
        self.assertTrue(result['partial'])
        self.assertEqual(result['notices'].count('Process-holder inventory skipped: no O_NOATIME permission'),1)
        self.assertEqual(result['items'],[])
    def test_installer_leftovers_fixture(self):
        with tempfile.TemporaryDirectory() as root:
            pathlib.Path(root,'clawctl-agent-bootstrap-old.tar.gz').write_bytes(b'fixture')
            report=deep.scan(POLICY,500,[root])
            self.assertEqual(report['items'][0]['category'],'installer-leftovers')
            self.assertEqual(report['items'][0]['suggested_action'],'investigate')
            self.assertIn('holder',report['items'][0]['exclusion_reason'])
    def test_orphan_process_fixture_start_owner_holder_count(self):
        with tempfile.TemporaryDirectory() as root:
            boot=pathlib.Path(root,'sys/kernel/random/boot_id');boot.parent.mkdir(parents=True);boot.write_text('fixture-boot')
            proc=pathlib.Path(root,'100');(proc/'fd').mkdir(parents=True)
            fields=['S','999']+['0']*17+['123']
            (proc/'stat').write_text('100 (codex-linux-san) '+' '.join(fields))
            os.symlink('/tmp/stale.lock',proc/'fd/3')
            result={'items':[],'partial':False,'truncated':False,'notices':[]}
            deep.inventory_processes(result,500,deep.time.monotonic()+60,root)
            self.assertEqual(len(result['items']),1)
            item=result['items'][0]
            self.assertEqual(item['category'],'orphaned-processes')
            self.assertEqual((item['pid'],item['start_time'],item['holder_count']),(100,'123',1))
            self.assertEqual(item['owner_uid'],os.geteuid())
            self.assertEqual(item['suggested_action'],'investigate')
    def test_time_budget_and_mount_boundary(self):
        with tempfile.TemporaryDirectory() as root:
            pathlib.Path(root,'other-device.bak').write_bytes(b'fixture')
            original=deep.os.stat
            class OtherDevice:
                def __init__(self,s):self.value=s;self.st_dev=s.st_dev+1
                def __getattr__(self,key):return getattr(self.value,key)
            def checked(name,*args,**kwargs):
                value=original(name,*args,**kwargs)
                return OtherDevice(value) if name=='other-device.bak' else value
            with mock.patch.object(deep.os,'stat',side_effect=checked):report=deep.scan(POLICY,500,[root])
            self.assertEqual(report['items'],[])
            policy=copy.deepcopy(POLICY);policy['scan_budgets']['max_seconds']=1
            with mock.patch.object(deep.time,'monotonic',side_effect=[0,2,2]):report=deep.scan(policy,500,[root])
            self.assertTrue(report['truncated']);self.assertTrue(report['partial'])
if __name__=='__main__':unittest.main()
