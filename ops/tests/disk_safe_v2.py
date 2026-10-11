"""Closed adapter safety fixtures, using local stubs and no host cleanup."""
import contextlib, importlib.util, io, json, os, pathlib, subprocess, tempfile, time, unittest
from unittest.mock import patch
ROOT = pathlib.Path(__file__).resolve().parents[2]

def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / ('internal/scriptcatalog/disk-safe-' + name + '-v2.py'))
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj

POLICY = dict(schema_version=1, safe_tier=dict(user_tmp_min_days=10,var_tmp_min_days=14,cargo_min_days=30,docker_min_hours=168,npm_mode='verify-only',uv_mode='lock-aware-prune'), protect_paths=[], scan_budgets=dict(max_seconds=60,max_entries=200000))

class Safety(unittest.TestCase):
    def setUp(self):
        self.preview, self.clean = module('preview'), module('clean')
        self.temp = tempfile.TemporaryDirectory(prefix='disk-fixture-')
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        # This sandbox has a repository marker at /tmp itself. The fixture
        # represents a standalone filesystem; retain repository checks inside it.
        lexists = os.path.lexists
        def fixture_lexists(path):
            if str(path).endswith('/.git') and not str(path).startswith(str(self.root) + '/'):
                return False
            return lexists(path)
        protection = patch('os.path.lexists', side_effect=fixture_lexists)
        protection.start(); self.addCleanup(protection.stop)
        original_stat=os.stat
        def fixture_stat(path,*args,**kwargs):
            if path=='.git' and kwargs.get('dir_fd') is not None:
                target=os.readlink('/proc/self/fd/'+str(kwargs['dir_fd']))
                if not target.startswith(str(self.root)):
                    raise FileNotFoundError()
            return original_stat(path,*args,**kwargs)
        stats=patch('os.stat',side_effect=fixture_stat)
        stats.start();self.addCleanup(stats.stop)
    def old(self, name):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('fixture')
        age = time.time() - 40 * 86400
        os.utime(path, (age, age))
        return path
    def test_preview_preserves_mtime_atime_and_contents(self):
        file = self.old('stale-test-temp/result.txt')
        # Prime directory times before the snapshot; preview uses O_NOATIME.
        before = {p: (p.stat().st_atime_ns, p.stat().st_mtime_ns) for p in [self.root,file.parent,file]}
        with patch.object(self.preview,'holders',return_value=({},True)):
            result = self.preview.scan(str(self.root), POLICY, {}, True, 10)
        self.assertEqual(result['candidate_bytes'],7)
        self.assertEqual(before,{p:(p.stat().st_atime_ns,p.stat().st_mtime_ns) for p in before})
        self.assertEqual(list(self.root.iterdir()),[file.parent])
    def test_protection_and_open_descriptor_override_age(self):
        files = [self.old(x) for x in ['repo/old.txt','.codex/generated_images/old.png','credentials.json','models/active.gguf','additive/old.txt','open.txt','cache.lock']]
        (self.root/'repo/.git').mkdir()
        policy=dict(POLICY,protect_paths=[str(self.root/'additive')])
        with open(files[5]) as held:
            self.assertIn(str(files[5]), self.clean.holders()[0])
            opened={str(files[5]):{'fixture'}}
            with patch.object(self.clean,'holders',return_value=(opened,True)):
                result=self.clean.scan(str(self.root),policy,opened,True,10,True)
        self.assertEqual(result['freed_bytes'],0)
        self.assertTrue(all(x.exists() for x in files))
    def test_owner_stale_regular_files_only(self):
        file=self.old('stale.txt'); fresh=self.root/'fresh.txt';fresh.write_text('new')
        with patch.object(self.clean,'holders',return_value=({},True)):
            result=self.clean.scan(str(self.root),POLICY,{},True,10,True)
        self.assertEqual(result['freed_bytes'],7);self.assertFalse(file.exists());self.assertTrue(fresh.exists())
    def native(self, tool, command, opened=None, timeout=False):
        cache=self.root/'cache';cache.mkdir(exist_ok=True)
        executable=self.root/tool
        executable.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "'+str(self.root/'args')+'"\n')
        executable.chmod(0o755)
        with patch.dict(os.environ,PATH=str(self.root)+':/usr/bin:/bin'), patch.object(self.clean,'holders',return_value=(opened or {},True)):
            if timeout:
                with patch.object(self.clean.subprocess,'run',side_effect=subprocess.TimeoutExpired(command,60)):
                    return self.clean.native(tool,str(cache),command,POLICY,opened or {},True)
            return self.clean.native(tool,str(cache),command,POLICY,opened or {},True)
    def test_uv_lock_holder_count_and_timeout(self):
        held={str(self.root/'cache/.lock'):{'1','2'}}
        result=self.native('uv',['uv','cache','prune'],held)
        self.assertEqual(result['note'],'deferred: cache lock held by 2');self.assertFalse((self.root/'args').exists())
        result=self.native('uv',['uv','cache','prune'],timeout=True)
        self.assertEqual(result['status'],'skipped');self.assertIn('timeout',result['note'])
    def test_native_uv_and_npm_verify_only(self):
        for command in [['uv','cache','prune'],['npm','cache','verify']]:
            self.assertEqual(self.native(command[0],command)['status'],'ok')
            self.assertEqual((self.root/'args').read_text().splitlines(),command[1:])
        for adapter in [self.preview,self.clean]:
            source=pathlib.Path(adapter.__file__).read_text()
            self.assertNotIn('clean --force',source);self.assertNotIn("'--force'",source)
    def test_unheld_uv_lock_is_retained_and_cargo_is_unsupported(self):
        cache=self.root/'cache';cache.mkdir()
        lock=cache/'.lock';lock.write_text('')
        self.assertEqual(self.native('uv',['uv','cache','prune'])['status'],'ok')
        self.assertTrue(lock.exists())
        request=json.dumps(dict(args=dict(scope='user',policy_id='fixture',policy_digest='sha256:'+'a'*64),policy=POLICY))
        output=io.StringIO()
        with patch.dict(os.environ,HOME=str(self.root)), patch.object(self.preview,'holders',return_value=({},True)), patch('sys.stdin',io.StringIO(request)), contextlib.redirect_stdout(output):
            self.preview.main()
        result=json.loads(output.getvalue())
        self.assertEqual(result['summary']['categories']['cargo']['status'],'skipped')
        self.assertIn('unsupported',result['summary']['categories']['cargo']['note'])
        self.assertFalse((self.root/'.local/state/disk-clean').exists())

    def test_docker_exact_filters_and_journal_cap(self):
        for command in self.clean.DOCKER_COMMANDS:
            self.native('docker',command)
            self.assertEqual((self.root/'args').read_text().splitlines(),command[1:])
        self.assertEqual(self.clean.DOCKER_COMMANDS,[['docker','image','prune','-f','--filter','until=168h'],['docker','builder','prune','-f','--filter','until=168h']])
        self.assertEqual(self.clean.JOURNAL_COMMAND,['journalctl','--vacuum-size=500M'])
    def test_preview_never_runs_native_gc(self):
        cache=self.root/'cache';cache.mkdir()
        with patch.object(self.preview.shutil,'which',return_value='/usr/bin/uv'),patch.object(self.preview.subprocess,'run',side_effect=AssertionError('preview GC')):
            result=self.preview.native('uv',str(cache),['uv','cache','prune'],POLICY,{},True)
        self.assertEqual(result['status'],'ok')
    def test_incomplete_visibility_and_cargo_root_skips(self):
        self.assertEqual(self.clean.native('uv',str(self.root),['uv','cache','prune'],POLICY,{},False)['status'],'skipped')
        request=json.dumps(dict(args=dict(scope='root',policy_id='fixture',policy_digest='sha256:'+'a'*64),policy=POLICY))
        for name in ['preview','clean']:
            out=subprocess.run(['/usr/bin/python3','-I','-B',str(ROOT/('internal/scriptcatalog/disk-safe-'+name+'-v2.py'))],input=request,text=True,capture_output=True,check=True)
            result=json.loads(out.stdout)
            self.assertTrue(all(x['note']=='root_helper_missing' for x in result['summary']['categories'].values()))
            self.assertEqual(result['operation']['ownership'],'local-timer')
            self.assertEqual(result['operation']['skip_code'],'root_helper_missing')

if __name__=='__main__': unittest.main()
