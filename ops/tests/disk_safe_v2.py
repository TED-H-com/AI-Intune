"""Closed adapter safety fixtures, using local stubs and no host cleanup."""
import contextlib, importlib.util, io, json, os, pathlib, subprocess, tempfile, time, unittest
from unittest.mock import patch
ROOT = pathlib.Path(__file__).resolve().parents[2]

def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / ('internal/scriptcatalog/disk-safe-' + name + '-v2.py'))
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj

POLICY = dict(schema_version=1, safe_tier=dict(user_tmp_min_days=10,var_tmp_min_days=14,cargo_min_days=30,docker_min_hours=168,npm_mode='verify-only',uv_mode='lock-aware-prune'), protect_paths=[], scan_budgets=dict(max_seconds=60,max_entries=200000,max_items=500))

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
        for command in self.clean.DOCKER_COMMANDS:
            self.assertFalse(set(command) & {'--force','system','volume','container','-a','--all'})
        self.assertEqual(self.clean.JOURNAL_COMMAND,['journalctl','--vacuum-size=500M'])
    def test_preview_never_runs_native_gc(self):
        cache=self.root/'cache';cache.mkdir()
        with patch.object(self.preview.shutil,'which',return_value='/usr/bin/uv'),patch.object(self.preview.subprocess,'run',side_effect=AssertionError('preview GC')):
            result=self.preview.native('uv',str(cache),['uv','cache','prune'],POLICY,{},True)
        self.assertEqual(result['status'],'ok')
    def test_max_items_bounds_preview_and_clean(self):
        for i in range(507): self.old('eligible/item-%04d' % i)
        for adapter, mutate in [(self.preview,False),(self.clean,True)]:
            with patch.object(adapter,'holders',return_value=({},True)):
                result=adapter.scan(str(self.root),POLICY,{},True,10,mutate)
            self.assertEqual(result['items'],500)
            self.assertEqual(result['candidate_bytes'],3500)
            self.assertIn('incomplete: max_items',result['note'])
            self.assertEqual(result['freed_bytes'],3500 if mutate else 0)
        self.assertEqual(len(list((self.root/'eligible').iterdir())),7)

    def test_inode_alias_and_held_directory_subtree(self):
        file=self.old('original.txt')
        with open(file) as descriptor:
            info=os.fstat(descriptor.fileno())
            renamed=self.root/'renamed.txt';file.rename(renamed)
            opened={(info.st_dev,info.st_ino):{'fixture'}}
            self.assertIn((info.st_dev,info.st_ino),self.clean.holders()[0])
            for adapter in [self.preview,self.clean]:
                with patch.object(adapter,'holders',return_value=(opened,True)):
                    self.assertEqual(adapter.scan(str(self.root),POLICY,opened,True,10,adapter.APPLY)['items'],0)
            self.assertTrue(renamed.exists())
        child=self.old('directory/child.txt')
        fd=os.open(child.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:
            info=os.fstat(fd)
            directory=self.root/'moved';child.parent.rename(directory)
            opened={('dir',info.st_dev,info.st_ino):{'fixture'}}
            for adapter in [self.preview,self.clean]:
                with patch.object(adapter,'holders',return_value=(opened,True)):
                    self.assertEqual(adapter.scan(str(self.root),POLICY,opened,True,10,adapter.APPLY)['items'],1)
            self.assertTrue((directory/'child.txt').exists())
        finally: os.close(fd)

    def test_inode_holder_rechecked_immediately_before_unlink(self):
        file=self.old('recheck.txt');info=file.stat()
        opened={(info.st_dev,info.st_ino):{'fixture'}}
        with patch.object(self.clean,'holders',return_value=(opened,True)):
            self.assertFalse(self.clean.unlink_checked(str(file),info,POLICY))
        self.assertTrue(file.exists())

    def test_cache_swap_before_spawn_is_refused(self):
        cache=self.root/'cache';cache.mkdir()
        other=self.root/'other';other.mkdir()
        real_entries=self.clean.entries
        def swapped(path):
            names=real_entries(path)
            if path==str(cache):
                cache.rename(self.root/'original-cache');cache.symlink_to(other,target_is_directory=True)
            return names
        with patch.object(self.clean,'entries',side_effect=swapped), patch.object(self.clean.shutil,'which',return_value='/usr/bin/uv'), patch.object(self.clean,'holders',return_value=({},True)), patch.object(self.clean.subprocess,'run',side_effect=AssertionError('unsafe spawn')):
            result=self.clean.native('uv',str(cache),['uv','cache','prune'],POLICY,{},True)
        self.assertEqual(result['status'],'skipped');self.assertIn('changed',result['note'])

    def test_cache_swap_at_spawn_keeps_inherited_directory(self):
        for tool, command in [('uv',['uv','cache','prune']),('npm',['npm','cache','verify'])]:
            cache=self.root/(tool+'-cache');cache.mkdir()
            other=self.root/(tool+'-other');other.mkdir()
            info=cache.stat()
            def spawn(argv,**kwargs):
                fd=kwargs['pass_fds'][0]
                self.assertEqual((os.fstat(fd).st_dev,os.fstat(fd).st_ino),(info.st_dev,info.st_ino))
                key='UV_CACHE_DIR' if tool=='uv' else 'npm_config_cache'
                self.assertEqual(kwargs['env'][key],'/proc/self/fd/'+str(fd))
                cache.rename(self.root/(tool+'-original'));cache.symlink_to(other,target_is_directory=True)
                self.assertEqual(os.stat(kwargs['env'][key]).st_ino,info.st_ino)
                return subprocess.CompletedProcess(argv,0)
            with patch.object(self.clean.shutil,'which',return_value='/usr/bin/'+tool),patch.object(self.clean,'holders',return_value=({},True)),patch.object(self.clean.subprocess,'run',side_effect=spawn):
                result=self.clean.native(tool,str(cache),command,POLICY,{},True)
            self.assertEqual(result['status'],'skipped');self.assertIn('changed',result['note'])
            self.assertEqual(list(other.iterdir()),[])

    def test_final_identity_after_holder_scan_substitution(self):
        for kind in ['replacement', 'symlink', 'directory', 'content-change']:
            with self.subTest(kind=kind):
                file=self.old('unlink-'+kind+'.txt');info=file.stat()
                def swap(**kwargs):
                    if kind=='content-change':
                        file.write_text('changed size and timestamps')
                    else:
                        file.rename(self.root/('retained-'+kind))
                        if kind=='replacement': file.write_text('replacement')
                        elif kind=='symlink': file.symlink_to(self.root/'retained-symlink')
                        else: file.mkdir()
                    return {},True
                with patch.object(self.clean,'holders',side_effect=swap):
                    self.assertFalse(self.clean.unlink_checked(str(file),info,POLICY))
                self.assertTrue(file.exists())

    def test_native_root_ownership_and_protection_boundaries(self):
        cache=self.root/'owned-cache';cache.mkdir()
        class WrongOwner:
            st_uid=os.geteuid()+1
        for adapter in [self.preview,self.clean]:
            with patch.object(adapter.os,'fstat',return_value=WrongOwner()):
                result=adapter.native('uv',str(cache),['uv','cache','prune'],POLICY,{},True)
            self.assertIn('not user-owned',result['note'])
            for protect in [cache,cache/'nested',self.root]:
                with patch.object(adapter.shutil,'which',return_value='/usr/bin/uv'):
                    result=adapter.native('uv',str(cache),['uv','cache','prune'],dict(POLICY,protect_paths=[str(protect)]),{},True)
                self.assertEqual(result['status'],'skipped');self.assertIn('protected',result['note'])
            (cache/'.git').mkdir()
            with patch.object(adapter.shutil,'which',return_value='/usr/bin/uv'):
                self.assertIn('protected',adapter.native('uv',str(cache),['uv','cache','prune'],POLICY,{},True)['note'])
            (cache/'.git').rmdir()
            repo=cache/'nested-repo';repo.mkdir();(repo/'.git').mkdir()
            with patch.object(adapter.shutil,'which',return_value='/usr/bin/uv'):
                self.assertIn('protected',adapter.native('uv',str(cache),['uv','cache','prune'],POLICY,{},True)['note'])
            (repo/'.git').rmdir();repo.rmdir()
            link=self.root/'root-link';link.symlink_to(cache,target_is_directory=True)
            self.assertEqual(adapter.native('uv',str(link),['uv','cache','prune'],POLICY,{},True)['status'],'skipped')
            link.unlink()

    def test_native_parent_alias_cannot_bypass_protection(self):
        actual=self.root/'actual';(actual/'cache').mkdir(parents=True)
        alias=self.root/'alias';alias.symlink_to(actual,target_is_directory=True)
        for adapter in [self.preview,self.clean]:
            with patch.object(adapter.shutil,'which',return_value='/usr/bin/uv'),patch.object(adapter.subprocess,'run',side_effect=AssertionError('protected alias spawn')):
                result=adapter.native('uv',str(alias/'cache'),['uv','cache','prune'],dict(POLICY,protect_paths=[str(actual/'cache'/'protected')]),{},True)
            self.assertEqual(result['status'],'skipped')
            self.assertIn('protected' if adapter.APPLY else 'resolution failed',result['note'])

    def test_native_escaping_symlinks_and_bounded_scan(self):
        cache=self.root/'cache';cache.mkdir()
        outside=self.root/'outside';outside.mkdir()
        for depth in [1,2]:
            directory=cache if depth==1 else cache/'nested'
            directory.mkdir(exist_ok=True)
            link=directory/'escape';link.symlink_to(outside,target_is_directory=True)
            for adapter in [self.preview,self.clean]:
                with patch.object(adapter.shutil,'which',return_value='/usr/bin/npm'),patch.object(adapter.subprocess,'run',side_effect=AssertionError('unsafe spawn')):
                    result=adapter.native('npm',str(cache),['npm','cache','verify'],POLICY,{},True)
                self.assertIn('symlink escapes root' if adapter.APPLY else 'resolution failed',result['note'])
            link.unlink()
        for i in range(5): (cache/('entry-'+str(i))).write_text('data')
        policy=dict(POLICY,scan_budgets=dict(POLICY['scan_budgets'],max_entries=2))
        with patch.object(self.clean.shutil,'which',return_value='/usr/bin/npm'),patch.object(self.clean.subprocess,'run',side_effect=AssertionError('unbounded spawn')):
            self.assertIn('budget exceeded',self.clean.native('npm',str(cache),['npm','cache','verify'],policy,{},True)['note'])

    def test_native_contained_symlink_is_allowed(self):
        cache=self.root/'cache';cache.mkdir()
        (cache/'content').write_text('data');(cache/'alias').symlink_to(cache/'content')
        self.assertEqual(self.native('npm',['npm','cache','verify'])['status'],'ok')

    def test_configured_protection_alias_blocks_native_cache_gc(self):
        cache=self.root/'cache';(cache/'content').mkdir(parents=True)
        alias=self.root/'protection-alias';alias.symlink_to(cache/'content',target_is_directory=True)
        policy=dict(POLICY,protect_paths=[str(alias)])
        for adapter in [self.preview,self.clean]:
            with patch.object(adapter.shutil,'which',return_value='/usr/bin/uv'),patch.object(adapter.subprocess,'run',side_effect=AssertionError('protected GC')):
                result=adapter.native('uv',str(cache),['uv','cache','prune'],policy,{},True)
            self.assertEqual(result['status'],'skipped');self.assertTrue('protected' in result['note'] or 'resolution failed' in result['note'])

    def test_configured_protection_alias_retains_tmp_subtree(self):
        file=self.old('tmp-candidates/keep.txt')
        alias=self.root/'protection-alias';alias.symlink_to(file.parent,target_is_directory=True)
        policy=dict(POLICY,protect_paths=[str(alias)])
        for adapter in [self.preview,self.clean]:
            with patch.object(adapter,'holders',return_value=({},True)):
                result=adapter.scan(str(file.parent),policy,{},True,10,adapter.APPLY)
            self.assertEqual(result['candidate_bytes'],0);self.assertEqual(result['freed_bytes'],0)
            self.assertTrue(file.exists())

    def test_builtin_alias_and_candidate_alias_use_both_path_sets(self):
        home=self.root/'home';home.mkdir()
        cache=self.root/'cache';cache.mkdir()
        (home/'.aws').symlink_to(cache,target_is_directory=True)
        for adapter in [self.preview,self.clean]:
            with patch.dict(os.environ,HOME=str(home)),patch.object(adapter.shutil,'which',return_value='/usr/bin/uv'):
                if adapter.APPLY:
                    policy=adapter.normalized_protections(POLICY)
                    self.assertIn(str(home/'.aws'),policy['_protection_paths'])
                    self.assertIn(str(cache),policy['_protection_paths'])
                result=adapter.native('uv',str(cache),['uv','cache','prune'],POLICY,{},True)
                self.assertEqual(result['status'],'skipped')
            alias=self.root/'candidate-alias';alias.symlink_to(cache,target_is_directory=True)
            if adapter.APPLY:
                self.assertTrue(adapter.protected(str(alias),dict(POLICY,protect_paths=[str(cache/'nested')])))
            else:
                with self.assertRaises(adapter.ProtectionResolutionError):
                    adapter.protected(str(alias),dict(POLICY,protect_paths=[str(cache/'nested')]))
            alias.unlink()

    def test_protection_resolution_errors_fail_closed(self):
        file=self.old('temp-data/old.txt')
        cache=self.root/'cache';cache.mkdir()
        dangling=self.root/'dangling';dangling.symlink_to(self.root/'absent')
        loop=self.root/'loop';loop.symlink_to(loop)
        absent=self.root/'missing-parent/missing-child'
        parent=self.root/'broken-parent';parent.symlink_to(self.root/'absent-parent')
        for adapter in [self.preview,self.clean]:
            ordinary=adapter.normalized_protections(dict(POLICY,protect_paths=[str(absent)]))
            self.assertIn(str(absent),ordinary['_protection_paths'])
            for alias in [dangling,loop,parent/'nested']:
                policy=dict(POLICY,protect_paths=[str(alias)])
                result=adapter.scan(str(file.parent),policy,{},True,10,adapter.APPLY)
                self.assertEqual(result['status'],'skipped');self.assertIn('protection path resolution failed',result['note'])
                with patch.object(adapter.subprocess,'run',side_effect=AssertionError('unresolved GC')):
                    result=adapter.native('uv',str(cache),['uv','cache','prune'],policy,{},True)
                self.assertIn('protection path resolution failed',result['note'])
            original=adapter.os.path.realpath
            def denied(path,**kwargs):
                if path==str(cache): raise PermissionError('fixture')
                return original(path,**kwargs)
            with patch.object(adapter.os.path,'realpath',side_effect=denied):
                result=adapter.scan(str(file.parent),dict(POLICY,protect_paths=[str(cache)]),{},True,10,adapter.APPLY)
            self.assertIn('protection path resolution failed',result['note'])
        self.assertTrue(file.exists())

    def test_preview_alias_resolution_preserves_symlink_atime(self):
        file=self.old('tmp-candidates/keep.txt')
        alias=self.root/'protection-alias';alias.symlink_to(file.parent,target_is_directory=True)
        age=time.time()-40*86400;os.utime(alias,(age,age),follow_symlinks=False)
        before=(os.lstat(alias).st_atime_ns,os.lstat(alias).st_mtime_ns)
        policy=dict(POLICY,protect_paths=[str(alias/'keep.txt')])
        result=self.preview.scan(str(file.parent),policy,{},True,10)
        self.assertEqual(result['status'],'skipped')
        self.assertEqual(before,(os.lstat(alias).st_atime_ns,os.lstat(alias).st_mtime_ns))
        self.assertTrue(file.exists())

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
