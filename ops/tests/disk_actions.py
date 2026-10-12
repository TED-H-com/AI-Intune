"""Quarantine/restore drill and adversarial filesystem fixtures; no host actions."""
import base64, hashlib, importlib.util, json, os, pathlib, subprocess, tempfile, time, unittest
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[2]
POLICY=dict(schema_version=1,quarantine_ttl_days=7,protect_paths=[],scan_budgets=dict(max_items=100,max_seconds=60))

class Actions(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='disk-action-fixture-');self.addCleanup(self.temp.cleanup)
        self.root=pathlib.Path(self.temp.name);self.home=self.root/'home';self.home.mkdir()
        self.file=self.root/'original'/'old.txt';self.file.parent.mkdir();self.file.write_bytes(b'preserved content')
        os.chmod(self.file,0o640);os.utime(self.file,ns=(123000000000,123000000000))
        self.mods={}
        for action,script in [('quarantine','disk-approved-quarantine'),('delete','disk-approved-delete'),('restore','disk-quarantine-restore'),('expire','disk-quarantine-expire')]:
            spec=importlib.util.spec_from_file_location(action,ROOT/('internal/scriptcatalog/'+script+'-v1.py'))
            mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);self.mods[action]=mod
        self.mod=self.mods['quarantine']
        expand=os.path.expanduser
        p=patch('os.path.expanduser',side_effect=lambda s:str(self.home) if s=='~' else expand(s));p.start();self.addCleanup(p.stop)
        exists=os.path.lexists
        p=patch('os.path.lexists',side_effect=lambda p:False if str(p).endswith('/.git') and not str(p).startswith(str(self.root)) else exists(p));p.start();self.addCleanup(p.stop)
        original_stat=os.stat
        def repo_stat(path,*args,**kwargs):
            if path=='.git' and kwargs.get('dir_fd') is not None:
                target=os.readlink('/proc/self/fd/'+str(kwargs['dir_fd']))
                if not target.startswith(str(self.root)):raise FileNotFoundError()
            return original_stat(path,*args,**kwargs)
        p=patch('os.stat',side_effect=repo_stat);p.start();self.addCleanup(p.stop)
        for mod in self.mods.values():
            p=patch.object(mod,'holders',return_value=({},True));p.start();self.addCleanup(p.stop)
            p=patch.object(mod,'renew',side_effect=lambda grant:dict(grant));p.start();self.addCleanup(p.stop)
        st=self.file.stat()
        self.item=dict(id='item-1',private_path=str(self.file),identity=self.mod.ident(st),owner_uid=os.geteuid(),allocated_bytes=st.st_blocks*512,category='installer-leftovers')
        self.manifest=dict(id='manifest-1',approval_id='approval-1',_digest='sha256:'+'a'*64,items=[self.item],ttl_seconds=604800)
        self.grant=dict(job_id='job-1',expires_at='2099-01-01T00:00:00Z')
    def run_action(self,action,manifest=None,policy=None):
        mod=self.mods[action]
        return mod.execute(self.grant,mod.normalized_protections(policy or dict(POLICY)),[manifest or self.manifest])
    def record(self):
        name=self.mod.record_name(self.manifest,self.item)
        q=self.home/'.local/state/ai-intune/quarantine'
        return q,name,json.loads((q/(name+'.json')).read_text())
    def restore_manifest(self):
        q,name,record=self.record()
        item=dict(self.item,identity=record['identity'])
        return dict(self.manifest,id='restore-1',quarantine_manifest_id=self.manifest['id'],items=[item])
    def test_round_trip_preserves_content_mode_uid_mtime_and_atime(self):
        before=self.file.stat()
        result=self.run_action('quarantine')
        self.assertEqual(result['items'][0]['status'],'quarantined');self.assertEqual(result['freed_bytes'],0)
        self.assertEqual(result['quarantined_bytes'],self.item['allocated_bytes']);self.assertFalse(self.file.exists())
        q,name,record=self.record();self.assertEqual(q.stat().st_mode&0o777,0o700)
        result=self.run_action('restore',self.restore_manifest())
        self.assertEqual(result['items'][0]['status'],'restored')
        after=self.file.stat()
        self.assertEqual((before.st_ino,before.st_dev,before.st_mode,before.st_uid,before.st_mtime_ns,before.st_atime_ns),(after.st_ino,after.st_dev,after.st_mode,after.st_uid,after.st_mtime_ns,after.st_atime_ns))
        self.assertEqual(self.file.read_bytes(),b'preserved content')
    def test_user_data_and_environment_credentials_override_approval(self):
        for name in ['Documents/old.txt','.env']:
            path=self.file.parent/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'private')
            item=dict(self.item,id='protected-item',private_path=str(path),identity=self.mod.ident(path.stat()))
            m=dict(self.manifest,items=[item])
            result=self.run_action('delete',m)
            self.assertEqual(result['items'][0]['reason'],'protected');self.assertTrue(path.exists())
    def test_files_writable_by_other_users_are_skipped(self):
        os.chmod(self.file,0o666);self.item['identity']=self.mod.ident(self.file.stat())
        result=self.run_action('quarantine')
        self.assertEqual(result['items'][0]['reason'],'shared_write_permissions');self.assertTrue(self.file.exists())
    def test_delete_counts_only_freed_bytes_and_replay_does_not_repeat(self):
        first=self.run_action('delete');self.assertEqual(first['items'][0]['status'],'deleted')
        self.assertEqual(first['quarantined_bytes'],0);self.assertEqual(first['freed_bytes'],self.item['allocated_bytes'])
        self.assertFalse(self.file.exists());second=self.run_action('delete');self.assertEqual(second['freed_bytes'],0)
    def test_stable_quarantine_entry_swapped_before_operation_capture(self):
        for action in ['delete','expire','restore']:
            with self.subTest(action=action):
                # Separate fixture item/manifest for each destructive adapter.
                self.file.write_bytes(b'preserved content')
                self.item['identity']=self.mod.ident(self.file.stat())
                self.item['id']='swap-'+action
                self.manifest['id']='manifest-'+action
                mod=self.mods[action]
                if action!='delete': self.run_action('quarantine')
                manifest=self.restore_manifest() if action=='restore' else self.manifest
                rename=mod.noreplace
                substituted=[]
                def swap(srcfd,src,dstfd,dst):
                    if src.endswith('.data') and '.op-' in dst and not substituted:
                        os.rename(src,src+'.saved',src_dir_fd=srcfd,dst_dir_fd=srcfd)
                        fd=os.open(src,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600,dir_fd=srcfd)
                        os.write(fd,b'attacker replacement');os.close(fd)
                        substituted.append((srcfd,src))
                    return rename(srcfd,src,dstfd,dst)
                with patch.object(mod,'noreplace',side_effect=swap):
                    if action=='expire':
                        with patch('time.time',return_value=time.time()+604802): result=self.run_action(action,manifest)
                    else: result=self.run_action(action,manifest)
                self.assertEqual(result['items'][0]['reason'],'staged_identity_changed')
                self.assertEqual(result['freed_bytes'],0)
                q,name,record=self.record()
                self.assertEqual((q/(name+'.data')).read_bytes(),b'attacker replacement')
                self.assertEqual((q/(name+'.data.saved')).read_bytes(),b'preserved content')
                self.assertFalse(self.file.exists())

    def test_restore_final_rename_substitution_is_verified_and_rolled_back(self):
        self.run_action('quarantine');manifest=self.restore_manifest();mod=self.mods['restore'];rename=mod.noreplace
        def replace_after(srcfd,src,dstfd,dst):
            rename(srcfd,src,dstfd,dst)
            if '.op-' in src and dst=='old.txt':
                os.rename(dst,dst+'.saved',src_dir_fd=dstfd,dst_dir_fd=dstfd)
                fd=os.open(dst,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600,dir_fd=dstfd)
                os.write(fd,b'attacker destination');os.close(fd)
        with patch.object(mod,'noreplace',side_effect=replace_after):result=self.run_action('restore',manifest)
        self.assertEqual(result['items'][0]['reason'],'restore_identity_changed')
        self.assertFalse(self.file.exists())
        self.assertEqual(self.file.with_name('old.txt.saved').read_bytes(),b'preserved content')
        q,name,_=self.record();self.assertEqual((q/(name+'.data')).read_bytes(),b'attacker destination')

    def test_stage_mismatch_with_occupied_rollback_retains_both_entries(self):
        self.run_action('quarantine');mod=self.mods['expire'];rename=mod.noreplace
        def replace(srcfd,src,dstfd,dst):
            if src.endswith('.data') and '.op-' in dst:
                os.rename(src,src+'.saved',src_dir_fd=srcfd,dst_dir_fd=srcfd)
                fd=os.open(src,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600,dir_fd=srcfd)
                os.write(fd,b'captured replacement');os.close(fd)
                rename(srcfd,src,dstfd,dst)
                fd=os.open(src,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600,dir_fd=srcfd)
                os.write(fd,b'occupied rollback');os.close(fd)
                return
            return rename(srcfd,src,dstfd,dst)
        with patch.object(mod,'noreplace',side_effect=replace),patch('time.time',return_value=time.time()+604802):result=self.run_action('expire')
        self.assertEqual(result['items'][0]['reason'],'stage_retained_for_recovery')
        q,name,record=self.record()
        self.assertEqual((q/record['operation_stage']).read_bytes(),b'captured replacement')
        self.assertEqual((q/(name+'.data')).read_bytes(),b'occupied rollback')
        self.assertEqual(result['freed_bytes'],0)

    def test_occupied_restore_never_overwrites(self):
        self.run_action('quarantine');m=self.restore_manifest();self.file.write_bytes(b'new data')
        result=self.run_action('restore',m)
        self.assertEqual(result['items'][0]['reason'],'destination_occupied');self.assertEqual(self.file.read_bytes(),b'new data')
        q,name,r=self.record();self.assertTrue((q/(name+'.data')).exists())
    def test_holder_appears_after_journal(self):
        mod=self.mod;save=mod.save
        def journal(*args):
            save(*args)
            mod.holders.return_value=({(self.item['identity']['dev'],self.item['identity']['inode']):{'holder'}},True)
        with patch.object(mod,'save',side_effect=journal):result=self.run_action('quarantine')
        self.assertEqual(result['items'][0]['reason'],'held');self.assertTrue(self.file.exists())
    def test_entry_substituted_after_first_verify(self):
        mod=self.mod;save=mod.save
        def journal(*args):
            save(*args);self.file.rename(self.file.with_suffix('.saved'));self.file.write_bytes(b'attacker')
        with patch.object(mod,'save',side_effect=journal):result=self.run_action('quarantine')
        self.assertEqual(result['items'][0]['reason'],'identity_changed');self.assertEqual(self.file.read_bytes(),b'attacker')
    def test_substitution_inside_rename_is_rolled_back_never_deleted(self):
        mod=self.mods['delete'];rename=mod.noreplace
        def swap(srcfd,src,dstfd,dst):
            self.file.rename(self.file.with_suffix('.saved'));self.file.write_bytes(b'attacker')
            rename(srcfd,src,dstfd,dst)
        calls=0
        def raced(*args):
            nonlocal calls
            calls+=1
            if calls==1:return swap(*args)
            return rename(*args)
        with patch.object(mod,'noreplace',side_effect=raced):result=self.run_action('delete')
        self.assertEqual(result['items'][0]['reason'],'rename_identity_changed')
        self.assertEqual(result['freed_bytes'],0);self.assertEqual(self.file.read_bytes(),b'attacker')
    def test_protection_alias_retargeted_during_journal(self):
        a=self.root/'a';b=self.root/'b';a.mkdir();b.mkdir();alias=self.root/'alias';alias.symlink_to(a,target_is_directory=True)
        policy=dict(POLICY,protect_paths=[str(alias)])
        save=self.mod.save
        def retarget(*args):save(*args);alias.unlink();alias.symlink_to(b,target_is_directory=True)
        with patch.object(self.mod,'save',side_effect=retarget):result=self.run_action('quarantine',policy=policy)
        self.assertEqual(result['items'][0]['reason'],'protection_changed');self.assertTrue(self.file.exists())
    def test_budget_shared_across_manifest_items(self):
        second=self.file.parent/'second.txt';second.write_bytes(b'second');st=second.stat()
        item=dict(self.item,id='item-2',private_path=str(second),identity=self.mod.ident(st))
        m=dict(self.manifest,items=[self.item,item]);result=self.run_action('quarantine',m,dict(POLICY,scan_budgets=dict(max_items=1,max_seconds=60)))
        self.assertEqual(result['items'][0]['status'],'quarantined');self.assertEqual(result['items'][1]['reason'],'budget_exhausted');self.assertTrue(second.exists())
    def test_expiry_budget_is_shared_across_original_manifests(self):
        self.run_action('quarantine')
        second=self.file.parent/'second.txt';second.write_bytes(b'second')
        item=dict(self.item,id='item-2',private_path=str(second),identity=self.mod.ident(second.stat()))
        m=dict(self.manifest,id='manifest-2',approval_id='approval-2',items=[item])
        self.run_action('quarantine',m)
        mod=self.mods['expire'];policy=mod.normalized_protections(dict(POLICY,scan_budgets=dict(max_items=1,max_seconds=60)))
        with patch('time.time',return_value=time.time()+604802):
            result=mod.execute(self.grant,policy,[self.manifest,m])
        self.assertEqual(result['items'][0]['status'],'expired');self.assertEqual(result['items'][1]['reason'],'budget_exhausted')
        q,_,_=self.record();name=self.mod.record_name(m,item)
        self.assertTrue((q/(name+'.data')).exists())
    def test_retry_cannot_reset_item_budget(self):
        policy=dict(POLICY,scan_budgets=dict(max_items=1,max_seconds=60))
        first=self.run_action('quarantine',policy=policy)
        self.assertEqual(first['items'][0]['status'],'quarantined')
        second=self.file.with_name('second.bak');second.write_bytes(b'retained')
        item=dict(self.item,id='item-2',private_path=str(second),identity=self.mod.ident(second.stat()))
        manifest=dict(self.manifest,id='manifest-2',approval_id='approval-2',items=[item])
        retry=self.run_action('quarantine',manifest,policy=policy)
        self.assertEqual(retry['items'][0]['reason'],'budget_exhausted')
        self.assertTrue(second.exists())

    def test_last_instruction_holder_appearance_rolls_back(self):
        rename=self.mod.noreplace
        def held_after(*args):
            rename(*args)
            self.mod.holders.return_value=({(self.item['identity']['dev'],self.item['identity']['inode']):{'holder'}},True)
        with patch.object(self.mod,'noreplace',side_effect=held_after):result=self.run_action('quarantine')
        self.assertEqual(result['items'][0]['reason'],'held');self.assertTrue(self.file.exists())
    def test_interrupted_rename_recovers_conservatively(self):
        save=self.mod.save
        calls=0
        def interrupted(*args):
            nonlocal calls
            calls+=1
            if calls==3:raise OSError('injected interruption')
            save(*args)
        with patch.object(self.mod,'save',side_effect=interrupted):self.run_action('quarantine')
        self.assertFalse(self.file.exists());result=self.run_action('quarantine')
        self.assertEqual(result['items'][0]['status'],'recovered_quarantine');self.assertEqual(result['freed_bytes'],0)
        q,name,r=self.record();self.assertGreaterEqual(r['expires_at'],time.time()+604799)
    def test_interrupted_restore_reconciles_existing_exact_destination(self):
        self.run_action('quarantine');m=self.restore_manifest();mod=self.mods['restore'];save=mod.save
        calls=0
        def interrupted(*args):
            nonlocal calls
            calls+=1
            if calls==4:raise OSError('interrupted')
            save(*args)
        with patch.object(mod,'save',side_effect=interrupted):self.run_action('restore',m)
        self.assertTrue(self.file.exists());result=self.run_action('restore',m)
        self.assertEqual(result['items'][0]['status'],'recovered_restore')
        q,name,record=self.record();self.assertNotIn('operation_stage',record)
    def test_ttl_holds_and_protection_override_original_approval(self):
        self.run_action('quarantine');result=self.run_action('expire');self.assertEqual(result['items'][0]['reason'],'ttl_not_elapsed')
        q,name,r=self.record()
        future=time.time()+604802
        clock=patch('time.time',return_value=future);clock.start();self.addCleanup(clock.stop)
        mod=self.mods['expire'];key=(r['identity']['dev'],r['identity']['inode'])
        with patch.object(mod,'holders',return_value=({key:{'holder'}},True)):result=self.run_action('expire')
        self.assertEqual(result['items'][0]['reason'],'held')
        result=self.run_action('expire',policy=dict(POLICY,protect_paths=[str(self.file)]));self.assertEqual(result['items'][0]['reason'],'protected')
        result=self.run_action('expire');self.assertEqual(result['items'][0]['status'],'expired');self.assertFalse((q/(name+'.data')).exists())
    def test_revocation_at_item_boundary_preserves_file(self):
        with patch.object(self.mod,'renew',side_effect=self.mod.Denied('policy_or_authority_revoked')):
            result=self.run_action('quarantine')
        self.assertEqual(result['items'][0]['reason'],'policy_or_authority_revoked');self.assertTrue(self.file.exists())
    def test_valid_signature_and_payload_tamper(self):
        key=self.root/'fixture-signing-key.pem'
        subprocess.run(['openssl','genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:2048','-out',str(key)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        n=subprocess.check_output(['openssl','rsa','-in',str(key),'-noout','-modulus'],stderr=subprocess.DEVNULL).decode().strip().split('=')[1]
        raw=b'{"schema":"fixture"}'
        signature=subprocess.run(['openssl','dgst','-sha256','-sign',str(key)],input=raw,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,check=True).stdout
        envelope=dict(payload=base64.b64encode(raw).decode(),signature=base64.b64encode(signature).decode())
        with patch.object(self.mod,'private_key',return_value=dict(n=n,e=65537)):
            self.assertEqual(self.mod.verify_signed(envelope),dict(schema='fixture'))
            envelope['payload']=base64.b64encode(b'{"schema":"tampered"}').decode()
            with self.assertRaises(self.mod.Denied):self.mod.verify_signed(envelope)
    def test_expired_dispatch_and_symlinks_skip(self):
        self.grant['expires_at']='2000-01-01T00:00:00Z';r=self.run_action('quarantine');self.assertEqual(r['items'][0]['reason'],'authorization_expired');self.assertTrue(self.file.exists())
        self.grant['expires_at']='2099-01-01T00:00:00Z';self.file.rename(self.file.with_suffix('.saved'));self.file.symlink_to(self.file.with_suffix('.saved'))
        r=self.run_action('quarantine');self.assertEqual(r['items'][0]['reason'],'identity_changed')
    def test_cross_filesystem_is_skipped_never_copied(self):
        from types import SimpleNamespace
        fstat=os.fstat
        def changed(fd):
            st=fstat(fd)
            if os.readlink('/proc/self/fd/'+str(fd)).endswith('/ai-intune/quarantine'):
                return SimpleNamespace(st_uid=st.st_uid,st_mode=st.st_mode,st_dev=st.st_dev+1,st_ino=st.st_ino,st_nlink=st.st_nlink)
            return st
        with patch('os.fstat',side_effect=changed):result=self.run_action('quarantine')
        self.assertEqual(result['items'][0]['reason'],'cross_filesystem');self.assertTrue(self.file.exists())
    def test_tampered_expiry_record_cannot_substitute_another_identity(self):
        self.run_action('quarantine');q,name,r=self.record()
        r['identity']['inode']+=1;(q/(name+'.json')).write_text(json.dumps(r))
        with patch('time.time',return_value=time.time()+604802):result=self.run_action('expire')
        self.assertEqual(result['items'][0]['reason'],'quarantine_identity_changed');self.assertTrue((q/(name+'.data')).exists())
    def test_restore_refuses_replaced_original_parent(self):
        self.run_action('quarantine');m=self.restore_manifest();parent=self.file.parent;parent.rename(parent.with_name('old-parent'));parent.mkdir()
        r=self.run_action('restore',m);self.assertEqual(r['items'][0]['reason'],'original_parent_changed')
    def test_signed_authority_rejects_missing_key_and_revoked_policy_grant(self):
        with self.assertRaises(self.mod.Denied):self.mod.verify_signed(dict(payload=base64.b64encode(b'{}').decode(),signature=base64.b64encode(b'x'*256).decode()))
        args=dict(manifest_id='manifest-1',manifest_digest=self.manifest['_digest'],approval_id='approval-1')
        grant=dict(schema='disk-grant/v1',action='quarantine',machine_id='machine-1',job_id='job-1',expires_at='2099-01-01T00:00:00Z',script_id=self.mod.SCRIPT_ID,script_sha256=hashlib.sha256(pathlib.Path(self.mod.__file__).read_bytes()).hexdigest(),args_digest='sha256:'+hashlib.sha256(json.dumps(args).encode()).hexdigest(),policy=base64.b64encode(json.dumps(POLICY).encode()).decode(),policy_digest='sha256:'+'b'*64,manifests=[])
        request=dict(authorization={},args=args,canonical_args=json.dumps(args),job_id='job-1',machine_id='machine-1')
        with patch.object(self.mod,'verify_signed',return_value=grant):
            with self.assertRaisesRegex(self.mod.Denied,'policy_binding'):self.mod.authorized(request)

if __name__=='__main__':unittest.main()
