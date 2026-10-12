# Source for the four generated hash-pinned action scripts. Regenerate with
# ops/generate-disk-actions.py. Safety functions above are copied from P2-02.
import base64, ctypes, errno, hashlib, hmac, re

# Deep actions retain safe-tier protections and add user data / private state.
BUILTIN += '.env .env.* Documents Desktop Pictures Videos Music ai-intune .ai-intune-delete-*'.split()
AUTH_KEY = '/etc/clawctl/disk-manifest-key.json'
TTL = 604800
IDENTITY = ('dev', 'inode', 'type', 'size', 'mtime_ns', 'ctime_ns')

class Denied(Exception):
    pass

def ident(st):
    return dict(dev=st.st_dev, inode=st.st_ino, type=stat.S_IFMT(st.st_mode),
                size=st.st_size, mtime_ns=st.st_mtime_ns, ctime_ns=st.st_ctime_ns)

def exact(st, item, moved=False):
    fields = IDENTITY[:-1] if moved else IDENTITY
    return (all(ident(st)[k] == item['identity'][k] for k in fields)
            and st.st_uid == item['owner_uid'] == os.geteuid()
            and stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and not st.st_mode & 0o022)

def epoch(value):
    return datetime.datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()

def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r'[a-zA-Z0-9_-]{1,128}', value):
        raise Denied('invalid_identifier')
    return value

def private_key():
    # Local admin pins the public key independently of the agent/Hub job.
    fds, name = parents(AUTH_KEY, repos=False)
    try:
        if any(os.fstat(fd).st_uid!=0 or os.fstat(fd).st_mode & 0o022 for fd in fds):
            raise Denied('authorization_key_unsafe')
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fds[-1])
        try:
            st = os.fstat(fd)
            if st.st_uid != 0 or not stat.S_ISREG(st.st_mode) or st.st_mode & 0o022 or st.st_size > 8192:
                raise Denied('authorization_key_unsafe')
            with os.fdopen(os.dup(fd)) as source:
                return json.load(source)
        finally: os.close(fd)
    finally: close(fds)

def verify_signed(envelope):
    try:
        raw = base64.b64decode(envelope['payload'], validate=True)
        sig = base64.b64decode(envelope['signature'], validate=True)
        if len(raw) > 2*1024*1024: raise Denied('authorization_too_large')
        key = private_key()
        n, e = int(key['n'], 16), int(key['e'])
        length = (n.bit_length()+7)//8
        if not 256 <= length <= 512 or e != 65537 or len(sig) != length or int.from_bytes(sig, 'big') >= n:
            raise Denied('authorization_invalid')
        tail = bytes.fromhex('3031300d060960864801650304020105000420') + hashlib.sha256(raw).digest()
        expected = b'\x00\x01' + b'\xff'*(length-len(tail)-3) + b'\x00' + tail
        actual = pow(int.from_bytes(sig, 'big'), e, n).to_bytes(length, 'big')
        if not hmac.compare_digest(expected, actual): raise Denied('authorization_invalid')
        return json.loads(raw)
    except (OSError, ValueError, KeyError, TypeError):
        raise Denied('authorization_unavailable')

def script_digest():
    fd=os.open(__file__,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as source:
        raw=source.read(256*1024+1)
    if len(raw)>256*1024: raise Denied('script_identity_unavailable')
    return hashlib.sha256(raw).hexdigest()

def authorized(request):
    grant = verify_signed(request['authorization'])
    args = request['args']
    if json.loads(request['canonical_args']) != args: raise Denied('args_binding')
    if (grant['schema'] != 'disk-grant/v1' or grant['action'] != ACTION or
        grant['machine_id'] != request['machine_id'] or grant['job_id'] != request['job_id'] or
        epoch(grant['expires_at']) <= time.time() or grant['script_id'] != SCRIPT_ID or
        grant.get('script_sha256') != script_digest() or
        grant['args_digest'] != 'sha256:'+hashlib.sha256(request['canonical_args'].encode()).hexdigest()):
        raise Denied('authorization_binding')
    policy_raw = base64.b64decode(grant['policy'], validate=True)
    policy = json.loads(policy_raw)
    if (grant['policy_digest'] != 'sha256:'+hashlib.sha256(policy_raw).hexdigest() or
        policy['quarantine_ttl_days'] != 7 or policy['schema_version'] != 1):
        raise Denied('policy_binding')
    manifests = []
    for encoded in grant['manifests']:
        raw = base64.b64decode(encoded, validate=True)
        m = json.loads(raw)
        digest = 'sha256:'+hashlib.sha256(raw).hexdigest()
        if (m['schema'] != 'disk-action/v1' or m['machine_id'] != grant['machine_id'] or
            m['policy_id'] != grant['policy_id'] or m['policy_digest'] != grant['policy_digest'] or
            m['ttl_seconds'] != TTL or not 1 <= len(m['items']) <= 100):
            raise Denied('manifest_binding')
        identifier(m['id']); identifier(m['approval_id'])
        if ACTION != 'expire':
            if (args['manifest_id'] != m['id'] or args['manifest_digest'] != digest or
                args['approval_id'] != m['approval_id'] or epoch(m['deadline']) <= time.time() or m['action'] != ACTION):
                raise Denied('manifest_binding')
        elif m['action'] != 'quarantine': raise Denied('expiry_not_quarantine')
        m['_digest'] = digest
        if ACTION == 'expire':
            selected=grant.get('selection',{}).get(m['id'],[])
            if not selected or len(set(selected))!=len(selected): raise Denied('expiry_selection')
            filtered=[i for i in m['items'] if i['id'] in selected]
            if len(filtered)!=len(selected): raise Denied('expiry_selection')
            m['items']=filtered
        manifests.append(m)
    if sum(len(m['items']) for m in manifests)>100: raise Denied('manifest_budget')
    if ACTION != 'expire' and len(manifests) != 1: raise Denied('manifest_binding')
    return grant, normalized_protections(policy), manifests

def close(fds):
    for fd in reversed(fds): os.close(fd)

def parents(path, repos=True):
    if not os.path.isabs(path) or os.path.normpath(path) != path or '\x00' in path:
        raise Denied('unsafe_path')
    parts = path.split('/')[1:]
    fds = [os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)]
    try:
        for part in parts[:-1]:
            fds.append(os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fds[-1]))
        if repos:
            for fd in fds:
                try: os.stat('.git', dir_fd=fd, follow_symlinks=False)
                except FileNotFoundError: continue
                raise Denied('protected_repository')
        return fds, parts[-1]
    except BaseException:
        close(fds); raise

def directory(base, name, private=True):
    try: os.mkdir(name, mode=0o700, dir_fd=base)
    except FileExistsError: pass
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=base)
    st = os.fstat(fd)
    if st.st_uid != os.geteuid() or st.st_mode & 0o022 or (private and stat.S_IMODE(st.st_mode) != 0o700):
        os.close(fd); raise Denied('quarantine_directory_unsafe')
    os.fsync(base)
    return fd

def quarantine_root():
    home = os.path.abspath(os.path.expanduser('~'))
    fds, name = parents(home, repos=False)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fds[-1])
    finally: close(fds)
    try:
        for name in ['.local', 'state', 'ai-intune', 'quarantine']:
            child = directory(fd, name, name in ['ai-intune','quarantine']); os.close(fd); fd = child
        return fd
    except BaseException: os.close(fd); raise

def noreplace(srcfd, src, dstfd, dst):
    # RENAME_NOREPLACE closes the occupied-destination race. No fallback to
    # os.rename (overwrite) or copy/unlink on an unsupported kernel/filesystem.
    libc = ctypes.CDLL(None, use_errno=True)
    rename = libc.renameat2
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(srcfd, os.fsencode(src), dstfd, os.fsencode(dst), 1) != 0:
        code = ctypes.get_errno()
        if code == errno.EXDEV: raise Denied('cross_filesystem')
        if code == errno.EEXIST: raise Denied('destination_occupied')
        raise OSError(code, 'rename refused')

def record_name(m, item):
    return hashlib.sha256((m['id']+'\x00'+identifier(item['id'])).encode()).hexdigest()

def save(fd, name, record):
    temp = name+'.tmp'
    try: os.unlink(temp, dir_fd=fd)
    except FileNotFoundError: pass
    output = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    with os.fdopen(output, 'w') as stream:
        json.dump(record, stream, separators=(',', ':'))
        stream.flush(); os.fsync(stream.fileno())
    os.rename(temp, name+'.json', src_dir_fd=fd, dst_dir_fd=fd)
    os.fsync(fd)

def load(fd, name):
    try: source = os.open(name+'.json', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
    except FileNotFoundError: return None
    try:
        st = os.fstat(source)
        if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o600 or st.st_nlink != 1 or not stat.S_ISREG(st.st_mode) or st.st_size>32768:
            raise Denied('journal_unsafe')
        with os.fdopen(os.dup(source)) as stream: return json.load(stream)
    finally: os.close(source)

def parent_same(path, fds):
    fresh, _ = parents(path)
    try:
        if [(os.fstat(fd).st_dev, os.fstat(fd).st_ino) for fd in fresh] != [(os.fstat(fd).st_dev, os.fstat(fd).st_ino) for fd in fds]:
            raise Denied('parent_changed')
    finally: close(fresh)

def checked(path, fd, name, item, policy, ignored, moved=False):
    if protected(path, policy): raise Denied('protected')
    opened, complete = holders(ignore_fds=ignored)
    st = os.stat(name, dir_fd=fd, follow_symlinks=False)
    if not complete: raise Denied('holder_visibility_incomplete')
    if held(path, st, opened) or any(('dir',os.fstat(f).st_dev,os.fstat(f).st_ino) in opened for f in ignored):
        raise Denied('held')
    if not revalidate_protections(policy): raise Denied('protection_changed')
    st = os.stat(name, dir_fd=fd, follow_symlinks=False)
    if stat.S_ISREG(st.st_mode) and st.st_mode & 0o022: raise Denied('shared_write_permissions')
    if not exact(st, item, moved): raise Denied('identity_changed')
    return st

def renew(grant):
    # The trusted supervisor obtains a new signed, machine/job-bound grant at
    # every item boundary. Pipes carry no machine credential into the helper.
    import select
    os.write(4,b'renew\n')
    data=b''
    while not data.endswith(b'\n'):
        ready,_,_=select.select([3],[],[],10)
        if not ready: raise Denied('renewal_unavailable')
        chunk=os.read(3,65536)
        if not chunk or len(data)>3*1024*1024: raise Denied('renewal_unavailable')
        data+=chunk
    fresh=verify_signed(json.loads(data))
    for key in grant:
        if key!='expires_at' and fresh.get(key)!=grant[key]: raise Denied('policy_or_authority_revoked')
    return fresh

def mutation_ready(grant):
    if epoch(grant['expires_at']) <= time.time(): raise Denied('authorization_expired')

def boundary(grant, budget):
    fresh=renew(grant)
    grant.clear();grant.update(fresh)
    if epoch(grant['expires_at']) <= time.time(): raise Denied('authorization_expired')
    if budget['remaining'] <= 0 or time.monotonic() >= budget['deadline']: raise Denied('budget_exhausted')
    budget['remaining'] -= 1
    if 'fd' in budget:
        budget['used']+=1
        save(budget['fd'],budget['name'],dict(used=budget['used'],deadline=budget['wall_deadline']))

def rollback_stage(qfd, name, stage, record, item):
    # Never overwrite a replacement at the stable quarantine name. Persist the
    # unpredictable stage in the journal if rollback is occupied or interrupted.
    try:
        noreplace(qfd,stage,qfd,name+'.data')
        os.fsync(qfd)
        st=os.stat(name+'.data',dir_fd=qfd,follow_symlinks=False)
        if exact(st,item,True): record['identity']=ident(st)
        record.pop('operation_stage',None)
        save(qfd,name,record)
    except (OSError,Denied):
        raise Denied('stage_retained_for_recovery')

def stage_entry(qfd, name, record, item, authority):
    if record.get('operation_stage'): raise Denied('stage_retained_for_recovery')
    stage=name+'.op-'+os.urandom(16).hex()
    record['operation_stage']=stage
    save(qfd,name,record)
    mutation_ready(authority)
    noreplace(qfd,name+'.data',qfd,stage)
    os.fsync(qfd)
    st=os.stat(stage,dir_fd=qfd,follow_symlinks=False)
    if not exact(st,item,True):
        rollback_stage(qfd,name,stage,record,item)
        raise Denied('staged_identity_changed')
    return stage,dict(item,identity=ident(st))

def move_item(m, item, policy, grant, qfd, budget):
    path = item['private_path']; name = record_name(m,item)
    existing = load(qfd,name)
    if existing:
        if existing['manifest_digest'] != m['_digest']: raise Denied('journal_binding')
        if existing['state'] in ['deleted','restored','expired']:
            return existing['state'], 0
        if existing['state'] == 'quarantined': return 'already_quarantined',0
        # A pending journal never authorizes deletion. Recover a completed move
        # conservatively with a new seven-day clock, or retry only the exact source.
        try: moved = os.stat(name+'.data',dir_fd=qfd,follow_symlinks=False)
        except FileNotFoundError: moved = None
        if moved is not None:
            if not exact(moved,item,True): raise Denied('interrupted_identity_changed')
            existing.update(state='quarantined', identity=ident(moved), quarantined_at=time.time(), expires_at=time.time()+TTL)
            save(qfd,name,existing)
            return 'recovered_quarantine',0
    fds, leaf = parents(path)
    try:
        if os.fstat(fds[-1]).st_dev != os.fstat(qfd).st_dev: raise Denied('cross_filesystem')
        st = checked(path,fds[-1],leaf,item,policy,fds+[qfd])
        parent = os.fstat(fds[-1])
        record = dict(state='pending',manifest_id=m['id'],manifest_digest=m['_digest'],approval_id=m['approval_id'],
                      item_id=item['id'],original_path=path,original_parent=[parent.st_dev,parent.st_ino],identity=ident(st),
                      owner_uid=item['owner_uid'],job_id=grant['job_id'],action=ACTION,quarantined_at=time.time(),expires_at=time.time()+TTL)
        save(qfd,name,record)
        # Journal I/O may be lengthy: all checks are repeated after it.
        boundary(grant,budget)
        checked(path,fds[-1],leaf,item,policy,fds+[qfd]); parent_same(path,fds)
        # The final stat is intentionally after budgets and ancestor revalidation.
        mutation_ready(grant)
        if not exact(os.stat(leaf,dir_fd=fds[-1],follow_symlinks=False),item): raise Denied('identity_changed')
        noreplace(fds[-1],leaf,qfd,name+'.data')
        os.fsync(fds[-1]); os.fsync(qfd)
        moved = os.stat(name+'.data',dir_fd=qfd,follow_symlinks=False)
        try:
            if not exact(moved,item,True): raise Denied('rename_identity_changed')
            parent_same(path,fds)
            if protected(path,policy) or not revalidate_protections(policy): raise Denied('protection_changed')
            opened,complete=holders(ignore_fds=fds+[qfd])
            if not complete: raise Denied('holder_visibility_incomplete')
            if held(path,moved,opened): raise Denied('held')
        except (Denied,OSError):
            # A last-instruction substitution or changed boundary is never
            # unlinked. Attempt non-overwriting rollback; retain the journal on
            # conflict so interruption/recovery remains explicit.
            try:
                noreplace(qfd,name+'.data',fds[-1],leaf)
                os.fsync(fds[-1]);os.fsync(qfd)
            except (OSError,Denied): pass
            raise
        record.update(state='quarantined',identity=ident(moved),quarantined_at=time.time(),expires_at=time.time()+TTL)
        save(qfd,name,record)
        if ACTION == 'delete':
            # Unlink only the re-verified private staged inode. Interrupted delete
            # becomes quarantine and requires a fresh human decision.
            pinned = dict(item,identity=record['identity'])
            fresh=renew(grant)
            if epoch(fresh['expires_at'])<=time.time(): raise Denied('authorization_expired')
            checked(path,qfd,name+'.data',pinned,policy,fds+[qfd])
            mutation_ready(fresh)
            if not exact(os.stat(name+'.data',dir_fd=qfd,follow_symlinks=False),pinned): raise Denied('identity_changed')
            stage,staged=stage_entry(qfd,name,record,pinned,fresh)
            try:
                checked(path,qfd,stage,staged,policy,fds+[qfd])
                mutation_ready(fresh)
                os.unlink(stage,dir_fd=qfd); os.fsync(qfd)
            except (Denied,OSError):
                rollback_stage(qfd,name,stage,record,pinned)
                raise
            record.pop('operation_stage',None)
            record['state']='deleted'; save(qfd,name,record)
            return 'deleted', item['allocated_bytes']
        return 'quarantined', item['allocated_bytes']
    finally: close(fds)

def restore_or_expire(m,item,policy,grant,qfd,budget):
    # Restore manifests carry a signed reference to the original quarantine.
    original = m.get('quarantine_manifest_id',m['id'])
    name = record_name(dict(id=original),item)
    record = load(qfd,name)
    if not record or record['manifest_id'] != original or record['item_id'] != item['id'] or record['original_path'] != item['private_path']:
        raise Denied('quarantine_binding')
    if ACTION == 'expire' and record['manifest_digest'] != m['_digest']: raise Denied('quarantine_binding')
    if record['state'] in ['restored','expired','deleted']: return 'already_'+record['state'],0
    if record['state'] not in ['quarantined','restore_pending']: raise Denied('journal_incomplete')
    if ACTION == 'expire' and (record['state'] != 'quarantined' or time.time() < record['expires_at'] or record['expires_at'] < record['quarantined_at']+TTL):
        raise Denied('ttl_not_elapsed')
    fds, leaf = parents(item['private_path'])
    try:
        st = os.fstat(fds[-1])
        if item.get('original_parent',record['original_parent']) != record['original_parent']: raise Denied('original_parent_changed')
        if [st.st_dev,st.st_ino] != record['original_parent']: raise Denied('original_parent_changed')
        if any(record['identity'][k]!=item['identity'][k] for k in IDENTITY[:-1]): raise Denied('quarantine_identity_changed')
        if ACTION == 'expire' and time.time() < record['identity']['ctime_ns']/1e9+TTL: raise Denied('ttl_not_elapsed')
        pinned = dict(item,identity=record['identity'])
        # A restore preview may bind the post-rename identity too.
        if ACTION == 'restore' and item['identity'] != record['identity']: raise Denied('restore_identity_changed')
        try: os.stat(name+'.data',dir_fd=qfd,follow_symlinks=False)
        except FileNotFoundError:
            if record['state'] == 'restore_pending' and ACTION == 'restore':
                checked(item['private_path'],fds[-1],leaf,pinned,policy,fds+[qfd],True)
                record['state']='restored';record.pop('operation_stage',None);save(qfd,name,record)
                return 'recovered_restore',0
            raise Denied('quarantine_data_missing')
        checked(item['private_path'],qfd,name+'.data',pinned,policy,fds+[qfd])
        parent_same(item['private_path'],fds)
        if ACTION == 'restore':
            record['state']='restore_pending';save(qfd,name,record)
            checked(item['private_path'],qfd,name+'.data',pinned,policy,fds+[qfd])
        boundary(grant,budget)
        checked(item['private_path'],qfd,name+'.data',pinned,policy,fds+[qfd]);parent_same(item['private_path'],fds)
        mutation_ready(grant)
        if not exact(os.stat(name+'.data',dir_fd=qfd,follow_symlinks=False),pinned): raise Denied('identity_changed')
        stage,staged=stage_entry(qfd,name,record,pinned,grant)
        try:
            checked(item['private_path'],qfd,stage,staged,policy,fds+[qfd]);parent_same(item['private_path'],fds)
            mutation_ready(grant)
            if ACTION == 'restore':
                noreplace(qfd,stage,fds[-1],leaf)
                os.fsync(fds[-1]);os.fsync(qfd)
                restored=os.stat(leaf,dir_fd=fds[-1],follow_symlinks=False)
                if not exact(restored,staged,True):
                    # Capture the final entry back to a unique private name;
                    # never overwrite the original quarantine entry.
                    try:
                        noreplace(fds[-1],leaf,qfd,stage)
                        os.fsync(fds[-1]);os.fsync(qfd)
                    except (Denied,OSError): raise Denied('restore_retained_for_recovery')
                    raise Denied('restore_identity_changed')
                record['state']='restored';value=0
            else:
                os.unlink(stage,dir_fd=qfd);record['state']='expired';value=item['allocated_bytes']
        except (Denied,OSError):
            rollback_stage(qfd,name,stage,record,pinned)
            raise
        record.pop('operation_stage',None)
        os.fsync(qfd);save(qfd,name,record)
        return record['state'],value
    finally: close(fds)

def execute(grant,policy,manifests):
    state=state_lock(os.path.abspath(os.path.expanduser('~')))
    try: qfd=quarantine_root()
    except BaseException:
        os.close(state[1]);os.close(state[0]);raise
    lock=None
    result=dict(schema='disk-action-result/v1',job_id=grant['job_id'],items=[],quarantined_bytes=0,freed_bytes=0)
    try:
        lock=os.open('lock',os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW,0o600,dir_fd=qfd)
        st=os.fstat(lock)
        if st.st_uid!=os.geteuid() or st.st_nlink!=1 or not stat.S_ISREG(st.st_mode): raise Denied('lock_unsafe')
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        name='budget-'+ACTION+'-'+identifier(grant['job_id'])
        previous=load(qfd,name)
        used=previous['used'] if previous else 0
        wall_deadline=previous['deadline'] if previous else time.time()+min(600,policy['scan_budgets']['max_seconds'])
        if not isinstance(used,int) or used<0: raise Denied('journal_unsafe')
        budget=dict(remaining=min(100,policy['scan_budgets']['max_items'])-used,deadline=time.monotonic()+max(0,wall_deadline-time.time()),fd=qfd,name=name,used=used,wall_deadline=wall_deadline)
        for m in manifests:
            for item in m['items']:
                if len(result['items']) >= 100:
                    result['omitted_items'] = result.get('omitted_items',0)+1
                    continue
                row=dict(manifest_id=m['id'],item_id=item['id'],status='skipped',reason='')
                try:
                    if ACTION in ['quarantine','delete']:
                        status,value=move_item(m,item,policy,grant,qfd,budget)
                    else: status,value=restore_or_expire(m,item,policy,grant,qfd,budget)
                    row['status']=status
                    result['quarantined_bytes' if status=='quarantined' else 'freed_bytes']+=value
                except Denied as error: row['reason']=str(error)
                except (OSError,ValueError,KeyError,TypeError,AttributeError): row['reason']='filesystem_or_journal_changed'
                original=m.get('quarantine_manifest_id',m['id'])
                record=load(qfd,record_name(dict(id=original),item))
                if record and record['state'] in ['quarantined','restore_pending','restored','expired','deleted']:
                    row['record']={k:record[k] for k in ['state','identity','original_parent','owner_uid','quarantined_at','expires_at']}
                result['items'].append(row)
        return result
    finally:
        if lock is not None: os.close(lock)
        os.close(qfd)
        os.close(state[1]);os.close(state[0])

def main():
    if os.geteuid()==0: raise Denied('agent_user_required')
    request=json.load(sys.stdin)
    grant,policy,manifests=authorized(request)
    qfd=quarantine_root()
    try: existing=load(qfd,'result-'+identifier(grant['job_id']))
    finally: os.close(qfd)
    if existing is not None:
        print(json.dumps(existing,separators=(',',':')));return
    result=execute(grant,policy,manifests)
    qfd=quarantine_root()
    try: save(qfd,'result-'+identifier(grant['job_id']),result)
    finally: os.close(qfd)
    print(json.dumps(result,separators=(',',':')))

if __name__=='__main__':
    try: main()
    except (Denied,OSError,ValueError,KeyError,TypeError,AttributeError):
        print('{"schema":"disk-action-result/v1","precondition_failed":true,"reason":"authorization_or_state_unavailable","items":[],"quarantined_bytes":0,"freed_bytes":0}')
        sys.exit(1)
