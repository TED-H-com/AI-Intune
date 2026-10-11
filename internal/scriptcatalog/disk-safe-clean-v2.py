# Fixed policy adapter. No caller-selected commands, paths, or environment.
# Native cache boundary: uv owns its cache descendants and exclusive prune lock;
# npm/cacache verify owns content-addressed cache entries. The adapter admits only
# real user-owned roots outside protected paths/repositories, bounds its safety
# scan, refuses escaping symlinks (including depth <= 2), and passes uv/npm only
# an inherited fd-anchored cache path. It does not implement native GC internals.
import datetime, fcntl, fnmatch, json, os, shutil, stat, subprocess, sys, time

APPLY = True
BUILTIN = 'systemd-private-* .X11-unix .ICE-unix .XIM-unix .font-unix .Test-unix tmux-* ssh-* snap-private-tmp *openclaw* *clawctl* *claude* *codex* *grok* *agy* *cursor* *vscode* *backup* *snapshot* *.sock *.pid *.lock .X*-lock .s.PGSQL* *odoo* *postgres* pulse-* dbus-* gpg-* krb5cc* hsperfdata_* *credential* *secret* *token* *password* *.pem *.key *model* *.gguf *.safetensors *.pt .npmrc .netrc auth.json .ssh .gnupg .aws .azure .config .git'.split()

def entries(path):
    # O_NOATIME is mandatory: preview must not change directory atime either.
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NOATIME)
    try:
        return os.listdir(fd)
    finally:
        os.close(fd)

def inside(path, root):
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)

class ProtectionResolutionError(OSError):
    pass

def preview_resolution_guard(path):
    if not APPLY:
        # Linux readlink can update symlink atime even through O_PATH. Preview
        # must defer instead of reading links on filesystems without noatime.
        prefix = '/'
        for part in path.split('/')[1:]:
            prefix = os.path.join(prefix, part)
            try: info = os.lstat(prefix)
            except FileNotFoundError: return
            if stat.S_ISLNK(info.st_mode) and not (os.statvfs(os.path.dirname(prefix)).f_flag & os.ST_NOATIME):
                raise ProtectionResolutionError('preview cannot resolve symlink without changing atime')

def strict_realpath(path):
    preview_resolution_guard(path)
    return os.path.realpath(path, strict=True)

def resolved_if_present(path):
    preview_resolution_guard(path)
    # Missing ordinary paths retain their lexical protection. Broken links,
    # loops and inaccessible ancestors cannot safely establish a boundary.
    try:
        os.lstat(path)
    except FileNotFoundError:
        prefix = '/'
        for part in path.split('/')[1:]:
            prefix = os.path.join(prefix, part)
            try:
                info = os.lstat(prefix)
            except FileNotFoundError:
                return None
            if stat.S_ISLNK(info.st_mode):
                strict_realpath(prefix)
        return None
    return strict_realpath(path)

def normalized_protections(policy):
    if '_protection_paths' in policy:
        return policy
    try:
        home = os.path.abspath(os.path.expanduser('~'))
        preview_resolution_guard(home)
        # Name-pattern protections remain unconditional. Materialize matching
        # home roots and fixed built-in locations so their symlink aliases also
        # protect destinations elsewhere (notably caches and temp trees).
        builtins = [os.path.join(home, name) for name in BUILTIN if not any(c in name for c in '*?[')]
        builtins += [os.path.join(home, '.codex/generated_images')]
        builtins += [os.path.join(home, name) for name in entries(home)
                     if any(fnmatch.fnmatch(name.lower(), pat.lower()) for pat in BUILTIN)]
        paths = set()
        for raw in builtins + policy['protect_paths']:
            lexical = os.path.abspath(os.path.expanduser(raw))
            paths.add(lexical)
            resolved = resolved_if_present(lexical)
            if resolved is not None:
                paths.add(resolved)
        return dict(policy, _protection_paths=paths)
    except OSError as error:
        raise ProtectionResolutionError('protection path resolution failed') from error

def protected(path, policy):
    policy = normalized_protections(policy)
    lexical = os.path.abspath(path)
    try:
        resolved = resolved_if_present(lexical)
    except OSError as error:
        raise ProtectionResolutionError('candidate path resolution failed') from error
    candidates = {lexical}
    if resolved is not None:
        candidates.add(resolved)
    for candidate in candidates:
        if any(inside(candidate, root) or inside(root, candidate) for root in policy['_protection_paths']):
            return True
        if any(fnmatch.fnmatch(x.lower(), pat.lower()) for x in candidate.split(os.sep) for pat in BUILTIN):
            return True
        parent = candidate if os.path.isdir(candidate) else os.path.dirname(candidate)
        while parent != '/':
            if os.path.lexists(os.path.join(parent, '.git')):
                return True
            parent = os.path.dirname(parent)
    return False

def held_pids(path, info, opened):
    pids = set(opened.get(path, ())) | set(opened.get((info.st_dev, info.st_ino), ()))
    # A descriptor-held directory protects descendants after rename or alias.
    parent = path if stat.S_ISDIR(info.st_mode) else os.path.dirname(path)
    while True:
        ancestor = os.stat(parent, follow_symlinks=False)
        pids.update(opened.get(('dir', ancestor.st_dev, ancestor.st_ino), ()))
        if parent == '/':
            return pids
        parent = os.path.dirname(parent)

def held(path, info, opened):
    return bool(held_pids(path, info, opened))

def cache_holders(cache, opened):
    pids = set()
    for key, owners in opened.items():
        if isinstance(key, str) and inside(key, cache):
            pids.update(owners)
    pids.update(held_pids(cache, os.stat(cache, follow_symlinks=False), opened))
    return len(pids)

def holders(ignore_fds=()):
    opened = {}
    complete = True
    try:
        with open('/proc/mounts') as mounts:
            if any('hidepid=' in line and 'hidepid=0' not in line for line in mounts): complete = False
    except OSError:
        complete = False
    for pid in os.listdir('/proc'):
        if not pid.isdigit():
            continue
        try:
            for fd in os.listdir('/proc/' + pid + '/fd'):
                try:
                    if pid == str(os.getpid()) and int(fd) in ignore_fds:
                        continue
                    descriptor = '/proc/' + pid + '/fd/' + fd
                    info = os.stat(descriptor)
                    opened.setdefault((info.st_dev, info.st_ino), set()).add(pid)
                    if stat.S_ISDIR(info.st_mode):
                        opened.setdefault(('dir', info.st_dev, info.st_ino), set()).add(pid)
                    opened.setdefault(os.readlink(descriptor).removesuffix(' (deleted)'), set()).add(pid)
                except FileNotFoundError:
                    pass
                except OSError:
                    complete = False
            try:
                cwd = '/proc/'+pid+'/cwd'
                opened.setdefault(os.readlink(cwd),set()).add(pid)
                with open('/proc/'+pid+'/maps') as mappings:
                    for line in mappings:
                        fields=line.rstrip().split(None,5)
                        if len(fields)==6 and fields[5].startswith('/'):
                            opened.setdefault(fields[5].removesuffix(' (deleted)'),set()).add(pid)
            except FileNotFoundError:
                pass
            except OSError:
                complete=False
        except FileNotFoundError:
            pass
        except OSError:
            complete = False
    # Descriptor visibility includes advisory-lock holders. An inaccessible
    # process makes native GC and unlink ineligible, never a reason to kill it.
    return opened, complete

def unlink_checked(path, info, policy):
    try: policy = normalized_protections(policy)
    except ProtectionResolutionError: return False
    # Anchor every ancestor without following links; retain all descriptors
    # while rechecking repositories, inode identity, owner and open holders.
    fds = [os.open('/', os.O_RDONLY | os.O_DIRECTORY)]
    try:
        parts = os.path.abspath(path).split('/')[1:]
        for part in parts[:-1]:
            fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fds[-1])
            fds.append(fd)
            try:
                os.stat('.git', dir_fd=fd, follow_symlinks=False)
                return False
            except FileNotFoundError:
                pass
        opened, complete = holders(ignore_fds=fds)
        fresh = os.stat(parts[-1], dir_fd=fds[-1], follow_symlinks=False)
        if not complete or held(path, fresh, opened) or any(('dir', os.fstat(fd).st_dev, os.fstat(fd).st_ino) in opened for fd in fds) or protected(path, policy):
            return False
        # All potentially lengthy checks precede the final descriptor-relative stat.
        fresh = os.stat(parts[-1], dir_fd=fds[-1], follow_symlinks=False)
        identity = lambda st: (st.st_dev, st.st_ino, stat.S_IFMT(st.st_mode), st.st_size, st.st_mtime_ns, st.st_ctime_ns)
        if identity(fresh) != identity(info) or not stat.S_ISREG(fresh.st_mode) or fresh.st_nlink != 1 or fresh.st_uid != os.geteuid():
            return False
        os.unlink(parts[-1], dir_fd=fds[-1])
        return True
    finally:
        for fd in reversed(fds):
            os.close(fd)

def category(note='', status='skipped', candidate=0, freed=0, items=0):
    return dict(mode='apply' if APPLY else 'dry-run', status=status,
                candidate_bytes=candidate, freed_bytes=freed, items=items, note=note)

def scan(root, policy, opened, complete, days, mutate=False, budget=None):
    try: policy = normalized_protections(policy)
    except ProtectionResolutionError: return category("deferred: protection path resolution failed")
    if not complete:
        return category('deferred: incomplete holder visibility')
    budget = budget if budget is not None else {"remaining": policy["scan_budgets"]["max_items"]}
    total = count = freed = skipped = visited = 0
    stack = [root]
    deadline = time.monotonic() + min(policy['scan_budgets']['max_seconds'], 60)
    while stack:
        current = stack.pop()
        try:
            if protected(current, policy):
                skipped += 1
                continue
        except ProtectionResolutionError:
            return category("deferred: candidate path resolution failed", candidate=total, freed=freed, items=count)
        try:
            names = entries(current)
        except (OSError, PermissionError):
            return category('incomplete visibility')
        # A repository root protects every child, including before .git is visited.
        if '.git' in names:
            skipped += len(names)
            continue
        for name in names:
            visited += 1
            if visited > policy['scan_budgets']['max_entries'] or time.monotonic() > deadline:
                return category('incomplete: scan budget exceeded', candidate=total, freed=freed, items=count)
            path = os.path.join(current, name)
            try:
                info = os.lstat(path)
                if protected(path, policy) or info.st_uid != os.geteuid() or stat.S_ISLNK(info.st_mode):
                    skipped += 1
                    continue
                if stat.S_ISDIR(info.st_mode):
                    stack.append(path)
                    continue
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    skipped += 1
                    continue
                if time.time() - max(info.st_mtime, info.st_atime) < days * 86400:
                    continue
                if held(path, info, opened) or not complete:
                    skipped += 1
                    continue
                if budget['remaining'] <= 0:
                    return category('incomplete: max_items budget reached', candidate=total, freed=freed, items=count)
                budget['remaining'] -= 1
                total += info.st_size
                count += 1
                if mutate:
                    if unlink_checked(path, info, policy):
                        freed += info.st_size
                    else:
                        skipped += 1
            except ProtectionResolutionError:
                return category('deferred: candidate path resolution failed', candidate=total, freed=freed, items=count)
            except OSError:
                return category('incomplete: filesystem changed; deferred', candidate=total, freed=freed, items=count)
    return category(str(skipped) + ' protected or open items skipped', 'ok', total, freed, count)

def native(name, cache, command, policy, opened, complete):
    try:
        policy = normalized_protections(policy)
        preview_resolution_guard(os.path.abspath(cache))
    except ProtectionResolutionError: return category("deferred: protection path resolution failed")
    # Hold the observed directory throughout validation and spawn. uv/npm receive
    # this inherited descriptor instead of a mutable pathname.
    try:
        fd = os.open(cache, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NOATIME)
    except OSError:
        return category('cache absent or unsafe')
    try:
        if name in ['uv', 'npm'] and os.fstat(fd).st_uid != os.geteuid():
            return category('unsafe: cache root is not user-owned')
        if APPLY:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return native_anchored(name, cache, command, policy, opened, complete, fd)
    except ProtectionResolutionError:
        return category('deferred: candidate path resolution failed')
    except OSError:
        return category('deferred: cache changed or lock held')
    finally:
        os.close(fd)

def same_cache(cache, fd):
    info = os.stat(cache, follow_symlinks=False)
    pinned = os.fstat(fd)
    return stat.S_ISDIR(info.st_mode) and (info.st_dev, info.st_ino) == (pinned.st_dev, pinned.st_ino)

def native_anchored(name, cache, command, policy, opened, complete, fd):
    # Resolve ancestor aliases as well as the caller's fixed cache location.
    if protected(cache, policy) or protected(os.path.realpath(cache, strict=True), policy):
        return category('protected cache root')
    try: n = cache_holders(cache, opened)
    except OSError: return category('cache absent or changed')
    if n:
        return category('deferred: cache lock held by ' + str(n))
    if not complete:
        return category('incomplete holder visibility')
    if not shutil.which(command[0]):
        return category('unsupported: native tool unavailable')
    if not os.path.isdir(cache):
        return category('cache absent')
    # Refuse native GC if it could affect a protected subtree or lock file.
    stack = [cache]
    visited = estimate = item_count = 0
    identities = set()
    deadline = time.monotonic() + min(policy["scan_budgets"]["max_seconds"], 60)
    try:
        while stack:
            root = stack.pop()
            if protected(root, policy):
                return category('protected cache subtree')
            for item in entries(root):
                visited += 1
                p = os.path.join(root, item)
                if visited > policy['scan_budgets']['max_entries'] or time.monotonic() > deadline:
                    return category('incomplete: scan budget exceeded')
                if protected(p, policy) and not (name=='uv' and p==cache+'/.lock' and not policy['protect_paths']):
                    return category('protected cache subtree')
                if os.path.islink(p):
                    # Never traverse links. Internal links remain native-tool
                    # owned; escaping or unresolved links refuse the entire GC.
                    target = os.path.realpath(p, strict=True)
                    if not inside(target, os.path.realpath(cache, strict=True)):
                        return category('unsafe: cache symlink escapes root')
                    if protected(target, policy):
                        return category('protected cache symlink target')
                    continue
                info = os.lstat(p)
                identities.add((info.st_dev, info.st_ino))
                owners = held_pids(p, info, opened)
                if owners: return category('deferred: cache lock held by ' + str(len(owners)))
                if stat.S_ISDIR(info.st_mode):
                    stack.append(p)
                else:
                    info=os.lstat(p)
                    if stat.S_ISREG(info.st_mode):
                        if item_count >= policy['scan_budgets']['max_items']:
                            return category('incomplete: max_items budget reached', candidate=estimate, items=item_count)
                        item_count += 1
                        estimate += info.st_size
    except ProtectionResolutionError:
        return category('deferred: candidate path resolution failed')
    except OSError:
        return category('incomplete protection visibility')
    if not same_cache(cache, fd): return category('deferred: cache changed')
    if not APPLY:
        return category('native GC estimate is an upper bound; no command executed', 'ok', candidate=estimate)
    fresh, visible = holders(ignore_fds=(fd,))
    owners = set()
    for identity in identities: owners.update(fresh.get(identity, ()))
    n = max(cache_holders(cache, fresh), len(owners))
    if n: return category('deferred: cache lock held by ' + str(n))
    if not visible: return category('incomplete holder visibility')
    if not same_cache(cache, fd): return category('deferred: cache changed')
    target = '/proc/self/fd/' + str(fd)
    env = dict(os.environ, UV_LOCK_TIMEOUT='60', UV_CACHE_DIR=target, npm_config_cache=target)
    try:
        out = subprocess.run(command, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, timeout=60, check=False, pass_fds=(fd,))
        if not same_cache(cache, fd): return category('deferred: cache changed during native GC')
        observation = scan(cache, policy, {}, True, 0) if out.returncode==0 else None
        after = observation['candidate_bytes'] if observation and observation['status']=='ok' else estimate
        return category('native GC completed' if out.returncode == 0 else 'native GC deferred', 'ok' if out.returncode == 0 else 'skipped', candidate=estimate, freed=max(estimate-after,0))
    except subprocess.TimeoutExpired:
        return category('deferred: cache lock timeout')

# Design §4.1 permits -f solely as non-interactive confirmation for these
# two fixed age-filtered commands; never --force, --all or other prune targets.
DOCKER_COMMANDS = [ ['docker', 'image', 'prune', '-f', '--filter', 'until=168h'],
                    ['docker', 'builder', 'prune', '-f', '--filter', 'until=168h'] ]
JOURNAL_COMMAND = ['journalctl', '--vacuum-size=500M']

def docker(policy, opened, complete):
    if not APPLY:
        return category('native GC estimate unavailable; no command executed', 'ok')
    if policy['safe_tier']['docker_min_hours'] != 168:
        return category('unsupported: Docker age policy requires a reviewed adapter')
    if not complete or not shutil.which('docker'):
        return category('incomplete holder visibility or Docker unavailable')
    # Never prune a remote context or an unverified storage root.
    try:
        context = subprocess.run(['docker', 'context', 'inspect', '--format', '{{json .Endpoints.docker.Host}}'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10, check=True)
        endpoint = json.loads(context.stdout)
        if endpoint not in ['unix:///var/run/docker.sock', 'unix:///run/user/' + str(os.geteuid()) + '/docker.sock']:
            return category('unsupported: non-local Docker context')
        info = subprocess.run(['docker', 'info', '--format', '{{json .DockerRootDir}}'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10, check=True)
        root = json.loads(info.stdout)
        if root not in ['/var/lib/docker', os.path.expanduser('~/.local/share/docker')]:
            return category('unsupported: Docker storage root')
    except (OSError, ValueError, subprocess.SubprocessError):
        return category('incomplete Docker inventory')
    # Native prune commands retain referenced objects; the storage tree must
    # additionally pass the same no-repository/model/additive-path checks.
    result = native('docker', root, DOCKER_COMMANDS[0], policy, opened, complete)
    if result['status'] != 'ok' or not APPLY:
        return result
    return native('docker', root, DOCKER_COMMANDS[1], policy, opened, complete)

def state_lock(home):
    # Share the existing local user timer's scope lock. Root timers are untouched.
    fd = os.open(home, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in ['.local', 'state', 'disk-clean']:
            try: os.mkdir(part, mode=0o700, dir_fd=fd)
            except FileExistsError: pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
            info = os.fstat(fd)
            if info.st_uid != os.geteuid() or info.st_mode & 0o022:
                raise OSError('unsafe state directory')
    except OSError:
        os.close(fd)
        raise
    lock = os.open('lock', os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    info = os.fstat(lock)
    if info.st_uid != os.geteuid() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        os.close(lock); os.close(fd)
        raise OSError('unsafe scope lock')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(lock); os.close(fd)
        raise
    return fd, lock

def save_summary(directory, summary):
    # Existing fleet-disk-clean/v1 consumers continue reading last.json.
    name = 'last-v2-' + str(os.getpid()) + '.tmp'
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    try:
        with os.fdopen(fd, 'w') as output:
            json.dump(summary, output, separators=(',', ':'))
            output.write('\n'); output.flush(); os.fsync(output.fileno())
        os.rename(name, 'last.json', src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        try: os.unlink(name, dir_fd=directory)
        except FileNotFoundError: pass

def mount_usage():
    mounts = []
    seen = set()
    try:
        with open('/proc/self/mountinfo') as source:
            for line in source:
                fields = line.split()
                separator = fields.index('-')
                if fields[separator+1] not in ['ext4','xfs','btrfs','zfs','overlay','fuseblk']:
                    continue
                mount = fields[4].replace('\\040',' ').replace('\\134','\\')
                if mount in seen or len(mounts)>=16 or not os.path.isdir(mount):
                    continue
                seen.add(mount)
                disk = os.statvfs(mount)
                avail, total = disk.f_bavail*disk.f_frsize, disk.f_blocks*disk.f_frsize
                mounts.append(dict(mount=mount,total_bytes=total,available_bytes=avail,percent=int(100*(total-avail)/total) if total else 0))
    except (OSError, ValueError):
        pass
    return mounts

def main():
    start = time.monotonic()
    request = json.load(sys.stdin)
    args, policy = request['args'], request['policy']
    # Canonical policy is checked by the Go runner; enforce adapter safety floors.
    tier = policy['safe_tier']
    if policy['schema_version'] != 1 or tier['user_tmp_min_days'] < 10 or tier['var_tmp_min_days'] < 14 or tier['cargo_min_days'] < 30 or tier['docker_min_hours'] < 168 or tier['npm_mode'] != 'verify-only' or tier['uv_mode'] != 'lock-aware-prune':
        raise ValueError('unsafe policy')
    home = os.path.expanduser('~')
    disk = os.statvfs('/')
    avail, total = disk.f_bavail * disk.f_frsize, disk.f_blocks * disk.f_frsize
    pct = int(100 * (total - avail) / total) if total else 0
    cats = {}
    state = None
    if APPLY and args['scope']=='user':
        try: state = state_lock(home)
        except OSError: cats = {x: category('deferred: local scope lock busy or unsafe') for x in ['user_tmp','uv','npm','cargo','docker','journald']}
    if cats:
        pass
    elif args['scope'] == 'root':
        cats = {x: category('root_helper_missing') for x in ['var_tmp', 'journald', 'docker']}
    else:
        opened, complete = holders()
        budget = {'remaining': policy['scan_budgets']['max_items']}
        cats['user_tmp'] = scan('/tmp', policy, opened, complete, tier['user_tmp_min_days'], APPLY, budget)
        for name, path in [('user_cache_tmp', home+'/.cache/tmp'), ('user_local_tmp', home+'/.local/tmp')]:
            cats[name] = scan(path, policy, opened, complete, tier['user_tmp_min_days'], APPLY, budget) if os.path.isdir(path) else category('temporary directory absent')
        cats['uv'] = native('uv', home + '/.cache/uv', ['uv', 'cache', 'prune'], policy, opened, complete)
        cats['npm'] = native('npm', home + '/.npm', ['npm', 'cache', 'verify'], policy, opened, complete)
        cats['cargo'] = category('unsupported: tested native age-aware GC unavailable')
        cats['docker'] = docker(policy, opened, complete)
        cats['journald'] = category('root_helper_missing')
    after = os.statvfs('/')
    avail_after = after.f_bavail*after.f_frsize
    pct_after = int(100*(total-avail_after)/total) if total else 0
    summary = dict(schema='fleet-disk-clean/v1', version='2.0.0', scope=args['scope'], host='agent', user='agent',
        mode='apply' if APPLY else 'dry-run', ts=datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        duration_s=int(time.monotonic()-start), config_digest=args['policy_digest'],
        disk=dict(mount='/', pct_before=pct, pct_after=pct_after, avail_bytes_before=avail, avail_bytes_after=avail_after),
        candidate_bytes=sum(x['candidate_bytes'] for x in cats.values()), freed_bytes=sum(x['freed_bytes'] for x in cats.values()), categories=cats,
        attention='', weekly=None, root=None)
    if state is not None:
        try: save_summary(state[0], summary)
        finally: os.close(state[1]); os.close(state[0])
    print(json.dumps(dict(summary=summary, operation=dict(schema='disk-safe/v2', policy_id=args['policy_id'], policy_digest=args['policy_digest'],
        ownership='hub' if args['scope']=='user' else 'local-timer', skip_code='root_helper_missing' if args['scope']=='root' else '', mounts=mount_usage(), protections=['credentials','generated_images','repositories','active-models','configured-paths','open-descriptors','locks'])), separators=(',', ':')))

if __name__ == '__main__':
    main()
