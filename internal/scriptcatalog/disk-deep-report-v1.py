# Pure observation adapter: all filesystem enumeration/content reads require
# O_NOATIME and descriptor-anchored O_NOFOLLOW. No writes or external caches.
import errno, select
import datetime, fnmatch, hashlib, itertools, json, os, stat, subprocess, sys, time

SECRET = '.env .env.* Documents Desktop Pictures Videos Music .ssh .gnupg .aws .azure .config .git .netrc .npmrc auth.json *secret* *credential* *token* *password* *.pem *.key *rollback* *current* *active* generated_images'.split()
ARCHIVES = ('.tar.gz', '.tgz', '.zip', '.tar', '.xz', '.gz')

APPLY = False

def inside(path, root):
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)

class ProtectionResolutionError(OSError):
    pass

class ProtectionChangedError(ProtectionResolutionError):
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

def protection_snapshot(lexical):
    resolved = resolved_if_present(lexical)
    try:
        info = os.lstat(lexical)
        root_identity = (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode), info.st_uid)
    except FileNotFoundError:
        root_identity = None
    aliases = {}
    pending, seen = [lexical], set()
    while pending:
        path = pending.pop()
        if path in seen: continue
        seen.add(path)
        if len(seen) > 256: raise ProtectionResolutionError('protection alias budget exceeded')
        prefix = '/'
        for part in path.split('/')[1:]:
            prefix = os.path.join(prefix, part)
            try: info = os.lstat(prefix)
            except FileNotFoundError: break
            if stat.S_ISLNK(info.st_mode):
                target = strict_realpath(prefix)
                identity = (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_uid)
                aliases[prefix] = (identity, target)
                # Include aliases in the link target chain, not only the spec.
                pending.append(os.path.abspath(os.path.join(os.path.dirname(prefix), os.readlink(prefix))))
    return root_identity, resolved, aliases

def revalidate_protections(policy):
    state = policy['_protection_state']
    if state['failed']: return False
    try:
        for spec, snapshot in policy['_protection_specs'].items():
            if protection_snapshot(spec) != snapshot:
                state['failed'] = True
                return False
    except OSError:
        state['failed'] = True
        return False
    return True

def normalized_protections(policy):
    # Same lexical + strict resolved snapshots as safe-v2. Concrete secret roots
    # are materialized without enumerating unrelated home entries.
    home = os.path.abspath(os.path.expanduser('~'))
    paths, specs = set(), {}
    builtins = [os.path.join(home, name) for name in SECRET if not any(c in name for c in '*?[')]
    builtins.append(os.path.join(home, '.codex/generated_images'))
    for raw in builtins + policy['protect_paths']:
        lexical = os.path.abspath(os.path.expanduser(raw))
        snapshot = protection_snapshot(lexical)
        specs[lexical] = snapshot
        paths.add(lexical)
        if snapshot[1] is not None: paths.add(snapshot[1])
    return dict(policy, _protection_paths=paths, _protection_specs=specs, _protection_state={'failed': False})

def stamp(ns):
    return datetime.datetime.fromtimestamp(ns / 1e9, datetime.timezone.utc).isoformat().replace('+00:00', 'Z')

def noatime_notice(result, error, label):
    if result is not None and getattr(error, 'errno', None) == errno.EPERM:
        notice = label + ' skipped: no O_NOATIME permission'
        if notice not in result['notices']: result['notices'].append(notice)

def listing(fd):
    with os.scandir(fd) as entries:
        for entry in entries: yield entry.name

def scan(policy, max_items, roots=None):
    home = os.environ['HOME']
    roots = roots or [home, '/tmp', '/var/tmp', '/usr/local/bin']
    budget = policy['scan_budgets']
    cap = min(max_items, budget['max_items'], 500)
    # Reserve one second for bounded serialization and supervisor handoff.
    deadline = time.monotonic() + max(0.1, min(budget['max_seconds'], 600) - 1)
    result = {'schema': 'disk-deep/v1', 'items': [], 'excluded': {}, 'inaccessible_roots': [], 'truncated': False,
              'partial': False, 'entries': 0, 'notices': ['Access times are weak under relatime/noatime.', 'Root inventory requires a read-only helper; inaccessible entries are unknown.']}
    try:
        policy = normalized_protections(policy)
    except OSError:
        result['partial'] = True
        result['notices'].append('Protection path resolution failed; scan deferred without reading aliases.')
        return result
    seen, hashes = set(), {}
    held = set()
    if roots == [home, '/tmp', '/var/tmp', '/usr/local/bin']:
        held, holders_complete, observed = file_holders(deadline, min(budget['max_entries'], 200000), result)
        result['entries'] = observed
        if observed >= min(budget['max_entries'], 200000): result['truncated'] = result['partial'] = True
        if not holders_complete:
            result['partial'] = True
            result['notices'].append('Holder visibility incomplete; installer candidates are excluded.')
    hash_budget = 64 * 1024 * 1024
    def excluded(s):
        a = result['excluded'].setdefault('protected', {'count': 0, 'allocated_bytes': 0})
        a['count'] += 1
        a['allocated_bytes'] += s.st_blocks * 512
    def expired():
        if result['entries'] >= min(budget['max_entries'], 200000) or time.monotonic() >= deadline or len(result['items']) >= cap:
            result['truncated'] = result['partial'] = True
            return True
        return False
    def walk(fd, path, device, depth=0):
        nonlocal hash_budget
        if depth > 128:
            result['partial'] = True
            return
        try:
            # A repository marker is checked before any candidate, independent
            # of listing order or entry budget.
            try:
                os.stat('.git', dir_fd=fd, follow_symlinks=False)
                excluded(os.fstat(fd)); return
            except FileNotFoundError: pass
            names = list(itertools.islice(listing(fd), max(0, min(budget['max_entries'], 200000) - result['entries']) + 1))
        except OSError:
            result['partial'] = True
            return
        # All repository roots, including clean/unknown repositories, are protected.
        if '.git' in names:
            excluded(os.fstat(fd))
            return
        for name in names:
            if expired(): return
            result['entries'] += 1
            full = os.path.join(path, name)
            try: s = os.stat(name, dir_fd=fd, follow_symlinks=False)
            except OSError:
                result['partial'] = True
                continue
            if stat.S_ISLNK(s.st_mode) or s.st_dev != device: continue
            key = (s.st_dev, s.st_ino)
            if key in seen: continue
            seen.add(key)
            if not revalidate_protections(policy):
                result['partial'] = True
                if 'Protection alias changed; remaining scan deferred.' not in result['notices']:
                    result['notices'].append('Protection alias changed; remaining scan deferred.')
                return
            basic = name.lower()
            for suffix in ('.bak', '.old', '.orig'):
                if basic.endswith(suffix): basic = basic[:-len(suffix)]
            if any(fnmatch.fnmatch(name.lower(), p) or fnmatch.fnmatch(basic, p) for p in SECRET) or any(full == p or full.startswith(p + '/') for p in policy['_protection_paths']):
                excluded(s)
                continue
            category = None
            if name.endswith(('.bak', '.old', '.orig')) or (path == home and name.startswith('clawctl-agent-backup-')) or (path == '/usr/local/bin' and '.bak-' in name): category = 'app-update-backups'
            elif full == '/tmp/clawctl-up' or name.startswith('clawctl-agent-bootstrap-') and name.endswith('.tar.gz'): category = 'installer-leftovers'
            elif '/.codex/sessions/' in full or '/.claude/projects/' in full: category = 'agent-session-stores'
            elif any(c in ('build', 'dist', 'releases') for c in full.split('/')): category = 'release-build-directories'
            elif '/.cache/' in full or name == '.cache' or name.endswith(('.gguf', '.safetensors', '.pt')): category = 'caches-models'
            elif stat.S_ISREG(s.st_mode) and name.endswith(ARCHIVES): category = 'duplicate-archives'
            if full in held or category == 'installer-leftovers' and (any(p.startswith(full + '/') for p in held) or roots == [home, '/tmp', '/var/tmp', '/usr/local/bin'] and not holders_complete):
                excluded(s); continue
            if category and stat.S_ISREG(s.st_mode):
                identity = {'dev': s.st_dev, 'inode': s.st_ino, 'type': stat.S_IFMT(s.st_mode), 'size': s.st_size, 'mtime_ns': s.st_mtime_ns, 'ctime_ns': s.st_ctime_ns}
                item = {'id': hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()[:32], 'category': category, 'private_path': full,
                        'allocated_bytes': s.st_blocks * 512, 'logical_bytes': s.st_size, 'last_used': stamp(s.st_atime_ns), 'last_used_source': 'atime',
                        'evidence_strength': 'weak', 'owner_uid': s.st_uid, 'owner_app': 'unknown', 'confidence': 'low', 'suggested_action': 'investigate',
                        'reversible': False, 'exclusion_reason': '', 'identity': identity}
                if category == 'duplicate-archives':
                    if s.st_uid == os.geteuid() and s.st_size <= hash_budget:
                        try:
                            f = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NOATIME | os.O_NONBLOCK, dir_fd=fd)
                            try:
                                before = os.fstat(f)
                                if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns): raise OSError('changed')
                                h = hashlib.sha256()
                                remaining = s.st_size
                                while remaining and time.monotonic() < deadline:
                                    data = os.read(f, min(65536, remaining))
                                    if not data: break
                                    h.update(data); remaining -= len(data); hash_budget -= len(data)
                                after = os.fstat(f)
                                if remaining or (after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (s.st_size, s.st_mtime_ns, s.st_ctime_ns): raise OSError('changed')
                                digest = h.hexdigest()
                                item['content_digest'] = 'sha256:' + digest
                                if digest in hashes:
                                    item.update(confidence='high', suggested_action='quarantine', reversible=True)
                                else: hashes[digest] = item['id']
                            finally: os.close(f)
                        except OSError as error:
                            item['evidence_strength'] = 'weak'
                            noatime_notice(result, error, 'Archive hashing')
                # Generation and holder evidence are deliberately required before action.
                if category == 'agent-session-stores':
                    days = max(0, (time.time_ns() - s.st_mtime_ns) // 86400000000000)
                    item['age_bucket'] = '0-7 days' if days < 7 else '7-30 days' if days < 30 else '30-90 days' if days < 90 else '90+ days'
                if category == 'release-build-directories': item['exclusion_reason'] = 'current/rollback manifests unknown; review required'
                if category == 'app-update-backups': item['exclusion_reason'] = 'generation references unknown; review required'
                if category == 'installer-leftovers': item['exclusion_reason'] = 'installer holder visibility unknown; review required'
                if category == 'caches-models': item['exclusion_reason'] = 'active model/service lease unknown; review required'
                result['items'].append(item)
            if stat.S_ISDIR(s.st_mode) and path != '/usr/local/bin':
                try:
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NOATIME, dir_fd=fd)
                    try:
                        fresh = os.fstat(child)
                        if fresh.st_dev == device and fresh.st_ino == s.st_ino: walk(child, full, device, depth + 1)
                        else: result['partial'] = True
                    finally: os.close(child)
                except OSError as error:
                    result['partial'] = True
                    if error.errno == errno.EPERM and 'Subtrees skipped: no O_NOATIME permission.' not in result['notices']:
                        result['notices'].append('Subtrees skipped: no O_NOATIME permission.')
    for root in roots:
        if expired(): break
        try:
            # Anchor each ancestor to prevent a replaced parent symlink escaping roots.
            fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
            try:
                for component in root.strip('/').split('/'):
                    if not component: continue
                    child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    os.close(fd); fd = child
                root_fd = os.open('.', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NOATIME, dir_fd=fd)
                try: walk(root_fd, root, os.fstat(root_fd).st_dev)
                finally: os.close(root_fd)
            finally: os.close(fd)
        except OSError as error:
            label = 'reviewed-root-' + str(roots.index(root) + 1)
            result['inaccessible_roots'].append(label)
            result['partial'] = True
            if error.errno == errno.EPERM:
                result['notices'].append(label + ' skipped: no O_NOATIME permission')
    result['items'].sort(key=lambda x: (x['last_used'] == '', -x['allocated_bytes'], {'high': 0, 'medium': 1, 'low': 2}[x['confidence']], x['last_used']))
    if roots == [home, '/tmp', '/var/tmp', '/usr/local/bin']:
        inventory_processes(result, cap, deadline, max_entries=budget['max_entries'])
        inventory_docker(result, cap, deadline, max_entries=budget['max_entries'])
    if time.monotonic() >= deadline: result['truncated'] = result['partial'] = True
    result['items'].sort(key=lambda x: (x['last_used'] == '', -x['allocated_bytes'], {'high': 0, 'medium': 1, 'low': 2}[x['confidence']], x['last_used']))
    return result

def file_holders(deadline, budget, result=None):
    held, complete = set(), True
    original_budget = budget
    try:
        fd = os.open('/proc', os.O_RDONLY | os.O_DIRECTORY | os.O_NOATIME)
        try: pids = list(itertools.islice(listing(fd), budget + 1))
        finally: os.close(fd)
    except OSError as error:
        noatime_notice(result, error, 'Process-holder inventory')
        return held, False, 0
    for pid in pids:
        if not pid.isdigit(): continue
        if time.monotonic() >= deadline or budget <= 0: return held, False, original_budget - budget
        budget -= 1
        try:
            fd = os.open('/proc/' + pid + '/fd', os.O_RDONLY | os.O_DIRECTORY | os.O_NOATIME)
            try:
                for name in listing(fd):
                    if budget <= 0 or time.monotonic() >= deadline: return held, False, original_budget - budget
                    budget -= 1
                    try: held.add(os.readlink('/proc/' + pid + '/fd/' + name).removesuffix(' (deleted)'))
                    except FileNotFoundError: pass
                    except OSError: complete = False
            finally: os.close(fd)
            try: held.add(os.readlink('/proc/' + pid + '/cwd'))
            except FileNotFoundError: pass
            except OSError: complete = False
        except FileNotFoundError: pass
        except OSError as error:
            complete = False
            noatime_notice(result, error, 'Process-holder inventory')
    return held, complete, original_budget - budget

def read_noatime(path, maximum=65536):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NOATIME)
    try:
        data = os.read(fd, maximum + 1)
        if len(data) > maximum: raise OSError('limit')
        return data.decode()
    finally: os.close(fd)

def inventory_processes(result, cap, deadline, proc_root='/proc', max_entries=200000):
    try:
        fd = os.open(proc_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOATIME)
        try: pids = list(itertools.islice(listing(fd), 200000))
        finally: os.close(fd)
        boot = read_noatime(proc_root + '/sys/kernel/random/boot_id').strip()
    except OSError as error:
        result['partial'] = True
        noatime_notice(result, error, 'Process-holder inventory')
        result['notices'].append('Process-holder inventory inaccessible.')
        return
    for pid in pids:
        if time.monotonic() >= deadline or len(result['items']) >= cap or result.get('entries', 0) >= max_entries:
            result['partial'] = result['truncated'] = True
            return
        if not pid.isdigit(): continue
        result['entries'] = result.get('entries', 0) + 1
        base = proc_root + '/' + pid
        try:
            owner = os.stat(base).st_uid
            if owner != os.geteuid(): continue
            raw = read_noatime(base + '/stat')
            name = raw[raw.index('(') + 1:raw.rindex(')')]
            fields = raw[raw.rindex(')') + 2:].split()
            if name != 'codex-linux-san' and name != 'codex-linux-sandbox': continue
            if fields[1] != '1' and os.path.exists(proc_root + '/' + fields[1]): continue
            descriptors = os.open(base + '/fd', os.O_RDONLY | os.O_DIRECTORY | os.O_NOATIME)
            try:
                held = [os.readlink(base + '/fd/' + f) for f in itertools.islice(listing(descriptors), 4096)]
            finally: os.close(descriptors)
            temp = [f for f in held if f.startswith('/tmp/') or f.startswith('/var/tmp/')]
            if not temp: continue
            start = fields[19]
            identity = {'dev': 0, 'inode': int(pid), 'type': 0, 'size': 0, 'mtime_ns': 0, 'ctime_ns': 0}
            result['items'].append({'id': hashlib.sha256((boot + pid + start).encode()).hexdigest()[:32], 'category': 'orphaned-processes',
                'private_path': base, 'allocated_bytes': 0, 'logical_bytes': 0, 'last_used': '', 'last_used_source': 'process start ticks', 'evidence_strength': 'strong',
                'owner_uid': owner, 'owner_app': 'sandbox helper', 'confidence': 'medium', 'suggested_action': 'investigate', 'reversible': False,
                'exclusion_reason': '', 'identity': identity, 'pid': int(pid), 'start_time': start, 'boot_id': boot, 'holder_count': len(temp)})
        except (OSError, ValueError, IndexError) as error:
            result['partial'] = True
            noatime_notice(result, error, 'Process-holder inventory')

def inventory_docker(result, cap, deadline, max_entries=200000):
    def cli(args):
        timeout = min(15, deadline - time.monotonic())
        if timeout <= 0: raise OSError('budget')
        # Fixed binary/argv; no user-selected command or mutation. Docker reads
        # configuration but listing/inspect never refresh images or credentials.
        p = subprocess.Popen(['/usr/bin/docker', '--config', '/nonexistent/clawctl-disk-report'] + args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             env={'PATH': '/usr/bin:/bin', 'HOME': os.environ['HOME'], 'LANG': 'C'})
        output = bytearray()
        stop = time.monotonic() + timeout
        try:
            while True:
                remaining = stop - time.monotonic()
                if remaining <= 0: raise subprocess.TimeoutExpired(p.args, timeout)
                ready, _, _ = select.select([p.stdout], [], [], remaining)
                if not ready: raise subprocess.TimeoutExpired(p.args, timeout)
                # One excess byte detects overflow without buffering its tail.
                data = os.read(p.stdout.fileno(), min(65536, 2 * 1024 * 1024 + 1 - len(output)))
                if not data: break
                output.extend(data)
                if len(output) > 2 * 1024 * 1024: raise OSError('listing limit')
            if p.wait(timeout=max(0.001, stop - time.monotonic())):
                raise subprocess.CalledProcessError(p.returncode, p.args)
            return output.decode()
        finally:
            if p.poll() is None:
                p.kill()
            p.wait()
            p.stdout.close()
    try:
        ids = cli(['container', 'ls', '-aq', '--no-trunc']).split()
        if len(ids) + result.get('entries', 0) > max_entries:
            result['truncated'] = result['partial'] = True
            return
        result['entries'] = result.get('entries', 0) + len(ids)
        used = set()
        for offset in range(0, len(ids), 100):
            used.update(cli(['container', 'inspect', '--format', '{{.Image}}'] + ids[offset:offset+100]).split())
        images = cli(['image', 'ls', '--digests', '--no-trunc', '--format', '{{json .}}']).splitlines()
        seen = set()
        for line in images:
            if len(result['items']) >= cap or time.monotonic() >= deadline or result.get('entries', 0) >= max_entries:
                result['partial'] = result['truncated'] = True
                break
            result['entries'] = result.get('entries', 0) + 1
            image = json.loads(line)
            digest = image.get('Digest', '')
            image_id = image.get('ID', '')
            if image_id in used or image_id in seen or image.get('Tag') == '<none>' or not digest.startswith('sha256:'): continue
            seen.add(image_id)
            # Size from inspect is logical; shared layer reclaim is unknown.
            details = json.loads(cli(['image', 'inspect', image_id]))[0]
            if details['Id'] in used: continue
            size = max(0, int(details.get('Size', 0)))
            result['items'].append({'id': hashlib.sha256(digest.encode()).hexdigest()[:32], 'category': 'unused-docker-images',
                'private_path': '/docker/images/' + digest, 'allocated_bytes': 0, 'logical_bytes': size, 'last_used': '', 'last_used_source': 'all-container references',
                'evidence_strength': 'weak', 'owner_uid': os.geteuid(), 'owner_app': 'docker', 'confidence': 'medium', 'suggested_action': 'investigate',
                'reversible': False, 'exclusion_reason': 'shared-layer reclaim and rollback references unknown', 'identity': {'dev': 0, 'inode': 0, 'type': 0, 'size': size, 'mtime_ns': 0, 'ctime_ns': 0}, 'content_digest': digest})
    except (OSError, subprocess.SubprocessError, ValueError, KeyError):
        result['partial'] = True
        result['notices'].append('Docker inventory unavailable or incomplete; no clean verdict.')

if __name__ == '__main__':
    request = json.load(sys.stdin)
    report = scan(request['policy'], request['args']['max_items'])
    report['policy_id'] = request['args']['policy_id']
    report['policy_digest'] = request['args']['policy_digest']
    print(json.dumps(report, sort_keys=True, separators=(',', ':')))
