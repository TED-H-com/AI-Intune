#!/usr/bin/python3
"""Admin-approved, report-only BAT sweep. JSON arguments arrive on stdin, never as commands."""
import asyncio
import contextlib
import contextvars
import functools
import importlib
import importlib.machinery
import errno
import hashlib
import stat
import struct
import sysconfig
import resource
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time
from datetime import datetime, timezone

TED_ACTIVE_S = 30 * 60
MIN_IDLE_S = 10 * 60
KEEPGOING_WINDOW_S = 72 * 3600
FAILOVER_WINDOW_S = 2 * 3600
MAX_NUDGES_PER_HOST = 3
MAX_NUDGES_PER_SESSION_DAY = 6
MAX_FAILOVERS_PER_HOST = 2
OUR_MARKERS = ("[BAT hourly sweep]", "FYI from the supervisor", "decided by the supervisor", "You are taking over", "Handoff")
WRITE_DENYLIST = frozenset(("session_answer", "session_set_permissions", "session_failover", "session_cleanup", "session_send", "ask", "session_start", "session_continue", "session_interrupt", "operation_submit", "cleanup_apply"))

READ_CALL = contextvars.ContextVar("connector_read", default=False)

class Discard:
    def write(self, value):
        return len(value)
    def flush(self):
        pass

def enforce_io(private):
    root = Path(private).resolve()
    def audit(event, args):
        if event == "open":
            path, mode, flags = args
            writing = (isinstance(mode, str) and any(c in mode for c in "wax+")) or (flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC))
            if writing and isinstance(path, int):
                path = os.readlink(f"/proc/self/fd/{path}")
            if writing and (not isinstance(path, (str, bytes, os.PathLike)) or not Path(os.fsdecode(path)).resolve().is_relative_to(root)):
                raise PermissionError("report-only write boundary")
        if event in ("os.remove", "os.rmdir", "os.mkdir", "os.rename", "os.chmod", "os.chown", "os.truncate", "os.link", "os.symlink"):
            def under_private(path, directory_fd=-1):
                if not isinstance(path, (str, bytes, os.PathLike)):
                    return False
                target = Path(os.fsdecode(path))
                if not target.is_absolute() and isinstance(directory_fd, int) and directory_fd >= 0:
                    target = Path(os.readlink(f"/proc/self/fd/{directory_fd}")) / target
                return target.resolve().is_relative_to(root)
            if event in ("os.rename", "os.link"):
                targets = [(args[0], args[2]), (args[1], args[3])]
            elif event == "os.symlink":
                targets = [(args[0], args[2]), (args[1], args[2])]
            else:
                index = {"os.remove": 1, "os.rmdir": 1, "os.mkdir": 2, "os.chmod": 2, "os.chown": 3}.get(event)
                targets = [(args[0], args[index] if index is not None and len(args) > index else -1)]
            if any(not under_private(path, directory_fd) for path, directory_fd in targets):
                raise PermissionError("report-only state boundary")
        if event in ("subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.fork"):
            raise PermissionError("report-only process boundary")
        if event in ("socket.connect", "socket.getaddrinfo", "socket.sendto") and not READ_CALL.get():
            raise PermissionError("network outside connector read")
    sys.addaudithook(audit)

class ReadOnly:
    """Defense in depth only; admin-approved tree digest is the trust boundary."""
    def __init__(self, module, allowed):
        self._module, self._allowed = module, frozenset(allowed)

    def __getattr__(self, name):
        if name in WRITE_DENYLIST or name not in self._allowed:
            raise RuntimeError("report-only connector boundary")
        value = getattr(self._module, name)
        if name in ("sessions_list", "session_read", "sessions_triage"):
            @functools.wraps(value)
            async def read(*args, **kwargs):
                token = READ_CALL.set(True)
                try:
                    return await value(*args, **kwargs)
                finally:
                    READ_CALL.reset(token)
            return read
        return value

DESTRUCTIVE_CMD = re.compile(
    r"\brm\s+-[a-zA-Z]*[rf][a-zA-Z]*\s+(?:--\s+)?(?:/|~|\$HOME|\.\.|\*(?:\s|$|['\"]))"
    r"|\bgit\s+push\b|\bgit\s+reset\s+--hard\b|\bgit\s+clean\s+-[a-zA-Z]*f|\bgit\s+branch\s+-D\b"
    r"|\bgit\s+(?:checkout|restore)\s+(?:--\s+)?\.(?:\s|$)|\bgit\s+filter-(?:branch|repo)\b"
    r"|\b(?:DROP\s+(?:TABLE|DATABASE|SCHEMA)|TRUNCATE\s+TABLE)\b|\bmkfs\b|\bdd\s+if=|\bshred\b|\bwipefs\b"
    r"|\bsudo\b|\bchmod\s+-R\s+777\b|\bcurl\b[^|]*\|\s*(?:ba|z)?sh\b|\bkubectl\s+delete\b"
    r"|\bterraform\s+(?:apply|destroy)\b|\bdocker\s+(?:system\s+)?prune\b|\bsystemctl\s+(?:stop|disable|restart|mask)\b"
    r"|\b(?:reboot|shutdown|poweroff)\b|\b(?:npm|pnpm|cargo|yarn)\s+publish\b|\btwine\s+upload\b"
    r"|\bgh\s+(?:release\s+create|pr\s+merge|repo\s+delete)\b",
    re.I,
)
# never continue when the last message asks for any of these (en + zh-TW/zh-CN)
NEVER_TOPIC = re.compile(
    r"credential|password|passphrase|api[ _-]?key|secret|token|2fa|otp|log ?in|sign ?in|oauth|ssh key"
    r"|憑證|密碼|金鑰|登入|驗證碼|權杖"
    r"|payment|pay |purchase|billing|invoice|subscription|credit card|cost|budget|付款|購買|費用|訂閱|信用卡|預算|花費"
    r"|public release|publish|release (?:it|this|v?\d)|tag (?:and )?push|deploy(?:ment)? to prod|go live|app store|上架|發布|发布|公開|正式版"
    r"|delete|drop (?:table|database)|force[- ]push|reset --hard|wipe|destroy|irreversible|刪除|删除|清除|覆蓋|不可逆|強制推",
    re.I,
)
ASKS = re.compile(
    r"\?|？|\b(?:please|need(?:s)? (?:you|your|a human|ted)|should i|do you want|can you|could you|let me know|confirm|approve)\b"
    r"|請|需要你|需要您|是否|要不要|確認|批准|同意|提供|告訴我",
    re.I,
)
MILESTONE = re.compile(
    r"milestone|phase\s*\d+\s*(?:is\s*)?(?:complete|completed|done|finished)|all (?:planned )?(?:phases|tasks|steps) (?:are )?(?:complete|done)"
    r"|awaiting (?:your |a |human )?(?:decision|review|input|approval)|needs? (?:ted|your decision|a human|human review)"
    r"|blocked (?:on|by) (?:credentials|access|a decision)|stopping here|stop point"
    r"|里程碑|階段.{0,8}(?:完成|結束)|阶段.{0,8}完成|等待.{0,6}(?:決定|决定|確認|审核|審核)|需要.{0,6}(?:決定|决定|確認|人工)|待.{0,4}(?:決定|確認)|請.{0,6}(?:決定|確認|選擇)",
    re.I,
)

# Excerpts are opt-in. Redact the complete input before truncation.
SECRET = re.compile(r"""(?ix)
    -----BEGIN[^\n]*PRIVATE\ KEY-----.*?-----END[^\n]*PRIVATE\ KEY-----
    |(?:basic|bearer)\s+[^\s"']+
    |\b(?:AKIA|ASIA)[A-Z0-9]{16}\b
    |[a-z][a-z0-9+.-]*://[^\s/@]+(?::[^\s/@]*)?@[^\s]+
    |["']?(?:[a-z0-9_-]*(?:token|password|secret|api[_-]?key|credential|access[_-]?key)[a-z0-9_-]*)["']?\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;}]+)
    |(?:sk-|gh[pousr]_|github_pat_)[a-z0-9_-]+
    |[a-z0-9_+/=-]{24,}
""", re.S)

def excerpt(value):
    return re.sub(r"\s+", " ", SECRET.sub("[REDACTED]", str(value or ""))).strip()[:120]

class Refused(Exception):
    pass

class BudgetHit(Exception):
    pass

MAX_SESSIONS = 50
MAX_READS = 200
MAX_MESSAGES = 20
MAX_MESSAGE_CHARS = 2000
MAX_DECODED_CHARS = 2 * 1024 * 1024

class Budget:
    def __init__(self):
        self.calls = 0
        self.chars = 0

    def charge_call(self):
        if self.calls >= MAX_READS:
            raise BudgetHit("read_call_budget")
        self.calls += 1

    def charge_bytes(self, count):
        self.chars += count
        if self.chars > MAX_DECODED_CHARS:
            raise BudgetHit("decoded_char_budget")

    def decoded(self, value, depth=0):
        if depth > 20:
            raise BudgetHit("response_depth_budget")
        if isinstance(value, str):
            self.charge_bytes(len(value.encode("utf-8")) + 2)
        elif isinstance(value, dict):
            if len(value) > 1000:
                raise BudgetHit("response_item_budget")
            self.charge_bytes(2 + 2 * len(value))
            for key, item in value.items():
                if key == "messages" and isinstance(item, list):
                    if len(item) > MAX_MESSAGES:
                        raise BudgetHit("message_count_budget")
                    for message in item:
                        if len(message.get("text", "")) > MAX_MESSAGE_CHARS:
                            raise BudgetHit("message_char_budget")
                if key == "sessions" and isinstance(item, list) and len(item) >= MAX_SESSIONS:
                    raise BudgetHit("session_budget")
                self.decoded(key, depth+1)
                self.decoded(item, depth+1)
        elif isinstance(value, (list, tuple)):
            self.charge_bytes(2 + len(value))
            if len(value) > 1000:
                raise BudgetHit("response_item_budget")
            for item in value:
                self.decoded(item, depth+1)
        elif value is None or isinstance(value, (int, float, bool)):
            self.charge_bytes(len(str(value)))
        else:
            raise BudgetHit("response_type_budget")
        return value

    async def read(self, fn, *args, **kwargs):
        self.charge_call()
        return self.decoded(await fn(*args, **kwargs))

    def registry(self, fn, host):
        self.charge_call()
        entries = fn(host)
        if len(entries) >= MAX_SESSIONS:
            raise BudgetHit("session_budget")
        return self.decoded(entries)

def connector_directory():
    version = f"python{sys.version_info.major}.{sys.version_info.minor}"
    candidates = [Path.home() / ".local/lib" / version / "site-packages",
                  Path("/usr/local/lib") / version / "site-packages",
                  Path("/usr/local/lib") / version / "dist-packages",
                  Path("/usr/lib/python3/dist-packages")]
    for parent in candidates:
        package = parent / "bat_agent_connector"
        if package.exists() or package.is_symlink():
            return package
    raise FileNotFoundError("connector unavailable")

def connector_digest(package, snapshot=None):
    info = package.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022:
        raise Refused("connector_unsafe_tree")
    digest = hashlib.sha256()
    total = 0
    paths = sorted(package.rglob("*"), key=lambda p: p.relative_to(package).as_posix())
    for path in paths:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_mode & 0o022:
            raise Refused("connector_unsafe_tree")
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode) or path.suffix.lower() in (".so", ".pyd", ".dll", ".dylib"):
            raise Refused("connector_unsafe_tree")
        total += info.st_size
        if total > 32 * 1024 * 1024:
            raise Refused("connector_tree_budget")
        relative_path = path.relative_to(package)
        relative = relative_path.as_posix().encode()
        target = None
        if snapshot is not None:
            destination = snapshot / relative_path
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            target = destination
        digest.update(struct.pack(">I", len(relative)))
        digest.update(relative)
        digest.update(struct.pack(">Q", info.st_size))
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with contextlib.ExitStack() as stack:
            stream = stack.enter_context(os.fdopen(fd, "rb"))
            output = None
            if target is not None:
                output_fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                output = stack.enter_context(os.fdopen(output_fd, "wb"))
            opened = os.fstat(stream.fileno())
            if (opened.st_dev, opened.st_ino, opened.st_size) != (info.st_dev, info.st_ino, info.st_size):
                raise Refused("connector_unsafe_tree")
            remaining = info.st_size
            while remaining:
                chunk = stream.read(min(65536, remaining))
                if not chunk:
                    raise Refused("connector_unsafe_tree")
                remaining -= len(chunk)
                if output is not None and output.write(chunk) != len(chunk):
                    raise Refused("connector_snapshot_failed")
                # These are the exact bytes written to the private import tree.
                digest.update(chunk)
            if stream.read(1):
                raise Refused("connector_unsafe_tree")
    if not (package / "__init__.py").is_file():
        raise Refused("connector_unsafe_tree")
    return digest.hexdigest()

class PinnedFinder:
    def __init__(self, package, stdlib):
        self.package, self.stdlib = package, stdlib

    def find_spec(self, fullname, path=None, target=None):
        if fullname == "bat_agent_connector":
            return importlib.machinery.PathFinder.find_spec(fullname, [str(self.package.parent)])
        if fullname.startswith("bat_agent_connector."):
            if not path or not all(Path(p).resolve().is_relative_to(self.package.resolve()) for p in path):
                raise ImportError("connector path escape")
            return importlib.machinery.PathFinder.find_spec(fullname, path)
        # No unpinned sibling packages or connector dependencies.
        if path and not all(any(Path(p).is_relative_to(Path(root)) for root in self.stdlib) for p in path):
            raise ImportError("unpinned dependency")
        spec = importlib.machinery.PathFinder.find_spec(fullname, path or self.stdlib)
        if spec is None:
            raise ImportError("unpinned dependency")
        return spec

def isolated_imports(package):
    stdlib = [sysconfig.get_path("stdlib"), sysconfig.get_path("platstdlib")]
    stdlib += [str(Path(root) / "lib-dynload") for root in stdlib]
    sys.path[:] = list(dict.fromkeys(stdlib)) + [str(package.parent)]
    sys.meta_path[:] = [importlib.machinery.BuiltinImporter, importlib.machinery.FrozenImporter, PinnedFinder(package, stdlib)]
    sys.dont_write_bytecode = True

def channel_mapping():
    import tomllib
    # Each component is opened relative to a retained directory descriptor.
    fd = os.open(Path.home(), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        home_info = os.fstat(fd)
        if home_info.st_uid != os.getuid() or home_info.st_mode & 0o022:
            raise Refused("channels_unsafe")
        for component in (".config", "bat-agent-connector"):
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            if info.st_uid != os.getuid() or info.st_mode & 0o022:
                raise Refused("channels_unsafe")
        channel_fd = os.open("discord-channels.toml", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(channel_fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
                raise Refused("channels_unsafe")
            data = stream.read(65537)
            if len(data) > 65536:
                raise BudgetHit("channels_byte_budget")
        return tomllib.loads(data.decode()).get("channels", [])
    finally:
        os.close(fd)

def ts(value):
    try:
        return datetime.fromisoformat(value).timestamp()
    except (ValueError, TypeError):
        return 0

def classify(messages, now):
    agent = next((m for m in reversed(messages) if m.get("role") not in ("user", "system") and m.get("text")), None)
    human = next((m for m in reversed(messages) if m.get("role") == "user" and not any(k in m.get("text", "") for k in OUR_MARKERS)), None)
    if human and ts(human.get("ts")) > now - TED_ACTIVE_S:
        return "skip", "Ted active"
    if not agent:
        return "skip", "no agent output"
    text = agent["text"]
    tail = text[-1500:]
    if NEVER_TOPIC.search(tail) and ASKS.search(tail[-800:]):
        return "needs_human", "never-topic question"
    status = re.search(r"BAT-STATUS[^\n]*?\b(NEED_HUMAN|MILESTONE|CONTINUE)\b", text)
    if status and status[1] == "NEED_HUMAN":
        return "needs_human", "BAT-STATUS NEED_HUMAN"
    if (status and status[1] == "MILESTONE") or (not status and MILESTONE.search(tail)):
        return "milestone", "milestone/decision"
    if status and status[1] == "CONTINUE":
        return "nudge", "BAT-STATUS CONTINUE"
    return "needs_human", "Jev stop-point evaluation unavailable in report-only mode"

async def collect(args, now=None):
    # TemporaryDirectory uses mkdtemp (0700); exit removes even refused snapshots.
    with tempfile.TemporaryDirectory(prefix="connector-snapshot-", dir=os.environ["TMPDIR"]) as private:
        snapshot = Path(private) / "bat_agent_connector"
        snapshot.mkdir(mode=0o700)
        return await collect_snapshot(args, snapshot, now=now)

async def collect_snapshot(args, snapshot, now=None):
    try:
        package = connector_directory()
        if connector_digest(package, snapshot) != args["connector_tree_sha256"]:
            raise Refused("connector_digest_mismatch")
        isolated_imports(snapshot)
        mapping = channel_mapping()
    except Refused as e:
        return {"status": "refused", "reason": str(e)}
    except BudgetHit as e:
        return {"status": "partial", "reason": str(e)}
    except OSError as e:
        if e.errno in (errno.ELOOP, errno.ENOTDIR):
            return {"status": "refused", "reason": "channels_unsafe"}
        return {"status": "unavailable", "reason": "connector_or_channels_unavailable"}
    except ValueError:
        return {"status": "unavailable", "reason": "connector_or_channels_unavailable"}
    budget = Budget()
    try:
        config_api = ReadOnly(importlib.import_module("bat_agent_connector.config"), ("load_config",))
        fleet_api = ReadOnly(importlib.import_module("bat_agent_connector.fleet"), ("Fleet",))
        service = ReadOnly(importlib.import_module("bat_agent_connector.service"), ("sessions_list", "session_read"))
        registry = ReadOnly(importlib.import_module("bat_agent_connector.registry"), ("list_entries",))
        triage = ReadOnly(importlib.import_module("bat_agent_connector.triage"), ("QUOTA_PATTERNS",))
        config = config_api.load_config()
        if config is None:
            raise ValueError("missing config")
    except Exception:
        return {"status": "unavailable", "reason": "connector package or configuration unavailable"}
    now = time.time() if now is None else now
    report = {"schema_version": 1, "status": "ok", "generated_at": datetime.fromtimestamp(now, timezone.utc).isoformat(), "hosts": {}, "would_actions": [], "needs_human": [], "limitations": ["Cleanup gates and Jev require forbidden calls; reported as unknown", "Daily nudge history inferred only from available transcript; no persistent state"]}
    fleet = fleet_api.Fleet(config, actor="bat-sweep-report")
    try:
        for host in args["hosts"]:
            rows = report["hosts"][host] = []
            def add(sid, action, reason, text=""):
                item = {"host": host, "session_id": hashlib.sha256(str(sid).encode()).hexdigest()[:12], "action": action, "reason": re.sub(r"[^a-z0-9]+", "_", reason.lower()).strip("_")}
                if args.get("include_excerpts", False):
                    item["excerpt"] = excerpt(text)
                rows.append(item)
                if action in ("approve", "failover", "nudge"):
                    report["would_actions"].append(item)
                if action in ("escalate", "needs_human", "milestone", "cleanup_unknown"):
                    report["needs_human"].append(item)
                return item
            try:
                sessions = (await budget.read(service.sessions_list, fleet, host, limit=50, check_pending="none"))["sessions"]
                entries = budget.registry(registry.list_entries, host)
                reg = {e["session_id"]: e for e in entries}
                gone = {e["session_id"] for e in entries if e.get("status") not in (None, "active") or e.get("superseded_by")}
                gone.update(e["failover_of"] for e in entries if e.get("failover_of"))
                transcripts = {}
                for row in sessions:
                    sid = row["session_id"]
                    data = await budget.read(service.session_read, fleet, host, sid, last_n=20, max_message_chars=2000)
                    transcripts[sid] = data
                    pending = data.get("pending") or {}
                    preview = pending.get("input_preview", "")
                    if pending.get("kind") == "ask_user":
                        add(sid, "needs_human", "ask-user question", "; ".join(q.get("question", "") for q in pending.get("questions", [])))
                    elif pending.get("kind") == "permission" and pending.get("toolUseId"):
                        unsafe = bool(DESTRUCTIVE_CMD.search(preview))
                        add(sid, "escalate" if unsafe else "approve", "destructive/external command" if unsafe else "reference safe-prompt rule", preview)
                # Avoid triage's hidden fanout: use bounded cached evidence only.
                quota = []
                for row in sessions:
                    msgs = transcripts[row["session_id"]].get("messages", [])
                    tail = msgs[-1].get("text", "")[-600:] if msgs else ""
                    if row.get("agent_kind") == "claude" and (row.get("state") == "quota_exhausted" or any(p.search(tail) for p in triage.QUOTA_PATTERNS)):
                        quota.append(row)
                failovers = 0
                for row in quota:
                    sid = row["session_id"]
                    if sid in gone:
                        continue
                    msgs = transcripts[sid].get("messages", [])
                    last = ts(msgs[-1].get("ts")) if msgs else 0
                    newer = any(s["session_id"] != sid and s.get("workspace") == row.get("workspace") and ts(s.get("last_activity")) > last for s in sessions)
                    if last and now - last <= FAILOVER_WINDOW_S and not newer:
                        add(sid, "failover" if failovers < MAX_FAILOVERS_PER_HOST else "skip", "recent quota exhaustion" if failovers < MAX_FAILOVERS_PER_HOST else "host failover cap")
                        failovers += 1
                nudges = 0
                seen = set()
                for mapped in mapping:
                    if mapped.get("host") != host:
                        continue
                    candidates = sorted((s for s in sessions if s.get("workspace") == mapped.get("workspace") and s.get("agent_kind") in ("claude", "codex") and s["session_id"] not in gone), key=lambda s: ts(s.get("last_activity")), reverse=True)
                    if not candidates or candidates[0].get("streaming"):
                        continue
                    for s in [candidates[0]] + [s for s in candidates[1:] if s["session_id"] in reg and reg[s["session_id"]].get("status") in (None, "active")]:
                        sid = s["session_id"]
                        if sid in seen:
                            continue
                        seen.add(sid)
                        if not s.get("loaded") or s.get("streaming") or s.get("pending") or not MIN_IDLE_S <= now - ts(s.get("last_activity")) <= KEEPGOING_WINDOW_S:
                            continue
                        messages = transcripts[sid].get("messages", [])
                        action, reason = classify(messages[-8:], now)
                        last_agent = next((m for m in reversed(messages) if m.get("role") not in ("user", "system") and m.get("text")), None)
                        if last_agent and any(p.search(last_agent["text"][-600:]) for p in getattr(triage, "QUOTA_PATTERNS", [])):
                            action, reason = "skip", "quota message"
                        last_nudge = next((i for i in range(len(messages)-1, -1, -1) if "[BAT hourly sweep]" in messages[i].get("text", "")), None)
                        if action == "nudge" and last_nudge is not None and not any(m.get("role") not in ("user", "system") and m.get("text") for m in messages[last_nudge+1:]):
                            action, reason = "skip", "no new output since last nudge"
                        day = datetime.fromtimestamp(now).date()
                        history = [m for m in messages if "[BAT hourly sweep]" in m.get("text", "") and datetime.fromtimestamp(ts(m.get("ts"))).date() == day]
                        if action == "nudge":
                            if len(history) >= MAX_NUDGES_PER_SESSION_DAY:
                                action, reason = "skip", "session daily cap"
                            elif nudges >= MAX_NUDGES_PER_HOST:
                                action, reason = "skip", "host nudge cap"
                            elif len(messages) >= 20:
                                action, reason = "needs_human", "daily history incomplete"
                            else:
                                nudges += 1
                        add(sid, action, reason, next((m.get("text") for m in reversed(messages) if m.get("role") not in ("user", "system")), ""))
                for s in sessions:
                    add(s["session_id"], "cleanup_unknown", "cleanup gate evidence unavailable through allowed reads")
            except BudgetHit as e:
                report.update(status="partial", reason=str(e), truncated=True)
                break
            except MemoryError:
                report.update(status="partial", reason="response_memory_budget", truncated=True)
                break
            except Exception:
                add("", "needs_human", "connector read failed")
                report["status"] = "partial"
    finally:
        await fleet.close()
    report["budget"] = {"read_calls": budget.calls, "decoded_chars": budget.chars}
    report["counts"] = {k: sum(r["action"] == k for rows in report["hosts"].values() for r in rows) for k in ("approve", "escalate", "failover", "nudge", "milestone", "skip", "needs_human", "cleanup_unknown")}
    report["digest"] = "BAT report-only sweep: " + ", ".join(f"{k}={v}" for k, v in report["counts"].items())
    return report

def emit(report):
    # Preserve valid JSON under the executor cap, including all summary counts.
    while len(json.dumps(report, ensure_ascii=True).encode()) > 65000:
        report["truncated"] = True
        groups = list(report.get("hosts", {}).values()) + [report.get("would_actions", []), report.get("needs_human", [])]
        largest = max(groups, key=len)
        if not largest:
            break
        largest.pop()
    print(json.dumps(report, ensure_ascii=True))

def main(now=None):
    try:
        if sys.argv[1:] == ["--print-connector-digest"]:
            print(connector_digest(connector_directory()))
            return 0
        raw = sys.stdin.read(4097)
        if len(raw) > 4096:
            raise ValueError("invalid args")
        args = json.loads(raw)
        hosts = args.get("hosts")
        if not isinstance(hosts, list) or not 1 <= len(hosts) <= 8 or any(not isinstance(h, str) or not re.fullmatch(r"[a-z0-9-]{1,32}", h) for h in hosts) or set(args) - {"hosts", "connector_tree_sha256", "include_excerpts"} or not re.fullmatch(r"[a-f0-9]{64}", args.get("connector_tree_sha256", "")) or not isinstance(args.get("include_excerpts", False), bool):
            raise ValueError("invalid args")
        # Backstop for allocations inside the pinned connector before decoded checks.
        soft, hard = resource.getrlimit(resource.RLIMIT_AS)
        cap = 256 * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (min(soft, cap) if soft != resource.RLIM_INFINITY else cap, hard))
        with tempfile.TemporaryDirectory(prefix="bat-report-") as private:
            os.environ["TMPDIR"] = private
            sys.dont_write_bytecode = True
            # Connector chatter is discarded; exceptions never expose credentials.
            enforce_io(private)
            with contextlib.redirect_stdout(Discard()), contextlib.redirect_stderr(Discard()):
                report = asyncio.run(collect(args, now=now))
        emit(report)
        return 0
    except Refused as e:
        emit({"status": "refused", "reason": str(e)})
        return 0
    except Exception:
        emit({"status": "unavailable", "reason": "invalid arguments or unavailable connector"})
        return 0

if __name__ == "__main__":
    sys.exit(main())
