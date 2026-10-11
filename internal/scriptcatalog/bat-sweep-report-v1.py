#!/usr/bin/python3
"""Read-only BAT sweep. JSON arguments arrive on stdin, never as commands."""
import asyncio
import contextlib
import contextvars
import functools
import importlib
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
            if writing and (not isinstance(path, (str, bytes, os.PathLike)) or not Path(os.fsdecode(path)).resolve().is_relative_to(root)):
                raise PermissionError("report-only write boundary")
        if event in ("os.remove", "os.rmdir", "os.mkdir", "os.rename", "os.chmod", "os.chown", "os.truncate", "os.link", "os.symlink"):
            paths = args[:2] if event in ("os.rename", "os.link", "os.symlink") else args[:1]
            if any(not isinstance(p, (str, bytes, os.PathLike)) or not Path(os.fsdecode(p)).resolve().is_relative_to(root) for p in paths):
                raise PermissionError("report-only state boundary")
        if event in ("subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.fork"):
            raise PermissionError("report-only process boundary")
        if event in ("socket.connect", "socket.getaddrinfo", "socket.sendto") and not READ_CALL.get():
            raise PermissionError("network outside connector read")
    sys.addaudithook(audit)

class ReadOnly:
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

SECRET = re.compile(r'(?i)(bearer\s+[^\s"\']+|(?:token|password|secret|api[_-]?key)\s*[:=]\s*[^\s"\']+|(?:sk-|gh[pousr]_|github_pat_)[a-z0-9_-]+|eyJ[a-z0-9_-]+\.[a-z0-9_-]+\.[a-z0-9_-]+|[a-z0-9_+/=-]{32,})')

def excerpt(value):
    return SECRET.sub("[REDACTED]", re.sub(r"\s+", " ", str(value or ""))).strip()[:120]

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

async def collect(args):
    try:
        config_api = ReadOnly(importlib.import_module("bat_agent_connector.config"), ("load_config",))
        fleet_api = ReadOnly(importlib.import_module("bat_agent_connector.fleet"), ("Fleet",))
        service = ReadOnly(importlib.import_module("bat_agent_connector.service"), ("sessions_list", "session_read"))
        registry = ReadOnly(importlib.import_module("bat_agent_connector.registry"), ("list_entries",))
        triage = ReadOnly(importlib.import_module("bat_agent_connector.triage"), ("sessions_triage", "QUOTA_PATTERNS"))
        config = config_api.load_config()
        if config is None:
            raise ValueError("missing config")
    except Exception:
        return {"status": "unavailable", "reason": "connector package or configuration unavailable"}
    import tomllib
    base = (Path.home() / ".config/bat-agent-connector").resolve()
    channels = Path(args.get("channels_file") or base / "discord-channels.toml").expanduser().resolve()
    if not channels.is_relative_to(base):
        return {"status": "unavailable", "reason": "channels_file must be inside agent connector config directory"}
    try:
        mapping = tomllib.loads(channels.read_text()).get("channels", [])
    except (OSError, ValueError):
        return {"status": "unavailable", "reason": "channel configuration unavailable"}
    now = time.time()
    report = {"schema_version": 1, "status": "ok", "generated_at": datetime.now(timezone.utc).isoformat(), "hosts": {}, "would_actions": [], "needs_human": [], "limitations": ["Cleanup gates and Jev require forbidden calls; reported as unknown", "Daily nudge history inferred only from available transcript; no persistent state"]}
    fleet = fleet_api.Fleet(config, actor="bat-sweep-report")
    try:
        for host in args["hosts"]:
            rows = report["hosts"][host] = []
            def add(sid, action, reason, text=""):
                item = {"host": host, "session_id": excerpt(sid), "action": action, "reason": reason, "excerpt": excerpt(text)}
                rows.append(item)
                if action in ("approve", "failover", "nudge"):
                    report["would_actions"].append(item)
                if action in ("escalate", "needs_human", "milestone", "cleanup_unknown"):
                    report["needs_human"].append(item)
                return item
            try:
                sessions = (await service.sessions_list(fleet, host, limit=500, check_pending="all"))["sessions"][:500]
                entries = registry.list_entries(host)
                reg = {e["session_id"]: e for e in entries}
                gone = {e["session_id"] for e in entries if e.get("status") not in (None, "active") or e.get("superseded_by")}
                gone.update(e["failover_of"] for e in entries if e.get("failover_of"))
                waiting = await triage.sessions_triage(fleet, host, None, states=["waiting_permission", "waiting_question"], use_jev="never", include_unloaded=False)
                for row in waiting.get("sessions", [])[:500]:
                    sid = row["session_id"]
                    pending = (await service.session_read(fleet, host, sid, last_n=1)).get("pending") or {}
                    preview = pending.get("input_preview", "")
                    if pending.get("kind") == "ask_user":
                        add(sid, "needs_human", "ask-user question", "; ".join(q.get("question", "") for q in pending.get("questions", [])))
                    elif pending.get("kind") == "permission" and pending.get("toolUseId"):
                        unsafe = bool(DESTRUCTIVE_CMD.search(preview))
                        item = add(sid, "escalate" if unsafe else "approve", "destructive/external command" if unsafe else "reference safe-prompt rule", preview)
                        item["tool_use_id"] = excerpt(pending["toolUseId"])
                quota = await triage.sessions_triage(fleet, host, None, agent="claude", states=["quota_exhausted"], use_jev="never", include_unloaded=False)
                failovers = 0
                for row in quota.get("sessions", [])[:500]:
                    sid = row["session_id"]
                    if sid in gone:
                        continue
                    msgs = (await service.session_read(fleet, host, sid, last_n=1)).get("messages", [])
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
                        messages = (await service.session_read(fleet, host, sid, last_n=500, max_message_chars=3000)).get("messages", [])
                        action, reason = classify(messages[-8:], now)
                        last_agent = next((m for m in reversed(messages) if m.get("role") not in ("user", "system") and m.get("text")), None)
                        if last_agent and any(p.search(last_agent["text"][-600:]) for p in getattr(triage, "QUOTA_PATTERNS", [])):
                            action, reason = "skip", "quota message"
                        last_nudge = next((i for i in range(len(messages)-1, -1, -1) if "[BAT hourly sweep]" in messages[i].get("text", "")), None)
                        if action == "nudge" and last_nudge is not None and not any(m.get("role") not in ("user", "system") and m.get("text") for m in messages[last_nudge+1:]):
                            action, reason = "skip", "no new output since last nudge"
                        day = datetime.now().astimezone().date()
                        history = [m for m in messages if "[BAT hourly sweep]" in m.get("text", "") and datetime.fromtimestamp(ts(m.get("ts"))).date() == day]
                        if action == "nudge":
                            if len(history) >= MAX_NUDGES_PER_SESSION_DAY:
                                action, reason = "skip", "session daily cap"
                            elif nudges >= MAX_NUDGES_PER_HOST:
                                action, reason = "skip", "host nudge cap"
                            elif len(messages) >= 500:
                                action, reason = "needs_human", "daily history incomplete"
                            else:
                                nudges += 1
                        add(sid, action, reason, next((m.get("text") for m in reversed(messages) if m.get("role") not in ("user", "system")), ""))
                for s in sessions:
                    add(s["session_id"], "cleanup_unknown", "cleanup gate evidence unavailable through allowed reads")
            except Exception:
                add("", "needs_human", "connector read failed")
                report["status"] = "partial"
    finally:
        await fleet.close()
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

def main():
    try:
        args = json.load(sys.stdin)
        hosts = args.get("hosts")
        if not isinstance(hosts, list) or not 1 <= len(hosts) <= 8 or any(not isinstance(h, str) or not re.fullmatch(r"[a-z0-9-]{1,32}", h) for h in hosts) or set(args) - {"hosts", "channels_file"}:
            raise ValueError("invalid args")
        with tempfile.TemporaryDirectory(prefix="bat-report-") as private:
            os.environ["TMPDIR"] = private
            sys.dont_write_bytecode = True
            # Connector chatter is discarded; exceptions never expose credentials.
            enforce_io(private)
            with contextlib.redirect_stdout(Discard()), contextlib.redirect_stderr(Discard()):
                report = asyncio.run(collect(args))
        emit(report)
        return 0
    except Exception:
        emit({"status": "unavailable", "reason": "invalid arguments or unavailable connector"})
        return 0

if __name__ == "__main__":
    sys.exit(main())
