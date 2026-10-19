#!/usr/bin/python3
"""Reviewed read-only catalog report. No workspace imports or raw CLI output."""
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import re
import selectors
import shutil
import subprocess
import sys
import time

CAP = 64 << 10


class Failure(Exception):
    pass


def run(argv, timeout=15):
    """Bound both pipes in memory; discard raw diagnostics at the report boundary."""
    env = {k: os.environ[k] for k in ("HOME", "PATH", "LANG", "LC_ALL") if k in os.environ}
    env.update({"LANG": "C", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1"})
    # User systemd needs its bus even in the agent's deliberately minimal env.
    env["XDG_RUNTIME_DIR"] = "/run/user/" + str(os.getuid())
    env["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=" + env["XDG_RUNTIME_DIR"] + "/bus"
    try:
        p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, env=env)
    except FileNotFoundError:
        raise Failure("cli_missing") from None
    except OSError:
        raise Failure("cli_unavailable") from None
    output = {p.stdout: bytearray(), p.stderr: bytearray()}
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as sel:
            for pipe in output:
                sel.register(pipe, selectors.EVENT_READ)
            while sel.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise Failure("cli_timeout")
                for key, _ in sel.select(min(remaining, 0.2)):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        sel.unregister(key.fileobj)
                        continue
                    output[key.fileobj].extend(chunk)
                    if len(output[key.fileobj]) > 4 << 20:
                        raise Failure("cli_output_limit")
        p.wait(timeout=max(0.01, deadline - time.monotonic()))
        return p.returncode, output[p.stdout].decode("utf-8", "replace"), output[p.stderr].decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        raise Failure("cli_timeout") from None
    finally:
        if p.poll() is None:
            p.kill()
        p.wait()
        p.stdout.close()
        p.stderr.close()


def cli(name):
    found = shutil.which(name)
    if not found:
        raise Failure(name + "_cli_missing")
    return found


def document(text):
    try:
        return json.loads(text, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, RecursionError):
        raise Failure("invalid_cli_response") from None


def report(status, metrics, findings):
    return {"schema_version": 1, "status": status,
            "summary": "Read-only check " + status, "metrics": metrics, "findings": findings}


def main():
    try:
        if os.geteuid() == 0:
            raise Failure("root_execution_forbidden")
        raw = sys.stdin.buffer.read(4097)
        if len(raw) > 4096:
            raise Failure("invalid_args")
        args = document(raw)
        if not isinstance(args, dict):
            raise Failure("invalid_args")
        result = check(args)
    except Failure as exc:
        result = report("error", {}, [{"reason": str(exc)}])
    except Exception:
        # Never serialize exception text, CLI stderr, identifiers, or credentials.
        result = report("error", {}, [{"reason": "invalid_response_or_config"}])
    encoded = json.dumps(result, separators=(",", ":"), allow_nan=False)
    if len(encoded.encode()) + 1 > CAP:
        encoded = json.dumps(report("error", {}, [{"reason": "output_limit"}]))
    print(encoded)


def check(args):
    if set(args) - {"expected_peers", "resolve", "baseline_listen_digest", "baseline_listen_ports", "mode"}:
        raise Failure("invalid_args")
    expected, resolves = args.get("expected_peers", []), args.get("resolve", ["github.com", "cloudflare.com"])
    pattern = r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?"
    for values, limit in ((expected, 32), (resolves, 8)):
        if not isinstance(values, list) or len(values) > limit or any(not isinstance(v, str) or not re.fullmatch(pattern, v) for v in values):
            raise Failure("invalid_args")
    mode = args.get("mode", "watch")
    baseline = args.get("baseline_listen_digest")
    previous = args.get("baseline_listen_ports")
    if mode not in ("watch", "daily") or (baseline is not None and (not isinstance(baseline, str) or not re.fullmatch(r"[a-f0-9]{64}", baseline))):
        raise Failure("invalid_args")
    if previous is not None and (baseline is None or not isinstance(previous, list) or len(previous) > 256 or any(not isinstance(p, str) or not re.fullmatch(r"[1-9][0-9]{0,4}", p) or int(p) > 65535 for p in previous)):
        raise Failure("invalid_args")
    digest = lambda ports: hashlib.sha256(("".join(str(p) + "\n" for p in sorted(set(ports)))).encode()).hexdigest()
    if previous is not None and digest(map(int, previous)) != baseline:
        raise Failure("baseline_digest_mismatch")
    findings, metrics = [], {"mode": mode}
    def issue(reason, **data):
        findings.append({"reason": reason, **data})
    def read(name, command):
        try:
            return run([cli(name)] + command)
        except Failure as exc:
            issue(str(exc))
            return None
    ts = read("tailscale", ["status", "--json"])
    if ts:
        if ts[0]:
            issue("tailscale_status_failed")
        else:
            try:
                state = document(ts[1])
                peers = list((state.get("Peer") or {}).values())
                if state.get("BackendState") != "Running":
                    issue("tailscale_not_running")
                offline = 0
                for name in expected:
                    matches = [p for p in peers if name in (p.get("HostName", "").lower(), p.get("DNSName", "").lower().rstrip("."))]
                    offline += not any(p.get("Online") is True for p in matches)
                relay = sum(p.get("Online") is True and p.get("Active") is True and bool(p.get("Relay")) and not p.get("CurAddr") and not p.get("PeerRelay") for p in peers)
                metrics.update(peer_count=len(peers), expected_offline_count=offline, derp_only_count=relay)
                if offline:
                    issue("expected_peers_offline", count=offline)
                if relay:
                    issue("derp_only_peers", count=relay)
                if state.get("Health"):
                    issue("tailscale_health_warning")
            except (Failure, AttributeError, TypeError):
                issue("invalid_tailscale_response")
    routes = read("ip", ["-json", "route", "show", "default"])
    if routes:
        if routes[0]:
            issue("default_route_check_failed")
        else:
            try:
                value = document(routes[1])
                if not isinstance(value, list):
                    raise Failure("invalid_route_response")
                metrics["default_route_count"] = len(value)
                if not value:
                    issue("default_route_missing")
            except Failure:
                issue("invalid_route_response")
    failures = 0
    for index, name in enumerate(resolves):
        resolved = read("getent", ["hosts", name])
        if not resolved or resolved[0] or not resolved[1].strip():
            failures += 1
            issue("dns_resolution_failed", resolve_index=index)
    metrics["dns_failure_count"] = failures
    service = read("systemctl", ["is-active", "cloudflared.service"])
    if service:
        metrics["cloudflared_active"] = service[0] == 0 and service[1].strip() == "active"
        if not metrics["cloudflared_active"]:
            issue("cloudflared_inactive")
    listeners = read("ss", ["-H", "-ltn"])
    if listeners:
        if listeners[0]:
            issue("listen_check_failed")
        else:
            ports = set()
            invalid = False
            for line in listeners[1].splitlines():
                fields = line.split()
                if len(fields) < 5 or fields[0] != "LISTEN":
                    invalid = True
                    break
                address, sep, port = fields[3].rpartition(":")
                if not sep or not port.isdigit() or not 1 <= int(port) <= 65535:
                    invalid = True
                    break
                # Loopback listeners are deliberately excluded from external exposure.
                if address not in ("[::1]", "::1") and not address.startswith("127."):
                    ports.add(int(port))
            if invalid:
                issue("invalid_listen_response")
            else:
                current = digest(ports)
                metrics.update(listen_count=len(ports), listen_digest=current)
                if baseline is not None and baseline != current:
                    issue("listen_ports_changed")
                    if previous is not None:
                        old = set(map(int, previous))
                        metrics.update(added_ports=sorted(ports - old), removed_ports=sorted(old - ports))
                    else:
                        # A hash cannot reveal the old set. Never invent a diff.
                        issue("listen_diff_unavailable")
    # The former jobs also queried credentialed devices and Cloudflare analytics.
    # This entry never reads their secret files or invokes those workspace scripts.
    metrics["coverage_gaps"] = ["router_device_checks", "wan_performance_and_events", "cloudflare_api_analytics", "historical_security_correlation"]
    if mode == "daily":
        issue("security_coverage_incomplete")
    unavailable = any(f["reason"].endswith(("_missing", "_failed", "_timeout", "_limit", "_unavailable")) and f["reason"] not in ("default_route_missing", "listen_diff_unavailable") or f["reason"].startswith("invalid_") for f in findings)
    return report("error" if unavailable else "warn" if findings else "ok", metrics, findings)


if __name__ == "__main__":
    main()
