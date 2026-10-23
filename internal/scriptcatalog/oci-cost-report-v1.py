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


from decimal import Decimal, InvalidOperation


def oci_call(binary, profile, command):
    code, out, err = run([binary, "--profile", profile, "--cli-rc-file", "/dev/null",
                          "--connection-timeout", "5", "--read-timeout", "20",
                          "--max-retries", "0"] + command, timeout=40)
    if code:
        for needle, reason in (("NotAuthenticated", "oci_auth_failed"),
                               ("NotAuthorizedOrNotFound", "oci_permission_denied"),
                               ("TooManyRequests", "oci_rate_limited"),
                               ("Could not find profile", "profile_missing"),
                               ("ConfigFileNotFound", "profile_missing"),
                               ("InvalidConfig", "oci_config_invalid")):
            if needle.lower() in err.lower():
                raise Failure(reason)
        raise Failure("oci_request_failed")
    return out


def check(args, now=None):
    if set(args) - {"profile", "warn_usd", "urgent_usd"}:
        raise Failure("invalid_args")
    profile = args.get("profile")
    if not isinstance(profile, str) or not re.fullmatch(r"[a-z0-9-]{1,32}", profile):
        raise Failure("invalid_args")
    warn, urgent = args.get("warn_usd", 0), args.get("urgent_usd", 5)
    if any(type(n) not in (int, float) or not math.isfinite(n) or not 0 <= n <= 1000000 for n in (warn, urgent)) or urgent < warn:
        raise Failure("invalid_thresholds")
    binary = shutil.which("oci")
    if not binary:
        candidate = Path.home() / ".local/bin/oci"
        if candidate.is_file() and os.access(candidate, os.X_OK):
            binary = str(candidate)
    if not binary:
        raise Failure("oci_cli_missing")
    # Inspect section headers only. Authentication and key access belong to OCI CLI.
    config = Path.home() / ".oci/config"
    try:
        if config.stat().st_size > 65536:
            raise Failure("oci_config_invalid")
        with config.open() as stream:
            profiles = {line.strip()[1:-1] for line in stream if re.fullmatch(r"\[[^\]\r\n]+\]", line.strip())}
    except OSError:
        raise Failure("profile_missing") from None
    if profile not in profiles:
        raise Failure("profile_missing")
    now = now or dt.datetime.now(dt.timezone.utc)
    start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    end = (now + dt.timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    fmt = lambda t: t.strftime("%Y-%m-%dT%H:%M:%SZ")
    # This IAM command defaults to the selected profile's root compartment.
    # Keep the identifier in memory and never include it in evidence.
    tenant = oci_call(binary, profile, ["iam", "availability-domain", "list", "--query", 'data[0]."compartment-id"', "--raw-output"]).strip()
    if not re.fullmatch(r"ocid1\.tenancy\.[a-z0-9.-]{1,200}", tenant):
        raise Failure("oci_tenancy_unavailable")
    rows, page, seen = [], None, set()
    for _ in range(4):
        command = ["usage-api", "usage-summary", "request-summarized-usages",
                   "--tenant-id", tenant, "--granularity", "MONTHLY", "--query-type", "COST",
                   "--time-usage-started", fmt(start), "--time-usage-ended", fmt(end)]
        if page is not None:
            command += ["--page", page]
        usage = document(oci_call(binary, profile, command))
        batch = usage["data"]["items"]
        if not isinstance(batch, list):
            raise Failure("invalid_cli_response")
        rows.extend(batch)
        page = usage.get("opc-next-page")
        if not page:
            break
        if not isinstance(page, str) or len(page) > 2048 or page in seen:
            raise Failure("oci_usage_pagination_invalid")
        seen.add(page)
    else:
        raise Failure("oci_usage_page_limit")
    total = Decimal(0)
    for row in rows:
        if row.get("currency") != "USD":
            raise Failure("unexpected_currency")
        try:
            amount = Decimal(str(row["computed-amount"]))
        except (KeyError, InvalidOperation):
            raise Failure("invalid_cost_amount") from None
        if not amount.is_finite() or abs(amount) > 1000000000:
            raise Failure("invalid_cost_amount")
        total += amount
    # Count root plus accessible active child compartments in the profile region.
    child_output = oci_call(binary, profile, ["iam", "compartment", "list", "--all",
                        "--compartment-id-in-subtree", "true", "--access-level", "ACCESSIBLE",
                        "--lifecycle-state", "ACTIVE", "--query", "data[].id || `[]`"])
    # OCI CLI emits no stdout for successful empty list responses (render(data=[])).
    children = document(child_output) if child_output.strip() else []
    if not isinstance(children, list) or len(children) > 32 or any(not isinstance(c, str) or not re.fullmatch(r"ocid1\.compartment\.[a-z0-9.-]{1,200}", c) for c in children):
        raise Failure("oci_compartment_scope_limit")
    from concurrent.futures import ThreadPoolExecutor
    def count(compartment):
        count_output = oci_call(binary, profile, ["compute", "instance", "list", "--all",
                         "--compartment-id", compartment, "--lifecycle-state", "RUNNING",
                         "--query", "length(data || `[]`)"])
        value = document(count_output) if count_output.strip() else 0
        if type(value) is not int or not 0 <= value <= 1000000:
            raise Failure("invalid_instance_count")
        return value
    with ThreadPoolExecutor(max_workers=8) as pool:
        instances = sum(pool.map(count, dict.fromkeys([tenant] + children)))
    status = "urgent" if total > Decimal(str(urgent)) else "warn" if total > Decimal(str(warn)) else "ok"
    findings = [] if status == "ok" else [{"reason": "cost_above_" + status + "_threshold"}]
    return report(status, {"mtd_usd": float(total), "currency": "USD", "running_instances": instances,
                  "period_start": fmt(start), "period_end": fmt(end)}, findings)


if __name__ == "__main__":
    main()
