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


def version(value):
    if not isinstance(value, str) or not re.fullmatch(r"v?(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})", value):
        raise Failure("invalid_version")
    return tuple(map(int, value.lstrip("v").split(".")))


def installed_version():
    # Same source as bat-server-auto-update: BAT_INSTALL_DIR/VERSION, then
    # the versioned symlink target. Read only this variable from the unit env.
    systemctl = cli("systemctl")
    code, out, _ = run([systemctl, "--user", "show", "bat-server-auto-update.service", "--property=Environment", "--value"])
    if code:
        raise Failure("bat_updater_config_missing")
    import shlex
    paths = [s.split("=", 1)[1] for s in shlex.split(out) if s.startswith("BAT_INSTALL_DIR=")]
    if len(paths) != 1 or not paths[0].startswith("/"):
        raise Failure("bat_install_dir_missing")
    install = Path(paths[0])
    source = install / "VERSION"
    if source.is_file():
        with source.open() as stream:
            value = stream.read(128).strip()
        version(value)
        return value
    if install.is_symlink():
        target = install.resolve(strict=True).name
        if target.startswith("bat-server-"):
            value = target[len("bat-server-"):]
            version(value)
            return value
    raise Failure("installed_version_missing")


def check(args):
    if args:
        raise Failure("invalid_args")
    installed = installed_version()
    # curl's -q disables ~/.curlrc; no token, gh config, downloads, or writes.
    code, out, _ = run([cli("curl"), "-q", "--silent", "--show-error", "--proto", "=https",
                        "--connect-timeout", "5", "--max-time", "20",
                        "--header", "Accept: application/vnd.github+json",
                        "--write-out", "\n%{http_code}",
                        "https://api.github.com/repos/tony1223/better-agent-terminal/releases/latest"], timeout=25)
    if code:
        raise Failure("github_request_failed")
    body, _, http = out.rstrip("\r\n").rpartition("\n")
    metrics = {"installed_version": installed, "latest_stable": None,
               "newer_available": False, "published_at": None}
    if http in ("403", "429"):
        return report("warn", metrics, [{"reason": "github_rate_limited_or_forbidden"}])
    if http != "200":
        raise Failure("github_http_error")
    release = document(body)
    if release.get("draft") is not False or release.get("prerelease") is not False:
        raise Failure("stable_release_unavailable")
    latest = release.get("tag_name")
    newer = version(latest) > version(installed)
    published = release.get("published_at")
    if not isinstance(published, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", published):
        raise Failure("invalid_release_date")
    dt.datetime.strptime(published, "%Y-%m-%dT%H:%M:%SZ")
    metrics.update(latest_stable=latest, newer_available=newer, published_at=published)
    return report("warn" if newer else "ok", metrics, [{"reason": "new_stable_available"}] if newer else [])


if __name__ == "__main__":
    main()
