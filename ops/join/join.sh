#!/usr/bin/env bash
# Public bootstrap. No credentials are embedded in this file.
set +x
set -Eeuo pipefail
umask 077
hub='@@CLAWCTL_PUBLIC_URL@@'
agent_user=${SUDO_USER:-}
root_prefix=''
while (($#)); do
  case "$1" in
    --hub) hub=${2:?Missing Hub URL}; shift 2 ;;
    --user) agent_user=${2:?Missing user}; shift 2 ;;
    --root-prefix) root_prefix=${2:?Missing root prefix}; shift 2 ;;
    *) echo 'Usage: join.sh [--hub https://hub.example.com] [--user NAME]' >&2; exit 2 ;;
  esac
done
fail() {
  if declare -F join_failed >/dev/null; then
    printf '%s\n' "$1" >>"$log_file"
    join_failed "${2:-1}"
  fi
  echo "$1" >&2
  exit "${2:-1}"
}
[[ $(id -u) == 0 ]] || fail 'Run with sudo or as root with --user NAME.'
[[ $(uname -s) == Linux ]] || fail 'Joining requires Linux.'
[[ -n $agent_user && $agent_user != root && $agent_user =~ ^[a-zA-Z_][a-zA-Z0-9_.-]*\$?$ ]] || fail 'Choose a non-root agent account with --user NAME.'
agent_uid=$(id -u "$agent_user") || fail 'The agent account does not exist.'
[[ $agent_uid =~ ^[1-9][0-9]*$ ]] || fail 'The agent account must not be root.'
if ! command -v systemctl >/dev/null || [[ ! -d $root_prefix/run/systemd/system ]]; then fail 'Joining requires systemd.'; fi
command -v curl >/dev/null || fail 'Install curl first.'
command -v shred >/dev/null || fail 'Install coreutils first.'
case $(uname -m) in x86_64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) fail 'Supported architectures are amd64 and arm64.' ;; esac
ID=unknown VERSION_ID=unknown
if [[ -f $root_prefix/etc/os-release ]]; then
  # shellcheck disable=SC1091
  . "$root_prefix/etc/os-release"
fi
case "$ID:$VERSION_ID" in ubuntu:22.04|ubuntu:24.04|ubuntu:26.04|ol:9|ol:9.*) ;; *) echo 'Warning: this distribution has not been validated for joining.' >&2 ;; esac
install_package() {
  if command -v apt-get >/dev/null; then
    apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y "$1"
  elif command -v dnf >/dev/null; then
    dnf install -y "$1"
  else
    fail 'Install the required package with apt or dnf first.'
  fi
}
if ! command -v python3 >/dev/null; then install_package python3; fi
python3 - "$hub" <<'PY' || exit 2
import sys, urllib.parse
u=urllib.parse.urlsplit(sys.argv[1])
if u.scheme!='https' or not u.hostname or u.username or u.password or u.query or u.fragment or u.path not in ('','/') or any(c.isspace() for c in sys.argv[1]):
    sys.exit('Provide a public HTTPS Hub URL with --hub.')
PY
hub=${hub%/}
work=$(mktemp -d)
chmod 0700 "$work"
cleanup() {
  find "$work" -type f -exec shred -u -- {} + 2>/dev/null || true
  rm -rf -- "$work"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
log_path=/var/log/clawctl-join.log
log_file=$root_prefix$log_path
mkdir -p -- "${log_file%/*}"
[[ ! -L $log_file ]] || fail 'Join log must not be a symlink.'
: >>"$log_file"
chown 0:0 "$log_file"
chmod 0600 "$log_file"
step='starting join'
step_line=1
begin_step() {
  step=$1
  printf '\n=== %s ===\n' "$step" >>"$log_file"
  step_line=$(wc -l <"$log_file")
  step_line=$((step_line + 1))
}
join_failed() {
  local rc=${1:-$?}
  trap - ERR
  printf 'Joining failed during %s. Details: %s\n' "$step" "$log_path" >&2
  tail -n +"$step_line" "$log_file" | tail -n 20 >&2
  exit "$rc"
}
trap join_failed ERR
# Redact downstream output before it reaches the persistent log or terminal.
# Credentials stay in private files and are never passed to the filter on argv.
logged() {
  "$@" 2>&1 | python3 -c '
import json,pathlib,sys
p=pathlib.Path(sys.argv[1])
secrets=[]
for name in ("token", "ts-key"):
    f=p/name
    if f.exists(): secrets.append(f.read_text())
for name in ("poll.json", "response.json"):
    try:
        d=json.loads((p/name).read_text())
        secrets.extend(d.get(k, "") for k in ("device_secret", "enroll_token"))
        secrets.append((d.get("tailscale") or {}).get("auth_key", ""))
    except (OSError, ValueError): pass
for line in sys.stdin:
    for secret in secrets:
        if secret: line=line.replace(secret, "[REDACTED]")
    sys.stdout.write(line)
' "$work" >>"$log_file"
}
begin_step 'starting join'
# All credential-bearing requests use files, never argv or environment values.
python3 - "$(hostname)" "$arch" "$agent_user" >"$work/start.json" <<'PY'
import json,sys
json.dump(dict(hostname=sys.argv[1],os='linux',arch=sys.argv[2],user=sys.argv[3]),sys.stdout)
PY
request() {
  curl --silent --show-error --connect-timeout 10 --max-time 30 --proto '=https' \
    -H 'Content-Type: application/json' --data-binary "@$work/$1" \
    -o "$work/response.json" -w '%{http_code}' "$hub/v1/join/$2" 2>>"$log_file"
}
status=$(request start.json start)
[[ $status == 200 ]] || fail 'The Hub could not start this join. Try again shortly.'
logged python3 - "$work" <<'PY'
import json,pathlib,re,sys
p=pathlib.Path(sys.argv[1]); d=json.loads((p/'response.json').read_text())
assert re.fullmatch('[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}', d['join_code'])
assert re.fullmatch('[A-Za-z0-9_-]{43}',d['device_secret'])
assert isinstance(d['poll_seconds'],int) and 1<=d['poll_seconds']<=60
(p/'poll.json').write_text(json.dumps(dict(device_secret=d['device_secret'])))
(p/'headers').write_text('Authorization: Bearer '+d['device_secret']+'\n')
(p/'code').write_text(d['join_code']); (p/'interval').write_text(str(d['poll_seconds']))
PY
printf 'Join code: %s\nOpen %s/machines/join and approve this code.\n' "$(<"$work/code")" "$hub"
begin_step 'downloading agent bundle'
# Fetch while pending: redemption ends the device secret's download authority.
# The approved payload supplies the authoritative SHA-256 before extraction.
logged curl --silent --show-error --fail --connect-timeout 10 --max-time 120 --proto '=https' \
  -H "@$work/headers" "$hub/v1/join/bundle/$arch" -o "$work/bundle.tar.gz" || {
  echo "Could not download the pending join bundle for linux/$arch. Check that the Hub publishes this architecture's bundle." >>"$log_file"
  false
}
begin_step 'waiting for approval'
interval=$(<"$work/interval")
deadline=$((SECONDS + 900))
approval_notice=0
while ((SECONDS < deadline)); do
  status=$(request poll.json poll)
  case "$status" in
    200) break ;;
    202) sleep "$interval" ;;
    410)
      state=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("state","expired"))' "$work/response.json")
      case "$state" in rejected) fail 'Join rejected in the Hub.' 3 ;; approval_expired) if [[ $approval_notice == 0 ]]; then echo 'Approval expired. Ask the administrator to approve this code again.' >&2; approval_notice=1; fi; sleep "$interval"; continue ;; *) fail 'Join expired. Run the join command again.' 4 ;; esac ;;
    *) fail 'The Hub could not check this join. Run the join command again.' ;;
  esac
done
[[ $status == 200 ]] || fail 'Join expired. Run the join command again.' 4
begin_step 'verifying approved bundle'
logged python3 - "$work" "$hub" <<'PY'
import hashlib,json,pathlib,re,sys
p=pathlib.Path(sys.argv[1]); d=json.loads((p/'response.json').read_text())
assert d['hub_url']==sys.argv[2] and d['state']=='approved'
assert re.fullmatch('[a-f0-9]{64}',d['bundle']['sha256'])
assert hashlib.sha256((p/'bundle.tar.gz').read_bytes()).hexdigest()==d['bundle']['sha256'], 'Agent bundle checksum does not match'
for name,value in [('token',d['enroll_token']),('name',d['display_name'])]:
    assert isinstance(value,str) and value and len(value)<=4096 and '\n' not in value
    (p/name).write_text(value)
assert type(d.get('monitor_only',False)) is bool
(p/'monitor-only').write_text('true' if d.get('monitor_only',False) else 'false')
if d.get('tailscale'):
    t=d['tailscale']; assert all(re.fullmatch('tag:[a-z0-9-]{1,63}',x) for x in t['tags'])
    assert re.fullmatch('[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}',t['hostname'])
    assert isinstance(t['auth_key'],str) and 0<len(t['auth_key'])<=4096
    (p/'ts-key').write_text(t['auth_key']);(p/'ts-tags').write_text(','.join(t['tags']));(p/'ts-host').write_text(t['hostname'])
PY
begin_step 'configuring SSH'
if ! command -v sshd >/dev/null && [[ ! -x $root_prefix/usr/sbin/sshd ]]; then logged install_package openssh-server; fi
if [[ $ID == ubuntu ]]; then ssh_service=ssh; else ssh_service=sshd; fi
logged systemctl enable --now "$ssh_service"
begin_step 'configuring Tailscale'
if [[ -f $work/ts-key ]]; then
  if ! command -v tailscale >/dev/null; then
    logged curl -fsSL --proto '=https' https://tailscale.com/install.sh -o "$work/tailscale-install.sh"
    logged bash "$work/tailscale-install.sh"
  fi
  logged systemctl enable --now tailscaled.service
  logged tailscale up --auth-key="file:$work/ts-key" --hostname="$(<"$work/ts-host")" \
    --advertise-tags="$(<"$work/ts-tags")" --ssh=false --timeout=60s
  shred -u -- "$work/ts-key"
fi
begin_step 'extracting agent bundle'
mkdir "$work/bundle"
# Reject traversal and links before extracting an approved archive as root.
logged python3 - "$work/bundle.tar.gz" "$work/bundle" <<'PY'
import pathlib,sys,tarfile
with tarfile.open(sys.argv[1]) as t:
    for m in t.getmembers():
        p=pathlib.PurePosixPath(m.name)
        assert not p.is_absolute() and '..' not in p.parts and (m.isfile() or m.isdir())
    # Members were validated above; works on Python 3.9 (Oracle Linux 9).
    t.extractall(sys.argv[2])
PY
# Keep the bootstrap and secrets root-owned; the installer drops privilege for
# account files and enrollment while performing system setup as root.
begin_step 'installing agent'
logged bash "$work/bundle/install-agent.sh" --user "$agent_user" --hub "$hub" \
  --token-file "$work/token" --no-tailscale
if [[ $(<"$work/monitor-only") != true && -f $work/bundle/fleet-apply/install.sh ]]; then
  begin_step 'installing fleet applier'
  logged bash "$work/bundle/fleet-apply/install.sh" --agent-user "$agent_user"
fi
printf 'Joined as %s. Progress is on %s/readiness\n' "$(<"$work/name")" "$hub"
