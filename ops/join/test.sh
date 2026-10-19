#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
TEST_DIR=$(mktemp -d)
trap 'rm -rf -- "$TEST_DIR"' EXIT
mkdir -p "$TEST_DIR/bin" "$TEST_DIR/root/run/systemd/system" "$TEST_DIR/root/etc" "$TEST_DIR/stage/fleet-apply" "$TEST_DIR/tmp"
printf 'ID=ubuntu\nVERSION_ID=24.04\n' >"$TEST_DIR/root/etc/os-release"
export JOIN_TEST_DIR="$TEST_DIR"
cat >"$TEST_DIR/stage/install-agent.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ $1 == --user && $2 == operator && $3 == --hub && $5 == --token-file && $7 == --no-tailscale ]]
[[ $(stat -c '%a' "$6") == 600 ]]
# Even a downstream installer printing a credential must stay out of output.
cat "$6" "${6%/*}/poll.json"
if [[ $JOIN_TEST_MODE == installer-failure ]]; then
  for ((i=1; i<=25; i++)); do echo "installer diagnostic $i"; done
  exit 23
fi
echo installed >"$JOIN_TEST_DIR/installed"
SH
cat >"$TEST_DIR/stage/fleet-apply/install.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ $# == 2 && $1 == --agent-user && $2 == operator ]]
echo applied >"$JOIN_TEST_DIR/applied"
SH
tar -czf "$TEST_DIR/bundle.tar.gz" -C "$TEST_DIR/stage" install-agent.sh fleet-apply
cat >"$TEST_DIR/bin/stub" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
for arg in "$@"; do
  case "$arg" in *AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA*|*fixture-enrollment-secret*|*fixture-tailscale-secret*) echo 'Credential leaked on argv' >&2; exit 91 ;; esac
done
printf '%s ' "${0##*/}" "$@" >>"$JOIN_TEST_DIR/argv"
printf '\n' >>"$JOIN_TEST_DIR/argv"
case "${0##*/}" in
  uname) if [[ $1 == -s ]]; then echo Linux; else echo x86_64; fi ;;
  id) if [[ $# == 1 ]]; then echo 0; else echo 1001; fi ;;
  hostname) echo host-b ;;
  systemctl|sshd|chown|sleep) : ;;
  sudo) shift 3; "$@" ;;
  tailscale)
    [[ $2 == --auth-key=file:* ]]
    keyfile=${2#--auth-key=file:}
    [[ $(stat -c '%a' "$keyfile") == 600 ]]
    [[ $(cat "$keyfile") == fixture-tailscale-secret ]]
    echo fixture-tailscale-secret # Must also be suppressed.
    ;;
  curl)
    output='' url=''
    while (($#)); do
      case "$1" in
        -o) output=$2;shift 2 ;;
        -H) if [[ $2 == @* ]]; then [[ $(stat -c '%a' "${2#@}") == 600 ]]; fi;shift 2 ;;
        --data-binary) [[ $(stat -c '%a' "${2#@}") == 600 ]];shift 2 ;;
        https://*) url=$1;shift ;;
        *) shift ;;
      esac
    done
    case "$url" in
      */start) printf '{"join_code":"ABCD-2345","device_secret":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","poll_seconds":1}' >"$output";printf 200 ;;
      */bundle/*) [[ $JOIN_TEST_MODE != download-failure ]] || exit 22;cp "$JOIN_TEST_DIR/bundle.tar.gz" "$output" ;;
      */poll)
        case "$JOIN_TEST_MODE" in
          rejected|expired) printf '{"state":"%s"}' "$JOIN_TEST_MODE" >"$output";printf 410 ;;
          *) python3 - "$JOIN_TEST_DIR/bundle.tar.gz" >"$output" <<'PY'
import hashlib,json,sys
d=dict(state='approved',display_name='Host-B',hub_url='https://hub.example.com',enroll_token='fixture-enrollment-secret',bundle=dict(sha256=hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest()),tailscale=dict(auth_key='fixture-tailscale-secret',tags=['tag:fleet'],hostname='host-b'))
import os
if os.environ['JOIN_TEST_MODE']=='monitor-only': d['monitor_only']=True
if os.environ['JOIN_TEST_MODE']=='no-tailscale': d.pop('tailscale')
if os.environ['JOIN_TEST_MODE']=='checksum-failure': d['bundle']['sha256']='0'*64
json.dump(d,sys.stdout)
PY
          printf 200 ;;
        esac ;;
      *) exit 90 ;;
    esac ;;
  *) exit 92 ;;
esac
SH
chmod +x "$TEST_DIR/bin/stub"
for tool in uname id hostname systemctl sshd chown sleep sudo tailscale curl; do ln -s stub "$TEST_DIR/bin/$tool"; done
export PATH="$TEST_DIR/bin:$PATH"
runs=0
for mode in approved monitor-only no-tailscale no-fleet rejected expired download-failure checksum-failure installer-failure; do
  rm -f "$TEST_DIR/installed" "$TEST_DIR/applied"
  if [[ $mode == no-fleet ]]; then
    tar -czf "$TEST_DIR/bundle.tar.gz" -C "$TEST_DIR/stage" install-agent.sh
  else
    tar -czf "$TEST_DIR/bundle.tar.gz" -C "$TEST_DIR/stage" install-agent.sh fleet-apply
  fi
  runs=$((runs + 1))
  if [[ -f $TEST_DIR/root/var/log/clawctl-join.log ]]; then
    chmod 0644 "$TEST_DIR/root/var/log/clawctl-join.log"
  fi
  export JOIN_TEST_MODE=$mode
  rc=0
  TMPDIR="$TEST_DIR/tmp" SUDO_USER='' bash "$ROOT/ops/join/join.sh" --user operator --hub https://hub.example.com --root-prefix "$TEST_DIR/root" >"$TEST_DIR/output" 2>&1 || rc=$?
  case "$mode" in
    approved|no-tailscale) if [[ $rc != 0 ]]; then cat "$TEST_DIR/output"; fi; [[ $rc == 0 && -f $TEST_DIR/installed && -f $TEST_DIR/applied ]]; grep -q 'Joined as Host-B' "$TEST_DIR/output" ;;
    monitor-only) [[ $rc == 0 && -f $TEST_DIR/installed && ! -f $TEST_DIR/applied ]] ;;
    no-fleet) [[ $rc == 0 && -f $TEST_DIR/installed && ! -f $TEST_DIR/applied ]] ;;
    rejected) [[ $rc == 3 ]];grep -q 'Join rejected' "$TEST_DIR/output" ;;
    expired) [[ $rc == 4 ]];grep -q 'Join expired' "$TEST_DIR/output" ;;
    download-failure|checksum-failure|installer-failure) [[ $rc != 0 && ! -f $TEST_DIR/installed && ! -f $TEST_DIR/applied ]] ;;
  esac
  if grep -Eq 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|fixture-enrollment-secret|fixture-tailscale-secret' "$TEST_DIR/output" "$TEST_DIR/argv" "$TEST_DIR/root/var/log/clawctl-join.log"; then echo "Credential leaked" >&2; exit 1; fi
  [[ $(grep -c '^=== starting join ===$' "$TEST_DIR/root/var/log/clawctl-join.log") == "$runs" ]]
  [[ $(stat -c '%a' "$TEST_DIR/root/var/log/clawctl-join.log") == 600 ]]
  case "$mode" in
    download-failure)
      grep -q 'Joining failed during downloading agent bundle. Details: /var/log/clawctl-join.log' "$TEST_DIR/output"
      grep -q 'Could not download the pending join bundle for linux/amd64' "$TEST_DIR/output" ;;
    installer-failure)
      grep -q 'Joining failed during installing agent' "$TEST_DIR/output"
      grep -q 'installer diagnostic 25' "$TEST_DIR/output"
      ! grep -q 'installer diagnostic 5$' "$TEST_DIR/output" ;;
  esac
  [[ -z $(find "$TEST_DIR/tmp" -mindepth 1 -print -quit) ]]
done
printf 'join script: approval, optional installer, private files, argv/output secrecy, rejection, expiry and failure cleanup passed\n'
