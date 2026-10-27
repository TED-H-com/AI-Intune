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

python3 - "$ROOT" <<'PY'
import pathlib, sys
root = pathlib.Path(sys.argv[1])
s = (root/'ops/join/join.ps1').read_text()
for text in ("[switch]$JobsEnabled", "$jobs = 'false'", "--jobs-enabled $Jobs", "--token-file $TokenFile", 'WindowsBuiltInRole]::Administrator', 'Join code:', '/machines/join', 'expires_at', 'poll_seconds', 'Get-FileHash', 'SHA256', 'Unsafe agent archive member.', 'Set-JoinPrivate $work $true', 'Remove-Item -LiteralPath $work'):
    assert text in s, text
assert s.index('Get-FileHash') < s.index('Expand-JoinBundle $archive')
assert s.index('bundle/windows-$arch') < s.index('$Hub/v1/join/poll')
assert '*> $null' not in s, 'installer diagnostics must not be discarded'
for text in ('function Protect-JoinInstallerOutput', 'function Invoke-JoinInstaller',
             '$Text.Replace($secret,', '(?:token|secret)', r'\bbearer',
             '*>&1', '$LASTEXITCODE -ne 0',
             '$line = Protect-JoinInstallerOutput ([string]$_) $Secrets',
             'Add-Content -LiteralPath $LogFile -Value $line',
             'Last redacted output lines:', '$tail.Count -gt 10',
             '@($approved.enroll_token, $started.device_secret)',
             "Invoke-JoinInstaller (Join-Path $stage 'install-agent-windows.ps1')"):
    assert text in s, text
capture = s[s.index('function Invoke-JoinInstaller'):s.index('function Read-JoinBlock')]
assert capture.index('Protect-JoinInstallerOutput ([string]$_)') < capture.index('Add-Content')
assert 'Write-Host' not in capture and '[Console]' not in capture.split('$engine =', 1)[1]
assert "[string]$Proxy = ''" in s
assert '--jobs-enabled $Jobs @proxyArgs' in s
assert "@('--proxy', $Proxy)" in s
installer = (root / 'ops/install-agent-windows.ps1').read_text()
assert installer.index('Set-AgentConfig $ConfigFile $JobsEnabled $Proxy') < installer.index('Start-ScheduledTask')
assert '-NotePropertyName proxy_url -NotePropertyValue $Proxy' in installer
assert '$env:HTTP_PROXY = $Proxy' in s and '$env:HTTPS_PROXY = $Proxy' in s
assert '$proxyOptions.Proxy = $Proxy' in s
assert s.count('@proxyOptions') == 3
import xml.etree.ElementTree as ET
task = ET.fromstring((root/'ops/clawctl-agent.task.xml').read_text())
ns = {'t': 'http://schemas.microsoft.com/windows/2004/02/mit/task'}
assert task.find('t:Settings/t:Hidden', ns).text == 'true'
assert task.find('t:Actions/t:Exec/t:Command', ns).text == '@@CLAWCTL_AGENT_BIN@@'
assert task.find('t:Actions/t:Exec/t:Arguments', ns) is None
assert 'cmd.exe' not in (root/'ops/clawctl-agent.task.xml').read_text().lower()
installer = (root/'ops/install-agent-windows.ps1').read_text()
for text in ('jobs_enabled', '--monitor-only', 'Register-ScheduledTask', 'enroll --hub $Hub --token-file $TokenFile'):
    assert text in installer, text
assert installer.index("$TaskXml = $TaskXml -replace") < installer.index('\n  Register-ScheduledTask ')
assert 'encoding="UTF-16"' in installer
assert 'Fail "Scheduled task registration failed: $($_.Exception.Message)"' in installer
print('Windows bootstrap: static encoding, redacted diagnostics, monitor-only, approval, digest, private-file and cleanup checks passed.')
PY
if command -v pwsh >/dev/null 2>&1; then
  mkdir "$TEST_DIR/powershell"
  python3 - "$TEST_DIR/powershell" <<'PY'
import io, pathlib, sys, tarfile
root = pathlib.Path(sys.argv[1])
files = ['VERSION', 'clawctl-agent.exe', 'install-agent-windows.ps1', 'clawctl-agent.task.xml']
for mode in ['valid', 'traversal', 'backslash', 'absolute', 'symlink', 'hardlink', 'duplicate', 'missing', 'truncated']:
    with tarfile.open(root/f'{mode}.tar.gz', 'w:gz', format=tarfile.USTAR_FORMAT) as t:
        for name in files[:-1] if mode == 'missing' else files:
            entry = tarfile.TarInfo(name); entry.size = 4
            t.addfile(entry, io.BytesIO(b'test'))
        if mode not in ('valid', 'missing', 'truncated'):
            names = {'traversal':'../escape', 'backslash':'..\\escape', 'absolute':'C:/escape', 'duplicate':'VERSION'}
            entry = tarfile.TarInfo(names.get(mode, 'link'))
            if mode in ('symlink', 'hardlink'):
                entry.type = tarfile.SYMTYPE if mode == 'symlink' else tarfile.LNKTYPE
                entry.linkname = '../escape'
            t.addfile(entry)
    if mode == 'truncated':
        (root/f'{mode}.tar.gz').write_bytes(b'not gzip')
PY
  pwsh -NoProfile -File "$ROOT/ops/join/test-windows.ps1" -Fixtures "$TEST_DIR/powershell"
else
  printf 'skip: pwsh is not available; PowerShell parse/extraction/redaction tests not run.\n'
fi

# The Fly and Compose images share this initializer. Optional OS pairs must
# survive image-to-volume seeding, including on a rerun of the same release.
seed="$TEST_DIR/seed/agent-bootstrap/windows-test"
data="$TEST_DIR/hub-data"
mkdir -p "$seed"
for target in linux-amd64 linux-arm64 windows-amd64 windows-arm64; do
  printf '%s\n' "$target" >"$seed/clawctl-agent-bootstrap-$target.tar.gz"
done
printf 'fixture sums\n' >"$seed/SHA256SUMS"
CLAWCTL_VERSION=windows-test CLAWCTL_DATA="$data" CLAWCTL_SEED="$TEST_DIR/seed" sh "$ROOT/ops/docker/hub-data-init.sh" >"$TEST_DIR/seed-output"
for target in linux-amd64 linux-arm64 windows-amd64 windows-arm64; do
  cmp "$seed/clawctl-agent-bootstrap-$target.tar.gz" "$data/agent-bootstrap/windows-test/clawctl-agent-bootstrap-$target.tar.gz"
done
CLAWCTL_VERSION=windows-test CLAWCTL_DATA="$data" CLAWCTL_SEED="$TEST_DIR/seed" sh "$ROOT/ops/docker/hub-data-init.sh" >>"$TEST_DIR/seed-output"
rm "$seed/clawctl-agent-bootstrap-windows-arm64.tar.gz"
if CLAWCTL_VERSION=windows-test CLAWCTL_DATA="$data" CLAWCTL_SEED="$TEST_DIR/seed" sh "$ROOT/ops/docker/hub-data-init.sh" >"$TEST_DIR/seed-output" 2>&1; then
  echo 'Incomplete Windows seed accepted' >&2; exit 1
fi
printf 'Docker/Fly bootstrap: complete Windows pair is seeded and incomplete pairs are rejected.\n'
