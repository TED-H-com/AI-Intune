#!/bin/bash
set -euo pipefail
if (( EUID == 0 )); then
    printf 'Run this test suite as a non-root user.\n' >&2
    exit 2
fi
root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
wrapper=$root/clawctl-maint
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
export CLAWCTL_MAINT_TEST=1 CLAWCTL_MAINT_DRYEXEC=1
export CLAWCTL_MAINT_LOG=$tmp/log
export CLAWCTL_MAINT_CONF=${1:-$tmp/conf}
export SUDO_USER='test user'
printf 'NPM_BIN=/usr/bin/true\n' > "$tmp/conf"
count=0
check() {
    local expected=$1 needle=$2 output rc=0 before after
    shift 2
    before=$(wc -l < "$CLAWCTL_MAINT_LOG")
    output=$("$wrapper" "$@" 2>&1) || rc=$?
    after=$(wc -l < "$CLAWCTL_MAINT_LOG")
    if [[ $rc != "$expected" || $output != *"$needle"* || $after != "$((before + 1))" ]]; then
        printf 'FAIL (%s): %s\n%s\n' "$rc" "$*" "$output" >&2
        exit 1
    fi
    [[ $(tail -n 1 "$CLAWCTL_MAINT_LOG") == *" exit=$rc" ]] || exit 1
    count=$((count + 1))
}
: > "$CLAWCTL_MAINT_LOG"
base='env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LANG=C.UTF-8'
for sub in update upgrade dist-upgrade autoremove; do
    check 0 "$base DEBIAN_FRONTEND=noninteractive /usr/bin/apt-get -y $sub" apt "$sub"
done
check 0 'install -- curl libfoo:amd64=1.2~rc1 foo+bar' apt install curl libfoo:amd64=1.2~rc1 foo+bar
check 0 "$base /usr/sbin/reboot" reboot
for verb in restart start stop; do
    check 0 "/usr/bin/systemctl $verb foo@bar.service" svc "$verb" foo@bar
    check 0 "/usr/bin/systemctl $verb foo.service" svc "$verb" foo.service
done
check 0 '/usr/bin/systemctl --no-pager status foo.service' svc status foo
for pkg in ./x.deb x.deb '-o' foo/bar '--help' ''; do check 2 Usage: apt install "$pkg"; done
check 2 Usage: apt install -o foo
check 2 Usage: apt install
check 2 Usage: apt update extra
check 2 Usage: apt remove x
check 2 Usage: reboot extra
check 2 Usage: svc edit x
check 2 Usage: svc daemon-reload
check 2 Usage: svc restart 'a b'
check 2 Usage: svc restart --help
check 2 Usage: svc restart x y
for pkg in https://x git+https://x ../x file:x /x .x '-x' '@scope/.x:1'; do
    check 2 Usage: npm install -g --ignore-scripts "$pkg"
done
check 2 Usage: npm install -g x
check 2 Usage: npm install --ignore-scripts -g x
check 2 Usage: npm install -g --ignore-scripts
check 2 Usage: npm update -g --ignore-scripts x --dry-run
check 2 Usage: unknown
check 2 Usage:
# Non-root-owned config must be rejected even in test mode.
saved_conf=$CLAWCTL_MAINT_CONF
export CLAWCTL_MAINT_CONF=$tmp/conf
check 2 Usage: npm install -g --ignore-scripts x
# shellcheck disable=SC2016 # literal $(...) is the point: it must not run
printf 'NPM_BIN=$(touch %s/pwned)\n' "$tmp" > "$tmp/conf"
check 2 Usage: npm update -g --ignore-scripts
[[ ! -e $tmp/pwned ]]
export CLAWCTL_MAINT_CONF=$saved_conf
if [[ $# == 1 ]]; then
    for verb in install update; do
        check 0 'npm_config_ignore_scripts=true /usr/bin/true' npm "$verb" -g --ignore-scripts foo '@scope/pkg@^1.2' foo@~2
        check 0 '--ignore-scripts --dry-run foo' npm "$verb" -g --ignore-scripts --dry-run foo
    done
    check 0 'update -g --ignore-scripts' npm update -g --ignore-scripts
    check 0 'update -g --ignore-scripts --dry-run' npm update -g --ignore-scripts --dry-run
else
    printf 'Npm execution checks require a root-owned config argument (CI supplies it).\n'
fi
# Without test mode, an unprivileged invocation must fail before dispatch.
export CLAWCTL_MAINT_TEST=0
# Its production log is intentionally inaccessible; still require rejection.
rc=0
"$wrapper" reboot >/dev/null 2>&1 || rc=$?
[[ $rc == 2 ]]
printf 'Passed %s maintenance checks.\n' "$count"
