#!/bin/bash
set -euo pipefail
if (( EUID == 0 )); then
    printf 'Run this test suite as a non-root user.\n' >&2
    exit 2
fi
root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
wrapper=$root/clawctl-maint-macos
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
export CLAWCTL_MAINT_TEST=1 CLAWCTL_MAINT_DRYEXEC=1
export CLAWCTL_MAINT_LOG=$tmp/log
export CLAWCTL_MAINT_CONF=${1:-$tmp/conf}
export SUDO_USER='test user'
printf 'NPM_BIN=/usr/bin/true\n' > "$tmp/conf"
count=0
check() {
    local expected=$1 command=$2 output rc=0 before=0 after
    shift 2
    if [[ -e $CLAWCTL_MAINT_LOG ]]; then before=$(wc -l < "$CLAWCTL_MAINT_LOG"); fi
    output=$("$wrapper" "$@" 2>&1) || rc=$?
    after=$(wc -l < "$CLAWCTL_MAINT_LOG")
    if [[ $rc != "$expected" || $after != "$((before + 1))" ]]; then
        printf 'FAIL (%s): %s\n%s\n' "$rc" "$*" "$output" >&2
        exit 1
    fi
    if [[ $expected == 0 ]]; then
        [[ $output == "$command " ]] || { printf 'Expected: %s\nActual: %s\n' "$command" "$output" >&2; exit 1; }
    else
        [[ $output == *Usage:* ]] || exit 1
    fi
    local receipt quoted=''
    printf -v quoted '%q ' "$@"
    receipt=$(tail -n 1 "$CLAWCTL_MAINT_LOG")
    [[ $receipt == *" user=test\\ user argv=$quoted exit=$rc" ]] || exit 1
    count=$((count + 1))
}
base='/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/var/root'
# The first refusal must create the log, and every invocation adds one receipt.
check 2 '' apt update
mode=$(stat -c %a "$CLAWCTL_MAINT_LOG" 2>/dev/null || stat -f %Lp "$CLAWCTL_MAINT_LOG")
[[ $mode == 640 ]]
check 0 "$base /sbin/shutdown -r now" reboot
check 0 "$base /bin/launchctl kickstart -k system/com.example.agent" svc kickstart com.example.agent
check 0 "$base /bin/launchctl print system/com.example.agent" svc status com.example.agent
check 0 "$base /usr/bin/pmset -g" pmset -g
for sub in custom live batt ps cap assertions; do
    check 0 "$base /usr/bin/pmset -g $sub" pmset -g "$sub"
done
for flag in -a -b -c -u; do
    check 0 "$base /usr/bin/pmset $flag sleep 0 disksleep 9999 standby 1 powernap 0 autorestart 1 displaysleep 10" \
        pmset "$flag" sleep 0 disksleep 9999 standby 1 powernap 0 autorestart 1 displaysleep 10
done
for key in hibernatemode destroyfvkeyonstandby schedule repeat restoredefaults; do
    check 2 '' pmset -a "$key" 1
    check 2 '' pmset "$key"
done
for value in abc -1 1.5 10000 ''; do check 2 '' pmset -a sleep "$value"; done
check 2 '' pmset -s sleep 1
check 2 '' pmset -a sleep
check 2 '' pmset -g unknown
check 2 '' pmset -g custom extra
check 2 '' pmset -g ''
check 2 '' pmset
for label in ../x system/x -x nodot a..b 'a b.c'; do check 2 '' svc kickstart "$label"; done
long_label=$(printf 'a%0127d.b' 0)
check 2 '' svc status "$long_label"
check 2 '' svc restart com.example.agent
check 2 '' svc status
for pkg in https://x git+https://x git:x file:x ./x ../x /x .x -x x.tgz x.tar x.tar.gz x.tar.bz2 x.tbz2 x.txz; do
    check 2 '' npm install -g --ignore-scripts "$pkg"
done
check 2 '' npm install -g x
check 2 '' npm install --ignore-scripts -g x
check 2 '' npm install -g --ignore-scripts
check 2 '' npm update -g --ignore-scripts x --dry-run
check 2 '' reboot extra
check 2 '' unknown
check 2 ''
saved_conf=$CLAWCTL_MAINT_CONF
export CLAWCTL_MAINT_CONF=$tmp/conf
check 2 '' npm update -g --ignore-scripts
# shellcheck disable=SC2016 # Literal substitution must never be evaluated.
printf 'NPM_BIN=$(touch %s/pwned)\n' "$tmp" > "$tmp/conf"
check 2 '' npm update -g --ignore-scripts
[[ ! -e $tmp/pwned ]]
export CLAWCTL_MAINT_CONF=$saved_conf
if [[ $# == 1 ]]; then
    npm_base='/usr/bin/env -i PATH=/usr/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/var/root LANG=en_US.UTF-8 npm_config_ignore_scripts=true /usr/bin/true'
    for verb in install update; do
        check 0 "$npm_base $verb -g --ignore-scripts foo @scope/pkg@\^1.2 foo@~2" npm "$verb" -g --ignore-scripts foo '@scope/pkg@^1.2' foo@~2
        check 0 "$npm_base $verb -g --ignore-scripts --dry-run foo" npm "$verb" -g --ignore-scripts --dry-run foo
    done
    check 0 "$npm_base update -g --ignore-scripts" npm update -g --ignore-scripts
    check 0 "$npm_base update -g --ignore-scripts --dry-run" npm update -g --ignore-scripts --dry-run
else
    printf 'Npm execution checks require a root-owned config argument (CI supplies it).\n'
fi
/bin/bash -n "$wrapper"
export CLAWCTL_MAINT_TEST=0
rc=0
"$wrapper" reboot >/dev/null 2>&1 || rc=$?
[[ $rc == 2 ]]
printf 'Passed %s macOS maintenance checks.\n' "$count"
