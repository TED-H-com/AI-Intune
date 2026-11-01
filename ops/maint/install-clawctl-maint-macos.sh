#!/bin/bash
set -euo pipefail
umask 022
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
LC_ALL=C
export LC_ALL

usage() {
    printf 'Usage: sudo bash ops/maint/install-clawctl-maint-macos.sh <username>\n' >&2
    exit 2
}
(( EUID == 0 )) || usage
[[ $(uname -s) == Darwin && $# == 1 ]] || usage
user=$1
[[ $user =~ ^[a-z_][a-z0-9_-]*$ ]] || usage
id "$user" >/dev/null 2>&1 || usage
root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
user_home=$(dscl . -read "/Users/$user" NFSHomeDirectory | sed 's/^NFSHomeDirectory: //')
[[ $user_home == /* && -d $user_home ]] || exit 1
TS=$(date -u '+%Y%m%dT%H%M%SZ').$$
backup=/var/root/clawctl-backups
user_backup=$user_home/clawctl-backups
wrapper=/usr/local/sbin/clawctl-maint
rule=/etc/sudoers.d/clawctl-maintenance
# Validate the complete candidate before changing installed files.
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
sed "s/@USER@/$user/g" "$root/clawctl-maintenance-macos.sudoers.tmpl" > "$tmp"
chmod 0440 "$tmp"
/usr/sbin/visudo -cf "$tmp" || exit 1

/usr/bin/install -d -o root -g wheel -m 0700 "$backup"
/usr/bin/install -d -o "$user" -g "$(id -gn "$user")" -m 0700 "$user_backup"
if [[ -d /etc/sudoers.d ]]; then
    cp -Rp /etc/sudoers.d "$backup/sudoers.d.$TS"
else
    mkdir "$backup/sudoers.d.$TS"
fi
chown -R root:wheel "$backup/sudoers.d.$TS"
chmod 0700 "$backup/sudoers.d.$TS"
cp -Rp "$backup/sudoers.d.$TS" "$user_backup/sudoers.d.$TS"
chown -R "$user:$(id -gn "$user")" "$user_backup/sudoers.d.$TS"
chmod 0700 "$user_backup/sudoers.d.$TS"
if [[ -e $wrapper ]]; then
    cp -Rp "$wrapper" "$backup/clawctl-maint.$TS"
    cp -Rp "$wrapper" "$user_backup/clawctl-maint.$TS"
    chown "$user:$(id -gn "$user")" "$user_backup/clawctl-maint.$TS"
fi
/usr/bin/install -d -o root -g wheel -m 0755 /usr/local/sbin /etc/sudoers.d
/usr/bin/install -o root -g wheel -m 0755 "$root/clawctl-maint-macos" "$wrapper"
if [[ ! -e /var/log/sudo-clawctl.log ]]; then
    /usr/bin/install -o root -g wheel -m 0640 /dev/null /var/log/sudo-clawctl.log
fi
/usr/bin/install -o root -g wheel -m 0440 "$tmp" "$rule"
if ! /usr/sbin/visudo -c; then
    if [[ -e $backup/sudoers.d.$TS/clawctl-maintenance ]]; then
        cp -p "$backup/sudoers.d.$TS/clawctl-maintenance" "$rule"
    else
        rm -f "$rule"
    fi
    printf 'Sudoers validation failed; previous maintenance rule restored.\n' >&2
    exit 1
fi
if ! grep -Eq '^[[:space:]]*([#@]includedir)[[:space:]]+"?(/private)?/etc/sudoers\.d"?([[:space:]]|$)' /etc/sudoers; then
    printf 'Warning: add #includedir /private/etc/sudoers.d using sudo visudo to enable the maintenance rule.\n' >&2
fi
created_conf=0
if [[ ! -e /etc/clawctl/maint.conf ]]; then
    for npm in /opt/homebrew/bin/npm /usr/local/bin/npm; do
        if [[ -x $npm ]]; then
            /usr/bin/install -d -o root -g wheel -m 0755 /etc/clawctl
            printf 'NPM_BIN=%s\n' "$npm" > "$tmp"
            /usr/bin/install -o root -g wheel -m 0644 "$tmp" /etc/clawctl/maint.conf
            created_conf=1
            break
        fi
    done
fi
printf 'Wrapper: %s\nSudoers: %s\nLog: /var/log/sudo-clawctl.log\nConfig: /etc/clawctl/maint.conf\n' "$wrapper" "$rule"
printf 'Backups: %s and %s (suffix %s)\n' "$backup" "$user_backup" "$TS"
shasum -a 256 "$wrapper"
printf 'visudo: passed\nRollback commands:\n'
if [[ -e $backup/sudoers.d.$TS/clawctl-maintenance ]]; then
    printf 'sudo cp -p %q %q\n' "$backup/sudoers.d.$TS/clawctl-maintenance" "$rule"
else
    printf 'sudo rm -f %q\n' "$rule"
fi
printf 'sudo /usr/sbin/visudo -c\n'
if [[ -e $backup/clawctl-maint.$TS ]]; then
    printf 'sudo cp -p %q %q\n' "$backup/clawctl-maint.$TS" "$wrapper"
else
    printf 'sudo rm -f %q\n' "$wrapper"
fi
if (( created_conf )); then
    printf 'sudo rm -f /etc/clawctl/maint.conf\n'
fi
