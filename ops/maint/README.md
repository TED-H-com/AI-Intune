# Sudo maintenance wrapper

Install from the repository root. Replace `agentuser` with the operator account:

```sh
sudo install -o root -g root -m 0755 ops/maint/clawctl-maint /usr/local/sbin/clawctl-maint
sudo install -d -o root -g root -m 0755 /etc/clawctl
sudo install -o root -g root -m 0644 ops/maint/maint.conf.example /etc/clawctl/maint.conf
sudoedit /etc/clawctl/maint.conf
sed 's/@USER@/agentuser/g' ops/maint/clawctl-maintenance.sudoers.tmpl > /tmp/clawctl-maintenance.sudoers
sudo visudo -cf /tmp/clawctl-maintenance.sudoers
sudo install -o root -g root -m 0440 /tmp/clawctl-maintenance.sudoers /etc/sudoers.d/clawctl-maintenance
rm /tmp/clawctl-maintenance.sudoers
```

The sudoers rule uses plain command-path matching compatible with sudo-rs
0.2.13. The wrapper validates all arguments. Keep the wrapper, sudoers file,
and `/etc/clawctl` directory writable only by root. Set `NPM_BIN` to an
executable absolute path. Configuration accepts blank lines, comments beginning
with `#`, and exactly one unquoted `NPM_BIN=/absolute/path` assignment; it is
never sourced. The config must be root-owned without group/world write access.
Select an npm installation trusted to execute as root.

Examples:

```sh
sudo /usr/local/sbin/clawctl-maint apt update
sudo /usr/local/sbin/clawctl-maint apt install curl
sudo /usr/local/sbin/clawctl-maint svc restart clawctl-agent
sudo /usr/local/sbin/clawctl-maint npm update -g --ignore-scripts --dry-run
```

Commands run with a clean environment. npm runs from `/` with lifecycle scripts
disabled. Each invocation appends its timestamp, caller, shell-quoted arguments,
and exit status to `/var/log/sudo-clawctl.log` (created root:root 0640), and sends
the same receipt to syslog when logger is available.

Run checks as a non-root user:

```sh
shellcheck ops/maint/clawctl-maint ops/maint/test-clawctl-maint.sh
bash ops/maint/test-clawctl-maint.sh
```

For the full npm execution checks, supply a root-owned config containing
`NPM_BIN=/usr/bin/true` as the test script's first argument (CI creates this
fixture). Without that fixture the suite checks command validation and rejects
user-owned config. Tests never run real maintenance commands. Test overrides
`CLAWCTL_MAINT_LOG`, `CLAWCTL_MAINT_CONF`, and `CLAWCTL_MAINT_DRYEXEC=1` require
both `CLAWCTL_MAINT_TEST=1` and a non-root EUID. Root always uses production paths
and executes commands.

Rollback: remove the sudoers grant first, then the wrapper and config. Retain
the log for audit:

```sh
sudo rm /etc/sudoers.d/clawctl-maintenance
sudo rm /usr/local/sbin/clawctl-maint /etc/clawctl/maint.conf
```

## macOS

From a checkout on the Mac, replace `agentuser` with the operator account:

```sh
sudo bash ops/maint/install-clawctl-maint-macos.sh agentuser
```

The installer requires Darwin and an existing local account. It installs
`clawctl-maint-macos` as `/usr/local/sbin/clawctl-maint` (root:wheel 0755)
and the macOS sudoers template as `/etc/sudoers.d/clawctl-maintenance`
(root:wheel 0440). It validates the candidate with `visudo -cf` before
installation, checks the full config with `visudo -c`, and restores the
previous maintenance rule if the full check fails. Ensure `/etc/sudoers`
includes `/private/etc/sudoers.d` or `/etc/sudoers.d`; the installer warns
if that directive is absent.

Backups of `/etc/sudoers.d` and any existing wrapper are stored under
`/var/root/clawctl-backups` and the operator's `~/clawctl-backups`, with a
unique timestamp suffix. Backup directories are mode 0700 and owned by
root and the operator respectively. The summary prints the installed paths,
backup paths, wrapper SHA-256, validation result, and exact rollback commands.
Use the root-owned backups for rollback. Retain the audit log.

If `/etc/clawctl/maint.conf` is absent, the installer selects the first
executable npm at `/opt/homebrew/bin/npm` or `/usr/local/bin/npm` and writes
`NPM_BIN` in a root:wheel 0644 config. If neither exists, configure npm
manually before using npm commands. The same config syntax and ownership
requirements as Linux apply. Keep `/etc/clawctl` writable only by root.

```sh
sudo /usr/local/sbin/clawctl-maint reboot
sudo /usr/local/sbin/clawctl-maint svc kickstart com.example.agent
sudo /usr/local/sbin/clawctl-maint svc status com.example.agent
sudo /usr/local/sbin/clawctl-maint npm update -g --ignore-scripts --dry-run
sudo /usr/local/sbin/clawctl-maint pmset -g assertions
sudo /usr/local/sbin/clawctl-maint pmset -a sleep 30 displaysleep 10
```

Service labels must use reverse-DNS syntax with at least one dot, at most
128 characters, and no slashes, spaces, empty components, or leading dash.
`kickstart` runs `launchctl kickstart -k system/<label>`; `status` runs
`launchctl print system/<label>`. Reboot runs `/sbin/shutdown -r now`.

Power queries allow `pmset -g` optionally followed by `custom`, `live`,
`batt`, `ps`, `cap`, or `assertions`. Changes require one of `-a`, `-b`,
`-c`, or `-u`, followed by key/value pairs. Allowed keys are `sleep`,
`disksleep`, `standby`, `powernap`, `autorestart`, and `displaysleep`;
values must be one to four decimal digits. Other pmset operations and
`apt` are refused.

The wrapper supports macOS `/bin/bash` 3.2. Commands run from `/` in a
clean environment with `HOME=/var/root`; npm adds its directory to PATH,
sets `LANG=en_US.UTF-8`, and disables lifecycle scripts. npm accepts
package names and versions, including scoped packages, and rejects URLs,
paths, git/file references, and tarballs. Each call, including refusals,
appends a UTC ISO timestamp, caller, shell-quoted arguments, and exit status
to `/var/log/sudo-clawctl.log` (created root:wheel 0640), with best-effort
syslog delivery.

Run checks as a non-root user on Linux or macOS:

```sh
shellcheck ops/maint/clawctl-maint-macos ops/maint/test-clawctl-maint-macos.sh ops/maint/install-clawctl-maint-macos.sh
bash ops/maint/test-clawctl-maint-macos.sh
```

Pass a root-owned config containing `NPM_BIN=/usr/bin/true` as the optional
first test argument to include npm execution checks. CI supplies it. The
same non-root-only test overrides described above apply; tests print and
compare commands without performing maintenance.
