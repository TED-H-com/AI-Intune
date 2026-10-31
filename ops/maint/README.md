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
