# Host setup profile

Open **Machines → Configuration → Host setup profile**. An administrator can
save one fleet-wide profile; viewers can inspect settings and Linux machine
reports. Every setting starts **Do not manage**. Selecting Off removes only
changes made by this applier. Returning to Do not manage leaves current host
settings in place. There is no per-machine override in this phase.

| Setting | Effect |
| --- | --- |
| Keep running with the lid closed | A logind drop-in ignores lid switches on battery, external power and a dock. Reloads logind without restarting sessions. |
| Never sleep | Masks sleep, suspend, hibernate and hybrid-sleep targets. Existing administrator masks already satisfy the setting. Off removes only masks recorded as created by this applier. |
| Power mode | Selects Performance, Balanced or Power saver through powerprofilesctl. Reports unsupported when unavailable. |
| Keep Wi-Fi awake | NetworkManager drop-in sets wifi.powersave=2; reloads configuration. Existing connections adopt it on reconnect. |
| Journal size limit (MB) | Sets SystemMaxUse under [Journal], from 100 to 4096 MB, and restarts journald. |
| Install security updates automatically | Writes `/etc/apt/apt.conf.d/90-clawctl-fleet-auto-upgrades`, overriding earlier Debian/Ubuntu APT settings without touching `20auto-upgrades`. Off removes only this managed drop-in; it does not force automatic updates off. Requires the unattended-upgrades package; no downloads or package installation. Other distributions report unsupported. |
| Allow the agent's scoped admin commands | Installs the embedded, syntax-checked sudoers policy for the installed service account only. |
| Keep user services running after logout | Enables linger for that account. Off disables it only if the applier enabled it. |
| Clean root disk space daily | Uses the existing root disk-clean installer and timer, including its tmpfiles and 500 MB journal policy. The profile's explicit journal limit takes precedence. Keeps the installer's safe preview default; deletion requires separate local approval. Off disables a timer installed by the applier and retains its files. |

The logind, NetworkManager and journald settings use their own
`90-clawctl-fleet.conf` drop-ins, leaving distro defaults and other drop-ins
untouched. APT likewise uses its own later drop-in. An unmarked file at an
applier-owned drop-in path is preserved and reports Failed when enabling the
setting; Off leaves that unmarked file untouched. Later local drop-ins can still
override these settings. Backups
have the suffix `.fleet-apply.bak`. Changing a setting to Do not manage does not
restore a former host configuration. Power mode and the journal limit have no
Off value: choose another value or stop managing them.

## Install and inspect

As root, from a Linux bootstrap bundle:

```sh
bash fleet-apply/install.sh --agent-user agent
systemctl status clawctl-fleet-apply.timer clawctl-fleet-apply.path
/usr/local/sbin/clawctl-fleet-apply --dry-run
```

From the checkout use `ops/fleet/applier/install.sh`. Bootstrap also offers an
`applier` phase. The installer records only the service account name in
root-owned `/etc/clawctl/fleet-apply.conf` and installs reviewed assets under
`/usr/local`. It enables a file watch and a timer: first check two minutes after
boot, then every 30 minutes, with up to two minutes of random delay. Systemd
serializes service invocations; the executable additionally takes a file lock.
The agent writes its profile atomically on digest changes, so the watch promptly
starts the applier. The periodic timer repairs drift even when the profile does
not change. The agent never runs the installer or calls sudo.

`last.json` under `/var/lib/clawctl-fleet-apply` is atomic, mode 0644, and contains
only schema, profile digest, apply time, bounded fixed item messages and a reboot
flag. The agent relays it with observations. The Hub shows display names, whether
the digest matches, each item result, restart requirement and Hub receipt time.
Waiting includes missing or stale reports; Failed includes an item failure.
Unsupported items remain explicitly visible. Reports are agent-relayed host
facts, not independent verification of a compromised host.

The read API is `GET /v1/operator/host-profile`; MCP `host_profile_get` exposes the
same read. Saves are exclusively through the administrator's Hub form, with the
existing CSRF and MFA boundary and an atomic `fleet_host_profile` audit entry.

`uninstall.sh` stops/disables the applier timer, watch and service, and removes
only marked applier units. Host settings, binaries, state, configuration and
backups are retained for review and rollback. `--root-prefix /absolute/fixture`
is offline filesystem staging for tests; commands still use PATH, so use fakes
when testing the executable. It is not a systemd namespace or a live-host sandbox.

## Privilege boundary

The observer agent remains unprivileged with NoNewPrivileges and
ProtectSystem=strict. It writes only data to its existing writable
`~/.config/clawctl/host-profile.json`, mode 0600. Linux check-in responses add
`host_profile` and `host_profile_digest`. Other platforms receive neither.
The default profile is `{}` and manages nothing.

The separate root service accepts a fixed vocabulary, not shell, paths, unit
names, usernames or templates from the Hub. It reads the account from root-owned
installer configuration and resolves that account's home through the OS account
database. It rejects symlinks, wrong ownership, oversized files, unknown fields,
duplicate keys, wrong types and invalid ranges before applying any item. It opens
user-controlled path components through directory descriptors without following
symlinks. Drop-ins come from embedded templates, commands use fixed argument
arrays, and sudoers is checked with `visudo -cf` before atomic installation.

The scoped sudoers rule permits only restarting clawctl-agent.service,
enabling/disabling disk-clean-root.timer, and running the root cleaner with
`--scope root --dry-run`. It follows the documented narrow-service-command
policy; arbitrary binary installation, unit installation, shell commands and
unbounded sudo are excluded. The sandboxed observer still cannot elevate.

Threat note: a compromised agent user can choose vocabulary values for its own
host, including these privileged power and service choices. It cannot select
another account or host, substitute a template, or submit code to the applier.
A profile digest identifies data; it is not a signature or proof of operator
intent after the service account is compromised. Protect root-owned executable,
installer, config and state directories separately.

## New disk setup

Open a Linux machine's **Disks** section. Every reported disk shows its identity,
size, filesystem, mounts, partition count and boot/storage membership. Only an
empty, non-removable, writable disk of at least 1 GiB with a serial or WWN is
marked **Ready to set up**. Readiness links directly to these disks.

An administrator chooses a mount point (default `/data`), ext4 or xfs, a label
and an existing non-root owner (defaulting to the reported agent service user).
The confirmation names the model, serial or WWN, device and size. Approval uses
the Hub's protected browser form and fresh MFA window. Pending jobs can be
cancelled; cancellation appears as Expired in the job list and is distinguished
in the audit log. Approval, cancellation and final results each have an atomic
audit entry: `disk_setup_approve`, `disk_setup_cancel`, `disk_setup_result`.
Only one job may be active for a device, serial or WWN on that machine.
Uncollected approvals expire after 24 hours; delivered jobs remain single use.
The panel shows pending and completed jobs, refusal reasons, UUID, mount point
and disk usage after successful setup.

Check-in delivers `disk_jobs` only to Linux agents. The unprivileged agent writes
`~/.config/clawctl/disk-jobs.json` atomically, mode 0600, replacing the previous
list and dropping completed jobs. The root applier runs these jobs after profile
settings during the same service invocation; both files are watched. Results
are root-owned, readable receipts under
`/var/lib/clawctl-fleet-apply/disk-jobs/<id>.json`. Keep those receipts: an
existing ID, including a failed or interrupted operation, is never run again.
The agent relays only results for its last delivered jobs, so historical receipts
cannot crowd out a new result. Hub result transitions are machine-bound and
idempotent.

Before partitioning, the applier rechecks the exact device using lsblk and a
matching serial/WWN alias under `/dev/disk/by-id`. Model and byte size must match
exactly. It refuses partitions or children, any filesystem/UUID/label/partition
table or wipefs signature, mounts, swap, holders, removable or read-only media,
root/boot disks, an unavailable check, an existing fstab target, a mounted or
non-empty target directory, unsafe paths and a missing or low-UID owner. System
directories and `/var/lib/clawctl*` are forbidden mount targets. Labels use
1–16 ASCII letters, digits, underscores or hyphens. Owner names use a bounded
account-name grammar and must resolve to UID >= 1000.

Only then does it create GPT with one partition, make ext4/xfs without force
flags, obtain the UUID, back up and atomically append a marked fstab entry,
mount, assign ownership/mode 0755 and verify the mounted UUID/type/target.
A durable result reservation precedes partitioning. Failure after that point
stops with a named step; it never attempts cleanup. Inspect a failed operation
locally before deciding what to do next. **There is no wipe, force, overwrite or
reuse-disk option, in the UI, API or applier.** Unknown job fields are rejected.
Tests use fake commands and filesystem fixtures; no real disk acceptance is
claimed.

The installer-selected account and descriptor-based O_NOFOLLOW traversal,
ownership checks, 64 KiB limit, strict JSON and per-value validation apply to the
jobs file as well as the profile. Commands use fixed argument arrays. As with
the profile, this user-writable file is not cryptographic proof of Hub approval:
a compromised service account could request setup of an otherwise eligible
empty local disk. Root-side checks preserve existing data; protect the account,
root executable, configuration and receipt directory separately.
