# Onboarding v2: add a machine in one action

Status: proposal, 2026-10-18. Owner: fleet operator. Phase 1 implementation PR:
`feat-readiness-auto-vs-needs-you`.

Design principle (2026-10-11): every feature gets a polished, human-usable Hub
UI first. Hermes and Grok Bot act through MCP on the same contracts. Fleet-specific
values (host names, account slots, SSH public keys, Tailscale tags) live in the
private overlay or in Hub settings, never in this public repository.

## 1. Problem

Two laptops were onboarded on 2026-10-17/18 (generic names here: `host-b`,
`host-c`). Every step below was done by hand, either by the operator or by an
assistant driving SSH with the operator's password.

| # | Step | Who did it | Operator touches (2 hosts) |
|---|------|------------|---------------------------:|
| 1 | Install `openssh-server` at the console | operator | 2 |
| 2 | Share the login password with the assistant | operator | 1 |
| 3 | Install SSH keys, `~/.ssh/config`, jump host | assistant | 0 |
| 4 | Scoped sudoers drop-in, `visudo -c` | assistant (with password) | 0 |
| 5 | Power: lid ignore, mask sleep, power profile, Wi-Fi powersave | assistant | 0 |
| 6 | Unattended upgrades, full upgrade, base packages | assistant | 0 |
| 7 | Install Tailscale, `tailscale up`, **approve each device** | assistant + operator | 2 |
| 8 | Hermes install, plugin, user unit | assistant | 0 |
| 9 | agy install + **3 OAuth consents per host**, paste codes back | assistant + operator | 12 (6 opens, 6 code relays) |
| 10 | Disk-clean and daily-check timers, linger | assistant | 0 |
| 11 | **Enrollment tickets** in Hub (admin + MFA), download keyed package | operator | 3 (2 tickets, 1 MFA) |
| 12 | Copy token/package to the host, run installer | assistant | 0 |
| 13 | Reboot after kernel/shell upgrade | operator | 1 |
| 14 | Readiness targets per host (access path, sudoers path, backup unit) | operator | 6 |
| 15 | Notification channel binding per host | operator | 2 |
| 16 | Fix display-name capitalisation (`host1` vs `Host2`) | operator | 1 |
| | **Total** | | **≈ 30 operator touches, ≈ 20 hand-run procedures** |

Plus three secrets crossed chat or terminals: the login password, two enrollment
tokens. The readiness page then still listed ~10 checks per host without saying
which ones would resolve on their own.

## 2. Target flow

```
Operator                      New box (fresh Ubuntu)           Hub
--------                      ----------------------           ---
                              paste ONE line in a terminal:
                              curl -fsSL https://HUB/join.sh | sudo bash
                                 prints:  Join code  KQ7M-42XD
                                          https://HUB/join
Hub > Machines > Waiting to join
  "KQ7M-42XD  Ubuntu 26.04  amd64  192.168.x.y"
  name [Host3]  profile [Laptop]  ( Approve )   --approve-->  mints enroll token + one-off
                                                               preauthorized tagged Tailscale key
                              script receives both over TLS <-- (single use, 10 min)
                              installs Tailscale, sshd, agent,
                              root fleet applier, enrolls
                                                               progress appears on /readiness
Hub > Readiness: "Needs you (3)"
  agy sign-in on Host3 (3 accounts) -> one page, link + code field each
```

| | Before | After (phase 3) |
|---|---:|---:|
| Operator touches for 2 hosts | ≈ 30 | **2 pastes + 1 approve (batch) + 6 agy consents = 9** |
| Operator touches if agy uses a non-OAuth credential (open question) | — | **3** |
| Secrets typed or pasted by a human | 3 | **0** (OAuth codes go into a Hub field, not a terminal) |
| Hand-run procedures | ≈ 20 | 0 |

The six agy consents cannot be removed by the Hub: Antigravity CLI OAuth
tokens are bound to the device session and its docs say to sign in on each
machine (copying token files triggers re-authentication). What the Hub can do is
put all of them on one page with copy-paste code fields, in one sitting.

## 3. UX mockups

### 3.1 Readiness (phase 1, implemented in the first PR)

```
Host readiness
┌──────────────────────────────────────────────────────────────────────┐
│ Needs you (3)                                                        │
│  agy signed in .......... Host2, Host3   Sign in as the agent     │
│                                              user, then wait for a    │
│                                              fresh report. [How]      │
│  Reachability ........... Host3            Approve the machine in   │
│                                              the Tailscale console.   │
├──────────────────────────────────────────────────────────────────────┤
│ ▸ Fixing itself (5) — the Hub and agents are handling these          │
│ ▸ Done (31)                                                          │
└──────────────────────────────────────────────────────────────────────┘
Fleet defaults  [access path: tailscale ▾] [sudoers: /etc/sudoers.d/ops]
                [backup unit: backup.service] [x] claude [x] codex [ ] grok [x] agy
                expected user units: disk-clean.timer, fleet-daily-check.timer
                [x] Let agents turn on expected user timers and services
                    that are installed but off              ( Save )
Host2   Needs you 1 · Fixing itself 2 · Done 9
  ...per-host list, needs-you first, done collapsed...
```

Every item carries an owner: **you** (a human must act) or **hub** (fixed or
awaited automatically). Unknown evidence on a configured target is "Waiting for
the first report", not a red light. Fleet defaults remove the per-host forms;
a per-host value still overrides.

### 3.2 Waiting to join (phase 2)

```
Machines > Waiting to join (2)
  Code        Reported host     OS / arch           From            Expires
  KQ7M-42XD   host-b        Ubuntu 26.04 amd64  192.168.x.y      12 min
              Name [Host2]  Profile [Laptop ▾]   ( Approve )  ( Reject )
  P3NF-8H2C   host-c        Ubuntu 26.04 amd64  192.168.x.z      13 min
              Name [Host3]  Profile [Laptop ▾]   ( Approve )  ( Reject )
                                    ( Approve both )   (MFA within window)
```

The name field is prefilled from the reported hostname with the fleet naming
rule (Title case, strip the profile prefix), so display names stay consistent.

### 3.3 Onboarding progress per host (phase 2)

```
Host3 — joining (step 6 of 9)
 ✓ Join approved            ✓ Tailscale up (tag:fleet)   ✓ Agent enrolled
 ✓ Power and sleep          ✓ Sudoers (visudo ok)        ⟳ Apps: hermes, agy, CLIs
 ⟳ Maintenance timers       • Reboot when idle           ! Needs you: agy sign-in (3)
```

### 3.4 Sign-ins (phase 3)

```
Sign-ins waiting (6)                         ( Start all )
  Host2 · agy · slot 1   [Open sign-in ↗]   Code [__________] ( Send )
  Host2 · agy · slot 2   [Open sign-in ↗]   Code [__________] ( Send )
  ...
  Host3 · agy · slot 3   [Open sign-in ↗]   Code [__________] ( Send )
```

The agent starts each CLI login in a private PTY (existing terminal machinery),
captures only the authorization URL, and feeds the pasted code to that PTY once.

## 4. Phases

| Phase | Scope | Removes |
|---|---|---|
| **1 (PR now)** | Readiness split into Needs you / Fixing itself / Done; fleet readiness defaults (path, sudoers, backup unit, expected CLIs, expected user units); opt-in agent self-repair that runs `systemctl --user enable --now` on expected user units that are installed but off; additive API + read-only MCP fields. | 6 form touches, red-light noise, timer drift by hand |
| **2** | `join.sh` + device-style join codes + "Waiting to join" page + Hub-minted one-off Tailscale key; root **fleet applier** shipped in the agent bundle (typed settings only: logind, sleep targets, power profile, journald cap, unattended-upgrades, sudoers template, linger); auto-assigned deployments for profile apps (hermes, agy, standard CLIs) through the existing deploy executors; per-host progress view; reboot-when-idle with one-click consent. | ssh install, password, tickets, token copy, Tailscale approval, sudoers/power/timers/Hermes by hand |
| **3** | Batched sign-in page driven through the agent PTY; channel auto-binding from the profile; MCP tools `onboarding_status` (read) and `join_approve` (write, admin + MFA, Hub UI first). | agy code relays via chat/tmux |
| **4 (optional)** | Tailscale discovery: list tailnet devices tagged `tag:fleet` that are not enrolled, with **Adopt** (Hub pushes a join over Tailscale SSH). Useful for boxes that already run Tailscale. | the paste on such boxes |

Phase 2 starts only after phase 1 is reviewed. Phase 2 needs a Tailscale OAuth
client stored in the Hub secret provider (operator action, once).

## 5. Security notes

**No secrets in URLs or command lines.** `join.sh` is static and public. The
join code shown on the box is not a credential: it only lets the operator
recognise the box in the Hub. The box holds a 256-bit `device_secret` in memory
and polls `POST /v1/join/poll` with it in the body. Enrollment tokens, Tailscale
keys and OAuth codes travel only in TLS request/response bodies or 0600 files,
are never logged, never rendered back, and pages set `Cache-Control: no-store`.

| Credential | Minted by | TTL | Scope | Storage |
|---|---|---|---|---|
| Join code + device secret | Hub on `join/start` | 15 min, single use | lets the box receive its enrollment after approval; max 5 pending, per-IP rate limit | Hub stores hash of device secret |
| Approval | operator in Hub | — | admin + MFA window (existing) | audit row |
| Enrollment token | Hub on approval | 10 min, single use (existing ticket store, hash only) | one machine id | delivered once in poll response |
| Tailscale auth key | Hub via OAuth client (`auth_keys`, tag:fleet only) | one-off, pre-authorised, non-ephemeral, `expirySeconds=600` | joins as tag, not as a user | not stored; box writes 0600, shreds after `tailscale up` |
| Tailscale OAuth client secret | operator once | until rotated | `auth_keys` + one tag | Hub secret provider, admin only |
| CLI OAuth code | operator paste | provider-defined, minutes | one PTY on one host | memory only, forwarded once; audit records "code delivered", never the value |
| Agent credential | existing | existing | one machine | existing |

**Privilege split.** The agent stays unprivileged (`NoNewPrivileges`,
`ProtectSystem=strict`, no sudo). Phase 1 self-repair is user scope only, only
for units the operator listed, only enable/start of units that already exist,
at most once per unit per hour, and only when the fleet default is switched on
(an audited change). Root changes happen in two places only: `join.sh` (the
operator typed `sudo`) and the root fleet applier, which accepts a typed
profile (fixed vocabulary, validated values, templates shipped in the signed
bundle) and never free-form shell. The fleet overlay chooses values; it cannot
add commands.

**Failure modes.** An unapproved join expires silently. A leaked join code
cannot be redeemed without the device secret and an approval. A replayed poll
after redemption gets 410. A Tailscale key that is never used expires in 10
minutes and carries only the fleet tag. The sudoers template is checked with
`visudo -c` before install and the previous file is kept.

## 6. Display names

Display names come from the operator at approval time, prefilled with the fleet
naming rule. Existing hosts keep their names; the operator renames a
lower-case one (for example `host1` → `Host1`) from machine detail. A
readiness item "Name follows fleet naming" can be added in phase 2.

## 7. Not in scope

Sharing one OAuth login across hosts (not supported by the provider; copying
token files is unsafe and re-prompts), BIOS settings, Windows/macOS join scripts
(phase 2 covers Linux; the same join endpoint serves them later), and the
private overlay repository.
