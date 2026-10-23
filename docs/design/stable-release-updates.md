# Hub-Controlled Stable-Release Updates

Status: **Proposed design, docs only.** Nothing here authorizes implementation or deployment.
Owner: the admin. Language: English.
Code baseline: public main `cee5908`, reviewed 2026-10-23; this is not a deployed Hub version.
The generic update protocol, product tables and `/updates` UI below are proposals.
Current release publication signs Hub OCI images only; native agent bundles are not published by
that workflow. U2 therefore includes publishing and verifying signed native release assets.
Existing OpenClaw deployment records keep their current meaning; generic product runs need an
explicit adapter into the rollout driver, not a reinterpretation of existing records.
Builds on: `docs/SPEC.md` rollout/canary rules (M4 canary pause), `docs/CONTROL-PLANE-CONTRACT.md`
(`jobs_enabled` creation gate), `docs/design/HUB-PHASE2-STANDARD-OPS.md` (`ops_approvals` ledger),
`docs/design/token-usage-monitoring.md` (operating principle), `docs/RELEASE.md` (signed releases).

## 1. Operating principle

Same rules as Phase 2 §1A and the token-usage design:

- **Human Hub UI first.** Every capability here (drift view, policy, approve, rollout, rollback)
  is complete in the Hub web UI with no AI agent and no chat notifier.
- **Same action, any caller.** UI, JSON API and MCP (Hermes, Grok Bot acting for the admin) call one
  canonical `updates` operator service under the same scopes, ledger and audit. An agent never gets a
  capability a UI user lacks. V1 mutations and approvals require an authenticated human admin.
  Current service scopes are `view`, `operate`, and `operator-admin` with exact route admission;
  no `updates:approve` scope exists. Delegating update mutations requires a separate reviewed
  authorization contract and defaults off.
- **Optional integrations.** Telegram/Discord are opt-in notifiers over the existing notifier
  ("3 machines drift on OpenClaw", "canary passed, Continue?"). Every notification is also a Hub banner.
  Chat buttons deep-link to the Hub; they do not approve by themselves in v1.
- **Generic public defaults; fleet specifics in the private overlay.** Ring membership, which hosts are
  canaries, per-host policy overrides, maintenance windows, notifier recipients and any GitHub token
  live only in the private overlay. Public code, fixtures and screenshots use no real hostnames.
- **The device is the final authority.** The Hub decides *whether and when*; the device decides *whether
  the bytes are trustworthy*. The Hub can never weaken a device's signature, key or digest checks.

## 2. Goals

1. Agents report installed versions of managed products: `agentic-home`, `bat-agent-connector` (BAT),
   `OpenClaw`, `Hermes`, and `clawctl-agent` itself.
2. The Hub polls each product's GitHub Releases for the latest **stable** release (non-draft,
   non-prerelease, strict SemVer without pre-release suffix) and shows drift per machine and product.
3. Policy per machine × product: `auto`, `approve_each`, or `frozen`.
4. On approval the **agent** fetches the release directly from GitHub, verifies signature and checksum,
   takes a restore point, installs, health-checks, auto-rolls-back on failure, and reports the result.
5. Canary first, then rings, reusing the existing deployment driver and M4 canary pause.
6. One-click rollback to the previous verified version from the Hub.
7. agentic-home is treated as a **managed OS platform** beside Ubuntu and Windows, driven through its own
   trusted update flow; ordinary users do zero technical steps.

## 3. Non-goals

- The Hub does **not** host, proxy, mirror, re-sign or repackage release artifacts in v1.
- No prerelease/beta channels in v1 (a future `channel=prerelease` is listed in §11).
- No OS package updates (apt/Windows Update) — existing maintenance features cover those.
- No arbitrary-version install ("install v1.4.2 from a URL"). Targets are only releases the Hub
  observed on the configured repo **and** that the device can verify.
- No bypass, override or "force" path for agentic-home signature, publisher-key or review checks.
- No updates on machines in monitor-only mode (`jobs_enabled=false`), including fresh Windows join-code
  enrollments, until an admin enables jobs.
- No auto-update of the Hub itself (the Fly deploy skill remains the path for the deployed Hub).

## 4. Managed products

Product definitions are a public catalog with generic defaults; repo owners can be overridden in the
private overlay (e.g. forks).

| product_id | Default GitHub repo | Platforms | Artifact verification | Install mechanism |
| --- | --- | --- | --- | --- |
| `clawctl-agent` | `TED-H-com/AI-Intune` | linux, windows, macOS | proposed signed native assets + SHA256SUMS; current workflow signs Hub images only | staged binary swap + service restart; previous binary kept |
| `agentic-home` | `TED-H-com/agentic-smart-home` | agentic-home | signed device manifests, full locally pinned publisher key (adapter contract to verify) | device bootstrap `--review` / `--apply <review_digest>` (§7) |
| `bat-agent-connector` | overlay-defined | linux, windows | checksum manifest + signature (scheme per product, §11 Q4) | product installer |
| `openclaw` | overlay-defined | linux | checksum + signature | product installer, existing OpenClaw revision recorded |
| `hermes` | overlay-defined | linux | checksum + signature | product installer |

Product-specific mechanisms above are target adapters, not verified upstream availability.
A product without published, independently verifiable assets and a configured signature scheme is **report-only**: drift is shown, but
install jobs cannot be created (typed blocker `unverifiable_product`).

## 5. Data model

New tables (SQLite, same store conventions; all writes audited):

```
product_catalog(
  product_id TEXT PK, display_name, github_owner, github_repo,
  asset_pattern_json,          -- per-platform asset name templates
  verify_scheme TEXT,          -- cosign_keyless | minisign | agentic_home_manifest | none
  verify_identity_json,        -- pinned cert identity / full public key fingerprint (never an abbreviated key ID)
  install_adapter TEXT, enabled BOOL, updated_at)

product_releases(              -- what the Hub saw on GitHub
  product_id, tag, semver, published_at, html_url, release_id, etag,
  assets_json,                 -- name, size, browser_download_url, sha256 if published
  is_stable BOOL, observed_at, yanked_at NULL,
  PK(product_id, tag))

product_latest(product_id PK, tag, observed_at, poll_status, last_error, rate_remaining, rate_reset_at)

machine_products(              -- what the agent reported (latest per machine/product)
  machine_id, product_id, installed_version, install_source, measured BOOL,
  previous_version, restore_point_id NULL, checkin_id, observed_at,
  PK(machine_id, product_id))

update_policies(
  scope_type TEXT,             -- machine | ring | fleet_default
  scope_id, product_id,
  mode TEXT,                   -- auto | approve_each | frozen
  frozen_version NULL, max_major_jump INT DEFAULT 0,
  window_json NULL, reason, set_by, set_at,
  PK(scope_type, scope_id, product_id))

update_rings(ring_id PK, name, ordinal, -- 0 = canary
  soak_hours, members_source)  -- membership from overlay or UI

update_runs(                   -- one per (product, target tag) rollout
  run_id PK, product_id, target_tag, deployment_id, -- reuses rollout driver
  state, created_by, created_at, pause_after_canary BOOL DEFAULT 1)

update_attempts(
  attempt_id PK, run_id, machine_id, job_id,
  from_version, to_version, restore_point_id,
  approval_id NULL,            -- ops_approvals row (Hub side)
  device_review_digest NULL,   -- agentic-home review_digest (device side)
  device_review_expires_at NULL,
  phase TEXT,                  -- queued|fetching|verifying|reviewing|awaiting_approval|applying|
                               -- reboot_pending|health_check|succeeded|rolled_back|failed|expired
  reboot_required BOOL, ai_paused BOOL, ai_resumed_at NULL,
  error_code, error_detail_redacted, started_at, finished_at)
```

Effective policy: any applicable `frozen` rule blocks updates; otherwise choose the most specific
rule, machine → ring → fleet default. Conflicting ring rules block creation until resolved. The proposed
default for every product is `approve_each`. Drift = `installed_version < product_latest.tag`
with `measured=true`; unmeasured is shown as `unknown`, never as "up to date".

## 6. Agent protocol

### 6.1 Reporting (heartbeat)

Add to the check-in payload, versioned and omit-safe like `device_sync_v1`:

```json
"products_v1": true,
"products": [
  {"product_id": "openclaw", "version": "2.3.1", "measured": true, "source": "binary --version"},
  {"product_id": "agentic-home", "version": "2026.10.1", "measured": true,
   "source": "/etc/agentic-home/release", "update_inbox": true, "reconcile": true,
   "trusted_publisher_keys": ["full-publisher-key-fingerprint"]},
  {"product_id": "hermes", "measured": false, "error": "not_installed"}
],
"update_executor_v1": true
```

The Hub must not infer capability from `agent_version` text; omission means unsupported.

### 6.2 Update job

A new job kind `product_update_v1`, created only through the existing gate: latest check-in has
agent `jobs_enabled=true`, Hub execution policy enabled, `update_executor_v1=true`, machine lifecycle active, no conflicting nonterminal
job, and a preview digest pinned to (machine, product, from_version, target_tag, release assets
digest, policy revision). Recheck authorization and execution policy at creation, dispatch and
immediately before applying; a preview is not a reusable grant. Consume an approval exactly once
with job creation, authorizing before idempotency replay. A policy change invalidates stale queued
work and stops running work at the next safe boundary. Payload:

```json
{"kind":"product_update_v1","product_id":"openclaw","target_tag":"v2.4.0",
 "repo":"owner/name","release_id":123,"expected_assets":[{"name":"...","size":1234,"sha256":"..."}],
 "verify":{"scheme":"cosign_keyless","identity":"..."},
 "restore_point":"required","health_check":{"timeout_s":300},"rollback_on_failure":true}
```

Agent steps, each reported as a phase event:

1. **Fetch** directly from the configured GitHub release asset and its explicitly allowed HTTPS CDN redirects (no Hub proxy). Reject unexpected redirect origins and bind the asset to its configured repository and release identity. The
   Hub-supplied SHA256 is a hint for mismatch detection; the trust anchor is the signature verified with
   the identity/key **compiled into or locally configured on the agent**, not sent by the Hub.
2. **Verify** signature and checksum; refuse on any mismatch (`verify_failed`, never retried silently).
3. **Restore point**: copy previous binary/config (or product-native snapshot) to a versioned
   directory; record `restore_point_id`.
4. **Install** via the product adapter.
5. **Health check** (product-specific: service active + version reports target + adapter probe).
6. On failure: **auto-rollback** to the restore point, health-check again, report `rolled_back` or
   `failed` with redacted diagnostics.
7. Report final installed version in the next check-in; the Hub reconciles against reported reality,
   not against the job result alone.

**Rollback job** `product_rollback_v1` targets `restore_point_id` (one-click in UI). Restore points are
kept for the last 2 versions per product.

**clawctl-agent self-update**: staged binary, restart via systemd/Scheduled Task/launchd. An independent
watchdog must observe a check-in with the target version before a configured deadline, restoring the
previous binary if the process exits, hangs, or never checks in. `OnFailure=` alone does not detect a
live but stuck process. Verify this behavior on each supported OS before admitting that platform. Self-update is never batched with another product update.

## 7. agentic-home as a managed OS platform

agentic-home is a proposed managed platform (like `ubuntu`, `windows`). The adapter must verify the
upstream manifest, review/apply, expiry and reconcile contracts against a pinned upstream revision
before implementation. The names and approximate expiry below describe the intended integration;
they are not a claim that this repository has implemented or validated that adapter.

### 7.1 Mapping

| Device concept | Hub concept |
| --- | --- |
| signed `host-update.json`, `controller-update.json` with a full locally pinned publisher key | release assets of `agentic-home` stable release |
| local inbox `/var/lib/agentic-home/update-inbox` (agentic-smart-home PR #126) | where the clawctl agent drops fetched, still-unverified manifests |
| `bootstrap --review` → `review_digest` | attempt phase `reviewing`; digest reported to Hub |
| `bootstrap --apply <review_digest>` | executed only after Hub approval matching that exact digest |
| `--reconcile` (PR #128) | post-reboot / post-failure convergence step and drift self-heal |

### 7.2 Flow

1. Hub approves (policy `auto` or human click) a run for target tag `T` on the machine.
2. Agent downloads the manifests into the inbox. The agent does **not** judge their trust; the device
   bootstrap does, with its own pinned publisher key.
3. Agent runs `bootstrap --review`. The device verifies signatures/keys and emits a `review_digest`
   plus a human summary (components, versions, `reboot_required`). Failure → `verify_failed`, stop.
4. Agent reports digest + summary + expiry to the Hub. The Hub shows exactly that summary.
5. Approval binds to `(machine_id, target_tag, review_digest)`. For `auto` policy the Hub's standing
   approval is bound automatically **only if** the digest's manifest version equals `T` and the
   publisher key is the pinned one.
6. Agent runs `bootstrap --apply <review_digest>`. A digest mismatch is rejected by the device; the Hub
   cannot substitute a different digest.

### 7.3 10-minute review expiry

A `review_digest` is valid ~10 minutes. Design rules:

- For `auto` and pre-approved ring runs, review and apply run back-to-back in the same job; the human
  approval happened earlier at the run level (§8), so no human is in the 10-minute window.
- For `approve_each`, the Hub shows a countdown. If it expires, the attempt goes to `expired` and the
  UI offers **"Review again"**, which reruns `--review` (cheap, read-only) and presents a new digest.
  An approval click is valid only for the digest shown on screen; stale clicks return
  `review_expired`. Optionally (Q2) the human may approve "this tag for this machine", letting the agent
  re-review and apply automatically if the new digest describes the same manifest version and key.
- Clocks: expiry is computed by the device; the Hub displays the device-provided `expires_at` and
  never extends it.

### 7.4 `reboot_required`

- `--review` output declares `reboot_required`. The UI shows it before approval.
- Policy option `reboot: allowed_in_window | ask | never_auto` (default `ask`). With `ask`, apply
  completes staging, phase becomes `reboot_pending`, and the Hub shows "Reboot now / Schedule".
- After reboot the agent runs `--reconcile`, then reports version; success requires the post-reboot
  check-in to report `T`. No check-in within the timeout → `failed`, alert, and (if the device supports
  it) the device's own boot fallback; the Hub does not attempt remote recovery beyond the rollback job.

### 7.5 Paused-AI resume

agentic-home pauses its AI/automation during an update. Requirements:

- Agent records `ai_paused=true` when apply begins and reports it.
- On success, rollback or failure, the agent (or `--reconcile`) must resume AI and report
  `ai_resumed_at`. If AI is still paused N minutes after a terminal phase, the Hub raises a critical
  alert with a **"Resume AI"** button (a fixed, typed job), so a household never stays in a paused
  state silently.
- The resume is idempotent and safe to re-run after reboot.

### 7.6 Zero technical steps for ordinary users

The household user never runs a command. They see, at most, a plain notice on the device/Hub ("An
update is ready — it will restart tonight at 3:00" / "Updated successfully"). All digests, keys and
phases are behind a "Details" disclosure for the admin.

## 8. Canary and rings

Each `update_run` creates a deployment in the existing rollout driver:

- Ring 0 (canary) = 1 machine by default, matching SPEC: first batch is 1, failure pauses, and **canary
  success pauses** (M4, `pause_after_canary=1`) until explicit Continue — for `approve_each`.
- For `auto` products, the Continue after canary is granted automatically only after the ring's
  `soak_hours` (default 24h, SPEC's "one full working day") **and** no silent failures (stale check-in,
  version not reported, AI still paused) in the canary set.
- Any failure or rollback in any ring pauses the run fleet-wide for that product and alerts.
- A newer stable release observed mid-run does not hijack the run; it creates a new run that starts at
  canary again after the old one finishes or is cancelled.

## 9. Security and threat model

### 9.1 Trust boundaries

Hub decides scheduling only. Artifact trust = signature verified on the device with locally pinned
identities. The agent must restrict Hub requests to product-specific, locally trusted artifacts and fixed install
adapters. A signature authenticates the publisher, not the safety of the release: a compromised
publisher or trusted workflow can still publish malicious signed code. A compromised Hub can also
request disruptive legitimate updates; local policy, rollout limits and rollback remain necessary. Mitigations for the residual risk: anti-downgrade (agent
refuses `to_version < installed` except via `product_rollback_v1` to a local restore point), and
`max_major_jump=0` by default (major bumps always need a human).

### 9.2 Threats

| Threat | Mitigation |
| --- | --- |
| Malicious release in an upstream repo (compromised maintainer) | Pinned identity prevents substitution by other publishers, not compromise of that publisher. Canary + soak, local freeze and yank (`yanked_at`) limit exposure; independent review is still needed. |
| Hub sends forged hashes/URLs | agent verifies with its own pinned identity; URLs must match allowed GitHub hosts and the configured repo |
| MITM / CDN tampering | TLS + signature + checksum |
| Hub compromise approves agentic-home apply | device checks locally pinned full publisher key and its own `review_digest`; Hub cannot mint a digest |
| Downgrade / replay of an old signed release | anti-downgrade, monotonic version check; agentic-home manifests' own version rules |
| Stolen operator/MCP token mass-approves | Update approval/mutation routes are human-admin-only in v1; no existing token scope inherits them. Any future delegation requires its own route policy, limits and review. |
| Key rotation (new publisher key) | never auto-accepted; requires a device-local trust update via the product's own flow; Hub shows `untrusted_key` |
| Supply chain of the agent itself | U2 must publish signed native assets and pin their exact issuer/identity locally. RELEASE.md currently covers Hub OCI images; its signatures do not authenticate separate agent downloads. |

### 9.3 GitHub token and rate limits

- Polling uses **unauthenticated** requests by default (60 req/h/IP). With 5 products, ETag conditional
  requests (`If-None-Match` → 304 does not count against the limit when authenticated, and is cheap
  otherwise) and a 30–60 min interval, budget conservatively for pagination, other clients sharing the IP, and retries. Rate-limit headers are authoritative.
- Optional token: a fine-grained PAT or GitHub App token, **read-only, public repositories only**, no
  scopes beyond metadata/contents read, stored as a Fly secret (`fly secrets set`), never logged,
  never sent to agents, never exposed via API/MCP. Configured in the private overlay.
- Agents download release assets without any token (public repos). Agents never receive GitHub
  credentials.
- Respect `X-RateLimit-Remaining/Reset` and `Retry-After`; exponential backoff; poll status shown in UI
  (`ok`, `rate_limited until …`, `error`). On poll failure drift shows "last checked …", not "up to date".
- Asset download load spreads naturally via rings; agents add jitter.

### 9.4 Supply chain notes

- Releases must be `draft=false`, `prerelease=false`, tag strict SemVer; the Hub records `release_id`
  so a re-tagged release (same tag, different id/assets) is flagged and blocks runs.
- Products without a signature scheme are report-only (§4).

## 10. UI

Polished Intune-style pages (see `docs/INTUNE-UI-REFERENCE.md`):

1. **Updates overview** (`/updates`): table per product — latest stable, released date, machines
   current / behind / unknown / frozen, active run status, poll status. Primary action: "Start rollout".
2. **Product detail**: release notes (rendered from GitHub, sanitized), per-machine drift list with
   policy chips, ring view, run history.
3. **Machine detail → Updates tab**: each product's installed vs latest, policy selector
   (Auto / Approve each / Frozen), last attempt with phase timeline, **Rollback** button (with confirm
   showing from→to and restore point time).
4. **Approval card**: what changes, reboot required yes/no, canary results, for agentic-home the
   device review summary + digest + live countdown, "Review again" on expiry.
5. **Run page**: canary → rings progress, pause/continue/cancel, failures with redacted diagnostics.
6. **Alerts**: rollback happened, AI still paused, verify failed, poll rate-limited, re-tagged release.
7. Monitor-only machines show drift and a concise **"Monitor only"** state. Hide update actions that
   the authenticated operator cannot use. Show **"Enable execution"** only when that operator may
   change execution policy, following the existing confirmation flow. Keep protocol digests in the
   structured receipt/details surface, not the primary confirmation copy.

Proposed MCP reads: `updates_list_drift`, `updates_get_run`. Proposed mutation tools
`updates_preview_run`, `updates_start_run`, `updates_approve`, `updates_rollback` require the separately
reviewed delegation phase; v1 mutations use the human-admin Web/CLI/JSON path. Telegram/Discord:
opt-in notifications only. Every workflow must ship its Web, CLI, API, persistence, audit, tests,
documentation and deployment verification before the next visible workflow begins.

## 11. Rollout phases

| Phase | Scope | Exit criterion |
| --- | --- | --- |
| U0 | Reconciled proposal recorded; deployment choices and adapter contracts resolved | decisions recorded before dependent implementation; document merge alone is not approval |
| U1 | Agent version reporting (`products_v1`) + Hub GitHub poller + drift UI (read-only) | drift correct on all fleet machines for 1 week |
| U2 | Signed native release publication + policies + `clawctl-agent` self-update with independent watchdog rollback, approve_each only | 10 successful canary self-updates, 1 forced rollback drill |
| U3 | OpenClaw / Hermes / BAT adapters with signature verification, rings, M4 canary pause | each product updated across rings once |
| U4 | agentic-home platform flow (review/apply digest binding, inbox, reconcile, reboot, AI resume) | drill: expiry, reboot, failed apply, AI resume alert |
| U5 | `auto` policy with soak gates; MCP write tools; optional chat notifications | 30 days with no unattended incident |

Each phase is a separate PR series; no phase deploys to the production Hub without the admin's explicit
ask, following the Fly deploy skill.

## 12. Open questions (admin decides)

1. **Default policy**: `approve_each` for every product (proposed), or `auto` for `clawctl-agent` only?
2. **agentic-home approval granularity**: must a human approve each exact `review_digest` (strict,
   may hit the 10-min expiry), or may they approve "tag T on this machine" so the agent re-reviews and
   applies when the digest matches the same signed version and key (proposed)?
3. **Reboot policy default** for agentic-home: `ask` (proposed) vs nightly window auto-reboot.
4. **Signature schemes for BAT, OpenClaw, Hermes**: do these repos publish signatures/checksums today?
   If not, they stay report-only until they do — acceptable?
5. **GitHub token**: run unauthenticated (proposed) or add a read-only fine-grained token / GitHub App
   as a Fly secret?
6. **Canary hosts and ring membership** (private overlay): which machine is ring 0 for each platform?
7. **Soak time** for auto continue: 24h (proposed) vs one full working day per SPEC wording.
8. **MCP delegation**: retain read-only service-token access for v1 (proposed); any future mutation
   delegation needs exact routes and constraints reviewed separately. Do not assume a new scope exists.
9. **Major version bumps**: always human-only (proposed)?
10. **Restore-point retention**: last 2 versions (proposed) — disk constraints on small devices?
11. **Prerelease channel**: out of scope for v1; wanted later for canary hosts?
