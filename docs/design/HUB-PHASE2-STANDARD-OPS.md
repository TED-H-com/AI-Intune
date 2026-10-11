# Hub Phase 2: Standard Operations

Status: DRAFT — proposed implementation, not authorization to deploy.
Owner: Ted. Scope: Linux fleet operations after Phase 1. Language: English.
Implementation order: disk cleanup, AI login, then application management.

## 1. Operating principle

Use three layers, escalating in this order:

1. SaaS (Intune Hub): deterministic policy, schedules, execution and evidence.
2. Hermes: AI assistant agent on C4; uses Hub MCP through a scoped service token
   for judgment, diagnosis, recommendations and narrowly delegated decisions.
3. Grok Bot by hand: treated as people, explicitly tasked and supervised by Ted.
   SSH and Tailscale always remain available for recovery and exceptional work.

The two big tools are **Intune for operations** and **bat-agent-connector for
development**. Hub actions must not become arbitrary development shell sessions.
BAT's report-only sweep remains a pilot, not authorization for development writes.
Hermes never inherits Ted's admin session, sudo authority or browser credentials.
Grok Bot receives a concrete task, not standing authority to repair every finding.

Public documents use only these host labels:

| Label | Meaning |
| --- | --- |
| W1 | GPU workstation |
| W2 | Corporate-network workstation (proxy) |
| C1–C4 | Cloud VMs |
| C3 | Production web app |
| C4 | Agent-runtime host running Hermes |

The real mapping, addresses, users and notification destinations live only in the
private overlay. APIs authorize immutable machine IDs, never display labels.
Examples, reports committed to this repository and fixtures contain no real hostnames.

## 2. Baseline and references

The Phase 1 design, `docs/design/HUB-AS-HANDS.md`, belongs to draft PR #45,
branch `docs/hub-as-hands`, not main. Its origin ref was unavailable in this
checkout; this draft uses the supplied summary and inspected implementation.

Phase 1 delivered:

- `script_v1`: hash-pinned catalog scripts, read/write modes, `execution_mode`
  pinned in specs and schedules, bounded and redacted execution evidence.
- Scheduler: cron slots, overlap prevention, hash/mode-change pause.
- Scoped service tokens: view/operate, exact route allowlists, read-only scripts
  for tokens, self-rotation with overlap and revocable chains.
- Supervision: `jobs_summary`, `approvals_summary`, `hub_status`.
- BAT sweep report-only pilot. Its catalog mode is **write** because its execution
  behavior is write-equivalent; “report-only” alone does not determine permissions.

| Existing source | Contract to retain |
| --- | --- |
| `docs/MAINTENANCE-DISK-CLEAN.md` | Profile, dry-run/canary gate, summaries and verdicts |
| `docs/MAINTENANCE-TIMERS.md` | PR #40 timers, scope locks and summary paths |
| `docs/FLEET-AI-CLIS.md` | Credential probes, automation wrapper, sanitized checks |
| `docs/OPERATOR-AUTH.md` | Exact grants, service eligibility and rotation |
| `docs/CONTROL-PLANE-CONTRACT.md` | OpenClaw rollout and independent verification |
| `docs/MOVE-AGENTS.md` | Explicit re-enrollment and recovery |
| `ops/install-agent.sh` | Installation, proxy handling and managed-unit guards |
| `ops/maintenance/disk-clean` | Cleaner 1.1.1 and uv lock behavior |
| `ops/fleet/ai-cli/` | Installer, checker and `claude-automation` |
| `ops/fleet/tool-removal/` | Inventory, removal, verification and backups |
| `internal/scriptcatalog/` | Registry, args validation and Linux execution |
| `internal/store/schedules.go` | Slot/job transaction and pause semantics |
| `cmd/clawctl-hub/service_tokens.go` | Authentication, route admission and rotation |
| `internal/operatorclient/token_rotation.go` | Durable private token replacement |
| `internal/probe/probe.go` | Credential source/status/expiry projection |
| `internal/operatoragent/{schema,tools}.go` | MCP registration and supervision |

Existing updates/canary/stable means **OpenClaw release rollout**, not generic
installed-app updates. Generalize its gate principles without changing the meaning
of existing records or weakening the independent verification requirement.
All new IDs, routes, tables, tools and capabilities below are proposals unless
explicitly described as existing. This document changes no code or live policy.

## 3. Shared implementation contract

### 3.1 Catalog, jobs and capabilities

Keep `internal/scriptcatalog` as the build-time allowlist shared by Hub and agent.
Each new entry defines ID, version, SHA256, closed args schema, mode, allowed OS,
run identity, timeout and output cap. Never accept shell strings, executable paths,
URLs or arbitrary environment maps as script arguments.
Args remain at most 4096 bytes, using supported scalars and bounded string arrays.
Larger approved item lists travel as typed manifests referenced by ID and digest.
Proposed GET `/v1/ops-manifests/{id}` requires the assigned machine credential,
active job and digest. Return canonical JSON and a Hub signature bound to that job;
no unassigned manifests, secrets or arbitrary paths may be retrieved. Helper checks
the signature locally, not just the agent-provided claim of authorization.

Today's `run_linux.go` rejects root and uses temporary HOME except for BAT.
Add reviewed per-entry runtime profiles for fixed account HOME/interpreter access;
do not turn BAT's special case into caller-selected environment access.
Resolve the enrolled user locally from trusted configuration, not request data.
Scripts stay agent-user; privileged work goes through separate narrow helpers.
Missing helper or supported adapter returns `PRECONDITION_FAILED`, never a sudo prompt.

Advertise new capabilities: `disk_ops_v2`, `login_session_v1`, `managed_apps_v1`,
`agent_upgrade_v1`. Match the exact last check-in, OS, arch and helper version.
`script_v1` alone does not imply these capabilities or readiness.
Every job binds script hash/mode, args digest, machine and policy revision.
Every approval also binds action, item/manifest digest, deadline and initiator.
Agent revalidates policy, filesystem facts and grant freshness immediately before use.

Normal evidence remains at most 64 KiB, with explicit omitted/truncated counts.
Return typed safe JSON rather than raw command output. Paginate deep-report details
through a bounded structured endpoint; unseen truncated items cannot be approved.
Execution success and the Hub's post-action health verdict remain separate facts.

### 3.2 Scopes, approvals and Hermes delegation

Human `view`, `operate`, `admin` are exact grants, without implied inheritance.
Service tokens remain view/operate plus exact method/route-pattern admission.
Generic token `script_run_preview`/`script_run_apply` remains **read scripts only**.
Schedule create/update/enable/run-now remains human-only; current schedule reads
are also human-only unless a separate route-policy change is reviewed.

A safe cleanup schedule is an admin-approved standing authorization with pinned
policy and script bytes. The scheduler, not Hermes, creates its write jobs.
Add an explicit service-eligibility class only for the new low-risk disk preview
and decision routes. Require operate scope, exact allowlist, allowed machines,
category/byte budgets and an unexpired report digest. Default delegation is off.
No generic write-script route becomes token eligible.

The Hub evaluates policy, records a constrained decision and creates its job in
one transaction. Hermes cannot supply executable args or edit the delegated policy.
Until this boundary is implemented and reviewed, Ted approves every deep action.
All other Phase 2 mutations remain human-admin-only unless explicitly stated.

Proposed `ops_approvals` records pending/approved/rejected/expired/consumed,
actor, machine, operation, policy revision, item digest, deadline and job linkage.
Consume once with job creation; an idempotent retry returns the same receipt.
Authorize before idempotency replay. Policy revocation cancels queued work;
a fresh dispatch grant is required before start. Running work stops at the next
safe item boundary. Approval is never a reusable bearer credential.

### 3.3 API and scheduler conventions

Use canonical operator services behind JSON, UI and MCP with one ledger.
New reads require view; human mutations require admin and preview/apply binding.
`_preview` returns digest, normalized plan, expected revision, expiry and warnings.
`_apply` requires these bindings, reason and idempotency key; returns operation ID,
job IDs, state and replay flag. Stale facts reject with `REVISION_CONFLICT` or
`PRECONDITION_FAILED`; no silent rebasing of approved work.

Existing generic tools are `script_catalog_list`, `script_run_preview`,
`script_run_apply`. Runs take script ID/hash, args, targets, timeout and reason,
plus preview digest and idempotency key on apply. Catalog list returns entries.
Existing schedule tools are `schedule_list`, `schedule_get`,
`schedule_upsert_preview`, `schedule_upsert_apply`, `schedule_set_enabled_preview`,
`schedule_set_enabled_apply`, `schedule_run_now`.
They bind script/hash, args, targets, cron, mode and expected revision.

All cron expressions below use UTC and `catch_up=false`. Preserve current slots,
`skipped_late`, `skipped_overlap`, `skipped_unavailable`, `script_changed` and
`mode_changed`. A missed minute is not replayed; the current scheduler skips it.
Use separate per-host schedules with fixed offsets, not assumed random jitter.
Add a per-machine maintenance lock across ad hoc jobs, schedules, installers and
local fallback; current per-schedule overlap checks alone are insufficient.

### 3.4 Notifications, audit and secrets

Reuse the Hub notifier and `notifications` ledger; implementation entry point is
`cmd/clawctl-hub/notify_builtin.go`. Private config chooses Telegram or Discord.
Also show authenticated UI banners. Normal alerts contain label, operation ID,
severity, safe reason and authenticated detail link, never private host mapping.
Reuse per-condition deduplication and failed-send backoff of 1/2/4/8/16/32/60 minutes.
Send recovery once. Warn after 15 minutes of failed critical-alert delivery.

Login challenge delivery is a separate sensitive payload, not a normal notification
body. Persist session ID, keyed hash, expiry and outcome only. Default delivery is
an authenticated link to a no-store Hub banner containing URL/code.
Direct URL/code delivery is optional to Ted's private configured recipient only,
with explicit acknowledgment of chat retention. Do not persist or log the payload
locally, retry expired challenges, or deliver after success/cancel.

Audit actor/layer, capability, source, policy revision, preview digest, approval ID,
schedule slot, job ID, outcome and timestamps. Never audit device codes, auth URLs,
token values, credential contents, raw stdout, process argv or secret configs.
Short codes use keyed HMAC, not enumerable plain hashes. Credential observations
still contain no token hash; service-token authentication storage remains separate.
Private rollback configs stay on-host in 0700 directories with 0600 files.

## 4. Feature 1 — disk cleanup

### 4.1 Safe tier

Adapt cleaner 1.1.1 through a versioned policy, not arbitrary conf supplied by AI.
Keep `ops/maintenance/disk-clean` and `internal/maintenance/script/disk-clean`
identical when implemented. Preserve `fleet-disk-clean/v1` summary fields and
existing user/root summary files; put new operation metadata in a separate envelope.

| Category | Initial automatic policy |
| --- | --- |
| Tool caches | Native GC only; retain active-process dependencies |
| User tmp / stale test temp | >=10 days, owner-only, no open descriptors or locks |
| `/var/tmp` | >=14 days, root policy and immutable exclusions |
| uv | `uv cache prune`; defer with holders; 60s lock timeout is skipped; never `--force` |
| npm | `npm cache verify`; skip install lock holders; never forced cache clean |
| cargo | Supported native age-aware GC, >=30 days; skip holders/unsupported versions |
| Docker | Dangling images and build cache >=168 hours; no volumes/containers |
| journald | 500 MiB cap, approved vacuum only, no service restart |

Current npm large-cache cleanup uses `npm cache clean --force`; disable/replace
that branch in the Phase 2 adapter before automatic use. Never add uv force flags.
Docker's confirmation `-f` is permitted only for the two fixed age-filtered prune
commands; it does not authorize system prune, all-image prune or arbitrary flags.
Cargo needs a tested versioned adapter, not recursive registry deletion.
Incomplete holder visibility means skipped. Skips are not errors or successes and
never justify automatically killing a process to unlock its cache.

Protection overrides category, policy and approval: credentials and their backups,
`~/.codex/generated_images`, configured protect paths, active models and user data.
Never traverse repositories with uncommitted or unpushed work; unknown upstream or
worktree status is protected. Initially protect every repository root, even clean.
Retain built-in protected names in safe cleanup and tmpfiles exclusions.
The configured protect list is additive and cannot remove these protections.

### 4.2 Catalog and schedules

All following script IDs are new, with reviewed implementation-generated hashes.
Policy IDs resolve immutable revisions, checked against the supplied policy digest.

| Script ID | Mode | Closed args | Output / maximum time |
| --- | --- | --- | --- |
| `disk-safe-preview-v2` | read | `scope:user|root`, `policy_id`, `policy_digest` | Estimates, skips, protections / 600s |
| `disk-safe-clean-v2` | write | Same as preview | Existing summary + job/policy identity / 1800s |
| `disk-deep-report-v1` | read | `policy_id`, `policy_digest`, `max_items:1..500` | Ranked candidates, completeness / 600s |
| `disk-approved-quarantine-v1` | write | `manifest_id`, `manifest_digest`, `approval_id` | Per-item moved/skipped/rejected / 900s |
| `disk-approved-delete-v1` | write | `manifest_id`, `manifest_digest`, `approval_id` | Exact irreversible deletions, Ted only / 900s |
| `disk-quarantine-expire-v1` | write | `policy_id`, `policy_digest` | Approved TTL deletions/skips / 600s |
| `disk-quarantine-restore-v1` | write | `manifest_id`, `manifest_digest`, `approval_id` | Restored/conflicted items / 600s |

Generic script apply rejects action scripts without their approval/job binding.
Knowing a manifest ID grants nothing. Safe-clean needs a standing schedule grant
or human preview/apply. Root cleanup uses a fixed policy-verifying helper installed
by Ted; today's agent-user executor cannot simply run root scope.
Without that helper retain the local root timer and mark it `local-owned`.
Root deep inventory needs a fixed read-only helper or returns incomplete/unknown.
Do not label the existing cleaner dry-run read-class without adapting it: current
execution can write locks/logs/summaries. The new preview performs pure observation
and returns JSON; the apply adapter retains existing locking/summary behavior.

| Schedule | UTC baseline | Authority |
| --- | --- | --- |
| Root safe cleanup | `40 3 * * *` | Admin standing policy; helper-ready targets |
| User safe cleanup | `30 4 * * *` | Admin standing policy per enrolled user |
| Weekly deep report | `30 5 * * 0` | Read only, bounded scan |
| Quarantine expiry | `10 6 * * *` | Previously approved manifests only |
| Pressure detector | Hub minute reconciliation | Enqueue read report at fresh usage >80% |

Use per-host minute offsets 0/5/10/15/20/25, normalizing hours in private config.
Coalesce weekly/pressure scans; maximum one deep scan per host per six hours.
Pressure enqueue needs a persisted conditional-trigger slot; existing cron alone
cannot implement it. Ignore pressure observations older than 15 minutes.

### 4.3 Deep analysis: report-only, no application writes

The scanner writes no files, summaries, caches or manifests; it emits typed JSON
for the Hub to store. Executor-private script staging is not an application write.
Use no-atime reads where supported; skip content hashing if it would alter atime
without permission. Never run commands that refresh caches, credentials or indexes.
Scan only reviewed roots, without following symlinks or crossing mount boundaries.

Required discovery categories:

- App-update backups: `*.bak`, `*.old`, `*.orig`, `~/clawctl-agent-backup-*`,
  `/usr/local/bin/*.bak-*`; exclude active rollback generations and secret backups.
- Installer leftovers: `/tmp/clawctl-up`, staged bootstrap tarballs and abandoned
  downloads; require no active installer transaction/process holder.
- Old release/build directories, compared against current and rollback manifests.
- Unused tagged Docker images, checking stopped containers and rollback references;
  bind immutable image digest, not mutable tag alone.
- Large caches and ML models, with last-access evidence and model/service leases.
- Orphaned processes holding temp/locks, including a stuck `codex-linux-sandbox`
  holding temp on W1; report PID, boot ID/start time, owner and holder count only.
- Old agent session stores, e.g. `~/.codex/sessions`, grouped by age.
- Duplicate archives, verified by bounded content hashing; equal name/size is weak
  evidence and cannot alone establish duplication.

Protected candidates appear only as excluded aggregates, never actionable paths.
Keep blanket backup-name protection in the safe tier. A dedicated deep adapter may
classify obsolete non-secret backups without weakening the original cleaner rules.

Each item has ID, machine, category, private path reference, allocated/logical bytes,
last-used timestamp/source, owner UID/app, confidence (high/medium/low), suggested
action, reversible flag, exclusion reason, scan time and policy revision.
Bind device/inode/type/size/mtime/ctime, holder facts and app-generation references.
Atime under relatime/noatime is weak evidence; unknown last use stays unknown.
Rank by reclaimable allocated bytes, then confidence and age; unknowns rank last.
Deduplicate hardlinks/shared layers; distinguish estimates from measured bytes.
Stop at 500 candidates, 200,000 metadata entries, 600s or configured I/O budget.
Report truncation and inaccessible roots; partial evidence never means clean.

Add a typed report channel separate from capped stdout: proposed POST
`/v1/disk-reports/{job_id}/chunks` and POST `/v1/disk-reports/{job_id}/complete`.
Agent supervisor streams scanner records without writing them on-host. Authenticate
the assigned machine/job; limit 64 KiB per chunk, 2 MiB total and 500 items.
Sequence numbers and chunk digests deduplicate retries; complete binds the canonical
report digest and item count. Only finalized reports can produce action previews.
Keep stdout as a safe summary with report ID/digest. Hub stores private item paths
in restricted report records, not audit; ordinary MCP projection uses item IDs and
sanitized display paths. Retain reports 30 days, extending referenced manifests
until quarantine/restore closes; expired incomplete uploads are removed after 24h.

### 4.4 MCP, exact approval and quarantine

Proposed prefix: `/v1/operator/disk-ops`.

| MCP tool | Inputs | Outputs / route |
| --- | --- | --- |
| `disk_ops_status` | `machine_id` | Usage, summaries, skips, ownership; GET `/status/{machine_id}` |
| `disk_report_get` | Report ID, cursor, limit <=100 | Safe ranked items, digest/completeness; GET `/reports/{id}` |
| `disk_action_preview` | Report ID, item IDs <=100, quarantine/delete, reason | Manifest digest, eligibility, expiry; POST `/actions/preview` |
| `disk_action_decide` | Preview digest, decision, revision, reason, idempotency key | Approval/job receipt; POST `/actions/decide` |
| `disk_restore_preview` / `disk_restore_apply` | Quarantine ID, exact item IDs, common write bindings | Restore plan/receipt; POST `/restores/preview`, `/restores` |

Reads need view. Human preview/decision/restore needs admin. Delegated preview and
decision need operate plus explicit route eligibility and identical low-risk checks
on both calls. Restore and direct deletion are never delegated. No raw paths/commands.

Optional Hermes policy: quarantine only, agent-user-owned installer staging >14 days
or reproducible cache artifacts >30 days; high confidence, complete holder evidence,
known owner app, same-filesystem rename, no secrets/user data or active references.
At most 100 items/1 GiB per decision and 2 GiB per machine per UTC day; one active
decision per machine. Budgets span all Hermes token chains to prevent splitting.
Exclude root files, backups, session stores, models, tagged Docker images and PIDs.
Ted approves everything outside this policy; prohibited paths remain prohibited.
Process termination is separate Ted-supervised work, never a cleanup action.

Approval expires after 30 minutes; source report must be <=6 hours old.
Digest binds sorted exact item identities, action, TTL, target, report and policy.
Before acting, re-stat without following links, recheck holders/protection and use
directory-descriptor resolution. Changed items are skipped pending fresh approval;
never substitute a path or expand a glob. Signed item manifests travel on the
machine-authenticated job plane; audit stores IDs/digests, not filesystem paths.

Quarantine TTL defaults to seven days. Same-filesystem atomic rename to private
trash preserves identity; root trash stays root-owned. Durably journal each move.
Quarantine does **not** free blocks: report quarantined bytes separately from disk
space recovered. Pressure never authorizes shortening TTL automatically.
Cross-filesystem operations, image deletion and other non-reversible actions need
Ted's explicit delete approval; offer export/restore proof where feasible.
TTL expiry is covered by original approval but rechecks holds, protections, manifest
identity and policy revocation. Restore refuses occupied destinations, never overwrites.

### 4.5 Supervision, security, tests and transition

Warn at >=85% usage; critical at >=93%; deep report triggers strictly >80%.
Measure `/` and configured data mounts independently. Clear after two readings
five minutes apart below threshold minus two percentage points. Missing is unknown.
Require fresh post-clean evidence to claim recovery. Today's local daily-check
uses 95% critical: migrate it to 93% explicitly and disclose interim disagreement.
Warn at summary age >48h, two consecutive lock skips, truncated scans or approvals
pending >24h. Critical pressure alerts immediately and repeats unresolved at 6h.
Track freed/quarantined bytes, skips, holders, runtime, protection denials, TTL backlog
and restore success. Hermes reviews evidence; Grok Bot investigates exceptional
locks/processes through Ted's explicit task, using SSH when needed.

Security focus: path races, bind mounts, symlinks/hardlinks, incomplete holder views,
manifest replay, privileged helper boundary, cache side effects and model leases.
Tests cover all candidate/protection categories, dirty/unpushed repos, uv timeout as
skip, no uv force, npm safe branch, Docker age/no-volume rules, inode substitution,
budget splitting, interrupted rename/restore, TTL holds and single approval consume.
Prove deep scans leave fixture content/mtime/atime unchanged.

Migration: import local conf as typed policies without secrets; run one canary
preview and compare summaries for a week. Install root helper separately.
Disable a local apply timer only after replacement ownership is recorded and Hub
schedule is ready. Keep existing summary readers and daily-check evidence.
Inventory tmpfiles rules separately: they act independently of cleaner DRY_RUN.
Align protections/ages without pretending disabling the cleaner stops tmpfiles.
Rollback: disable Hub schedules/triggers, cancel grants, restore prior policy and
local timer ownership, then re-enable saved timer units. Restore trash by manifest.
Native cache GC/journal vacuum cannot be undone; stop further deletion instead.
Keep existing maintenance routes usable until each host's v2 migration succeeds.

## 5. Feature 2 — AI login and credential continuity

### 5.1 Observation and early warning policy

Preserve provider/status/expires_at/source and the renewal-stopped history heuristic.
The historical `gemini` slot means agy. Refreshable agy normally has no expires_at;
its one-hour access-token expiry is not a re-login warning. Claude automation has
no encoded expiry. Do not change probe classification to expires-soon solely
because a refreshable access token has little remaining lifetime.
New Hub health projection adds advisory reason, last observation/expiry advance,
refreshability and optional human-recorded renewal deadline, without token data.

| Provider/source | Warning / urgent defaults |
| --- | --- |
| Grok known non-refreshing expiry | 7 days / 24 hours |
| Codex known non-refreshing expiry | 7 days / 24 hours |
| Grok/Codex refreshable or unknown | No expiry-only page; renewal-stopped warning after >=3 unchanged observations spanning 24h and expired deadline |
| agy refresh token present | No access-expiry warning; invalid file/auth failure warns |
| agy without refresh token | 24 hours / 1 hour before known expiry |
| claude-automation | Remind day 60 after recorded setup; urgent day 75; unknown age asks baseline |
| Claude actual recorded deadline | Additionally 14 days / 3 days before deadline |
| Hermes service token | Rotate <=14 days remaining; warn <=7 days, urgent <=24h if unsuccessful |

Claude age reminders are policy, not invented token expiry. An earlier actual
recorded deadline takes precedence. Warn at unknown credential state >24h;
confirmed auth failure affecting scheduled work alerts immediately.
Renewal-stopped remains advisory; an approved bounded auth check confirms failure.
No paid periodic live prompts by default. Metadata alone does not prove login success.
When live verification is required, login preview discloses the single bounded
provider request and possible usage cost; Ted's start approval must include it.
If not approved and no supported status command proves auth, return
`verification_required` as a verifying substate until manual confirmation or timeout,
not succeeded. Generic read scripts cannot opt into that request.

### 5.2 Detached re-login protocol

Ted selects machine/provider and authorizes start re-login. Hermes recommends and
monitors, but its existing token cannot start or cancel login sessions.
Proposed `login_sessions` holds machine, provider, adapter version, state, deadline,
job link, challenge HMAC/expiry, safe error and final probe timestamp.
States: requested -> starting -> awaiting_user -> verifying -> succeeded;
alternatives failed/timed_out/cancelled. One active session per machine/provider;
idempotency retries return the same session.

Agent starts a fixed transient systemd user unit with private 0700/0600 runtime
state and bounded lifetime. A supervised PTY parser owns provider output; disable
journal/stdout persistence. Raw terminal bytes never enter generic script evidence,
logs or crash reports. Tmux is an explicitly tested fallback with a private socket,
logging/history disabled and no surviving interactive shell after completion.

| Provider | Fixed invocation or adapter |
| --- | --- |
| Grok | `grok --device-auth`; parse verification URL and user code only |
| Codex | `codex login --device-auth`; parse verification URL and user code only |
| agy | Pinned-version agy login adapter, capability-tested supported flow |
| Claude automation | Guided `claude setup-token`, private local completion below |

These are adapter requirements, not a claim every installed version supports them.
Unsupported agy/device flow returns `manual_required`, never invented flags or a
public tunnel to a loopback callback. Ted completes that flow privately on-host.
Automation never completes consent or enters credentials on Ted's behalf.

Proposed machine route `POST /v1/login-sessions/{id}/challenge` binds authenticated
machine, session and job. Accept bounded codes and HTTPS URLs matching the adapter's
exact provider host/path/query allowlist; reject arbitrary links and redirects.
Raw challenge lives only in agent/Hub memory until expiry; database stores HMAC.
Hub restart invalidates the challenge, cancels session and requires a fresh start.
Ted's authenticated human UI reveals it with no-store, no analytics, no referrer
leakage, no browser persistence and no challenge embedded in the page URL.

Default deadline is 15 minutes; hard maximum is 20 minutes or provider expiry,
whichever comes first. After provider completion, re-probe every 15 seconds.
Success needs provider exit success and a fresh valid observation of the intended
credential source; if metadata cannot establish authentication, require an approved
bounded provider status/live check. File existence is never sufficient.
On terminal state terminate only that session scope, remove runtime state and
cancel queued sensitive deliveries. Agent restart reconciles scopes and expires
stale sessions; it never automatically starts login or deletes valid credentials.

`claude setup-token` may output a long-lived token: do not use the generic URL/code
relay. Initial adapter returns guided manual completion. Ted runs it in a private
host terminal and writes `~/.config/claude-automation/oauth-token` privately at
0600 without token values in command arguments. A future local-only capture
adapter requires separate review; Hub would still receive metadata only.
Never promise silent Claude token rotation. Never run bare `claude -p` on Oracle/C
hosts; use `~/.local/bin/claude-automation`. Apply that wrapper rule to all automation.
Never export tokens in rc files, job args, notifications or persisted PTY logs.

### 5.3 Catalog, tools, scopes and schedules

| Script ID | Mode | Closed args | Output / maximum time |
| --- | --- | --- | --- |
| `ai-credential-report-v1` | read | `providers` bounded enum array | Sanitized metadata / 60s |
| `ai-cli-check-v1` | read | `providers` | Version/PATH/hygiene metadata / 120s |
| `ai-login-start-v1` | write | `session_id`, `session_digest` | Accepted/state only / 30s |
| `ai-login-cancel-v1` | write | Same as start | Cancelled/already terminal / 30s |

Start hands off to the agent supervisor; generic job completion is not login success.
Read adapters avoid legacy checker temp files and any credential-refreshing commands.
Paid live validation is a separate human-approved action, not a read-script flag.
Session scripts require server-issued session/job binding even for generic callers.

Proposed prefix `/v1/operator/ai-login`:

| MCP tool | Input | Output / route |
| --- | --- | --- |
| `ai_credentials_status` | Machine ID | Health/lead times; GET `/credentials/{machine_id}` |
| `ai_login_start_preview` / `ai_login_start_apply` | Machine, provider, common write bindings | Session plan/receipt; POST `/start/preview`, `/start` |
| `ai_login_status` | Session ID | Safe state/expiry/next step; GET `/sessions/{id}` |
| `ai_login_cancel_preview` / `ai_login_cancel_apply` | Session, common write bindings | Plan/receipt; POST `/cancel/preview`, `/cancel` |

View reads may be allowlisted for Hermes; start/cancel require human admin.
No MCP output includes codes/URLs/tokens. Proposed GET
`/v1/operator/ai-login/sessions/{id}/challenge` is human-admin-only with no-store,
matching the initiating human or Ted's explicit recovery authority. It returns
URL/code/expiry from memory, never from evidence; service tokens are ineligible.
Metadata reports run `17 */6 * * *`; CLI hygiene runs `20 7 * * *`, with offsets.
Check-in probes stay primary; Hub evaluates warnings each minute. Never schedule login.
Hermes self-rotation uses `ops/hermes/README.md` and existing GET
`/v1/operator/service-tokens/self`, POST `/v1/operator/service-tokens/rotate`.
Preserve 10-minute predecessor overlap, chain deadlines, rate limits and atomic
private-file replacement; warn before a chain deadline needs Ted's reissuance.

### 5.4 Supervision, tests, migration and rollback

Track completion latency, timeout/cancel rate, stale observations, provider auth
failures, renewal reminders and rotation failures, without challenge contents.
Warn after 10m awaiting user, two failed starts or report age >24h; urgent for
expired required credentials or failed Hermes rotation within 24h of expiry.
Three failed starts per provider/machine/hour blocks more starts pending Ted review.
Hermes triages/reminds; Grok Bot helps private host setup only when explicitly
asked and never copies token output into its conversation transcript.
Security focus: PTY isolation, phishing URLs, short-code disclosure, cross-machine
access, chat retention, restart cleanup and credential overwrite races.
Tests include split prompts/ANSI escapes, tokens adjacent to codes, malformed URLs,
no raw error output, cancel/expiry races, Hub/agent restart, invalid permissions,
agy refreshability, unknown Claude expiry and existing rotation recovery cases.
Assert secret fixtures absent from logs, audit, evidence, notifications and DB dumps.
Migration records existing metadata and renewal dates, leaving unknown dates unknown.
Keep manual private login until each adapter passes; pilot one provider/host then
W2 proxy behavior. Reuse wrapper and sanitized rc-hygiene checks.
Rollback disables starts/advisories, cancels sessions and retains valid credentials;
return to private manual login. Revoke suspected leaks separately, never restore
an old credential copy automatically.

## 6. Feature 3 — managed apps and agent self-upgrade

### 6.1 Per-host desired state

Add revisioned `managed_apps`, keyed by machine ID/canonical app ID: presence,
target (pinned version or channel), resolved artifact digest, platform, upgrade
adapter/version, health policy, rollback descriptor, owner layer, maintenance
window and adoption evidence. Resolve channels to exact versions before preview;
execution never resolves latest. Secret configs stay local, referenced by identity.

| App ID | Upgrade method | Health / rollback | Owner layer |
| --- | --- | --- | --- |
| `clawctl-agent` | Signed arch bundle + fixed helper | Version/check-in; durable binary/unit/config | Hub |
| `claude`, `codex` | Pinned npm in versioned prefix | Version/wrapper/PATH; prior prefix | Hub |
| `agy`, `grok` | Verified pinned release adapter | Version/probe; prior binary/tree | Hub |
| `openclaw` | Existing artifact deployment | Existing independent gate; prior artifact/config | Hub |
| `bat-server`, `bat` | Pinned release/package adapter | Endpoint/session continuity; prior release | Ted/development |
| `bat-agent-connector` | Pinned reviewed tree digest | Connector read probe; prior tree | Ted/development |
| `hermes` | Pinned package/image on C4 | Process/Hub MCP read; prior package/config | Ted |
| `cloudflared` | Pinned binary/package | Tunnel health; prior binary/config | Ted |
| `tailscale` | Pinned package with recovery window | Independent connectivity; prior package/config | Ted |

Declare only apps needed on that host, not the entire list everywhere.
W2 references private proxy config; C3 has explicit production windows.
Owner layer defines responsibility, not approval bypass. Hermes cannot upgrade its
own runtime, connector, service-token policy or Hub.
Durably back up previous binary/config before every mutation. Keep two successful
generations for >=14 days plus pinned rollback generations; protect them from cleanup.
Temporary installer backups do not satisfy this contract.

Unmanaged discovery adapts sanitized `ops/fleet/tool-removal/inventory.sh` sources:
packages, system/user units, containers and ports. No arbitrary regex scans via MCP.
`app_decisions` stores immutable evidence, owner/confidence and pending/adopted/
remove_approved/ignored state. Ted chooses adopt or remove; unknown provenance blocks
mutation. Adoption snapshots actual state and rollback feasibility before enforcement.
Removal needs exact manifest, dependency/service impact and separate approval;
retain user data by default.

Orca is retired: immutable canonical `orca` denylist applies at desired-state write,
dependency resolution, adapter execution and post-install inventory. Reviewed aliases
cover package identities. Detection alerts Ted and creates a removal decision;
never auto-adopt or reinstall it, even as a rollback dependency. An ignore decision
cannot suppress its alert or override the denylist.

### 6.2 Catalog, MCP and schedules

| Script ID | Mode | Closed args | Output / maximum time |
| --- | --- | --- | --- |
| `apps-inventory-v1` | read | `policy_id`, `policy_digest` | Sanitized inventory / 120s |
| `app-upgrade-plan-v1` | read | `manifest_id`, `manifest_digest` | Preconditions/backup feasibility / 120s |
| `app-upgrade-apply-v1` | write | Manifest ID/digest, approval ID | Stage/swap/health/rollback / 1800s |
| `app-health-v1` | read | `app_id`, `generation_id` | Version/health / 120s |
| `app-rollback-v1` | write | Manifest ID/digest, approval ID | Restored generation/health / 900s |
| `app-remove-v1` | write | Manifest ID/digest, approval ID | Removed/retained items / 900s |
| `agent-self-upgrade-v1` | write | Manifest ID/digest, approval ID | Durable handoff receipt / 120s |

Manifest specifies exact adapter/artifacts, target, prior generation, health checks,
deadline, recovery authority and allowed paths. Network shell installers must become
pinned reviewed adapters before automation; an app ID does not authorize root hooks.

Proposed operator prefix `/v1/operator/apps`:

| MCP tool | Input | Output / route |
| --- | --- | --- |
| `apps_status` | Machine, optional app | Desired/observed; GET `/status/{machine_id}` |
| `apps_desired_preview` / `apps_desired_apply` | Entries, expected revision, common bindings | Plan/revision; POST `/desired/preview`, `/desired` |
| `apps_rollout_preview` / `apps_rollout_apply` | App, revision, targets, canary, window, common bindings | Plan/rollout ID; POST `/rollouts/preview`, `/rollouts` |
| `apps_rollout_get` | Rollout ID | Gates/results; GET `/rollouts/{id}` |
| `apps_rollout_continue_preview` / `apps_rollout_continue_apply` | ID/control revision, common bindings | Batch plan/receipt; POST `/continue/preview`, `/continue` |
| `apps_rollback_preview` / `apps_rollback_apply` | Rollout, generations, common bindings | Recovery plan/receipt; POST `/rollback/preview`, `/rollback` |
| `apps_decisions` | Machine, cursor | Decision queue; GET `/decisions` |
| `apps_decision_preview` / `apps_decision_apply` | Item, adopt/remove/ignore, evidence digest, common bindings | Plan/receipt; POST `/decisions/preview`, `/decisions` |

Reads are view/token-allowlist eligible; mutations stay human-admin-only.
Hermes proposes timing/explains drift; Grok Bot handles Ted-approved exceptions.
Inventory runs `45 7 * * *`; health runs `*/15 * * * *` with host offsets.
Upgrades are not scheduled by default. Any later standing rollout must approve
exact artifact, targets and window, never unlimited moving-channel updates.

### 6.3 Canary-to-fleet and rollback

States: planned -> canary_running -> canary_soaking -> awaiting_continue ->
fleet_running -> complete; alternatives paused/rolling_back/rolled_back/
manual_intervention. Persist `app_rollouts` separately from OpenClaw deployments;
OpenClaw entries reference their existing ledger and independent verifier gate.
Snapshot targets/exact versions; select low-impact C1 or C2 only after private role
review, never default C3/C4. Require healthy preflight, backup, disk and mutation lock.
Run one canary, verify functional health/version, soak 24h, then Ted continues with
fresh evidence/control revision. Add representative arch/proxy cohort canaries.
Proceed one host at a time, C3/C4 last in separate supervised windows.
Health checks at 30s/2m/5m require fresh post-upgrade check-in and two passes >=60s
apart, plus app-specific independent evidence. Failed health blocks promotion;
unavailable evidence retries to the 5m deadline then rolls back. Any rollback pauses
fleet. No automatic retry of that release. Original approval binds rollback authority
and exact prior generation. Incompatible data-schema downgrades remain manual.

### 6.4 Narrow agent upgrade helper

Today Ted downloads an admin-only bootstrap bundle, verifies SHA256 and runs
`ops/install-agent.sh` per host. Without podman use `--no-container-runtime`;
unmanaged OpenClaw units stay alone. W1/W2 require Ted's sudo password.
Normal upgrades have no durable rollback guarantee; inspected staging uses temporary
files for re-enrollment recovery. Durable backup support must precede automation.
Self-upgrade never re-enrolls or changes Hub URL/machine identity.

1. Ted installs root-owned helper once on W1/W2 and other eligible hosts.
   Sudoers allows exactly `/usr/local/libexec/clawctl-agent-upgrade ""`, meaning
   no arguments, no preserved environment, shell or editor. Test actual sudo
   empty-argument matching and reject wildcard rules.
2. Agent uses its own credential for proposed GET
   `/v1/agent-upgrades/{job_id}/bundle`. Bind machine, active job, arch and digest;
   existing admin bootstrap download remains admin-only.
3. Job pins SHA256 and signed manifest containing job/machine/arch/version/digest,
   expiry and prior generation. Helper verifies locally pinned release and Hub
   authorization keys; checksum alone is not independent authenticity.
4. Download unprivileged with size bound, no redirects outside Hub, no archive
   traversal/symlinks. Never run downloaded `install-agent.sh` as root in this path.
5. Invoke no-argument helper with bounded manifest on stdin. It uses fixed staging,
   copies verified descriptors to root-private storage and re-verifies copied bytes;
   no caller-selected source/destination paths.
6. Lock upgrades, journal under `/var/lib/clawctl-agent-upgrade/`, fsync durable
   previous binary/unit/config and hashes. Private config backup remains bound to
   the same Hub identity. Insufficient backup space aborts before mutation.
7. Stage root-owned binary on destination filesystem, fsync, atomic rename to
   `/usr/local/bin/clawctl-agent`; restart only the fixed agent unit. Preserve proxy
   drop-ins, container policy and unmanaged OpenClaw units.
8. A root-owned watchdog survives restart/reboot. Hub confirms exact version and
   fresh check-in, returning a signed transaction health receipt within five minutes.
9. Missing/failed receipt makes helper restore prior binary and changed managed
   unit/config and restart, including on Hub outage. Recovery depends on neither
   Hermes nor the new agent. One failed recovery becomes manual intervention.
10. Persist outcome for next check-in; reconcile interrupted job lease by transaction
    ID, never repeat a completed swap because final acknowledgment was lost.

Helper updates and signing-key rotation are separate Ted-approved operations.
Tailscale/cloudflared upgrades need independent watchdog/out-of-band access too;
never upgrade both access paths in the same window.

### 6.5 Supervision, security, tests and transition

Track drift age, unmanaged count, canary wait, rollback rate, backup health,
check-in delay and denylist detection. Warn drift >24h, queue age >7d or missing
backup; critical for production health failure, no check-in >5m after swap,
rollback failure or any Orca detection. One canary failure halts rollout;
>=2 upgrade failures/24h across rollouts disables automatic writes pending Ted review.
Security focus: cross-machine downloads, signatures, downgrade/replay, archive paths,
sudoers matching, staging races, secret backups, package hooks and network lockout.
Tests exercise wrong arch/digest/signature, expired grants, cross-machine denial,
symlink/hardlink staging, power loss at every journal step, missing-check-in rollback,
old/new agent reconciliation, proxy preservation, no-container-runtime behavior,
unmanaged OpenClaw preservation, Orca aliases/dependencies and promotion gates.
Migration starts inventory-only; Ted adopts recoverable apps. Add durable installer
backups before helper upgrades. Pilot a cloud VM, then W1/W2 after helper bootstrap
and demonstrated restoration. Keep manual installer/SSH recovery available.
Do not combine Hub migration with upgrade; `docs/MOVE-AGENTS.md` remains authoritative.
Rollback freezes rollouts, restores pinned generations and independently checks
health. Preserve audit/transactions; check schema compatibility before Hub downgrade.
Disable helper admission without removing recovery backups.
Hermes reviews drift, gates and rollback receipts through view tools only. Grok Bot
receives a specific repair/recovery task from Ted and reports independent evidence;
it cannot silently bypass a failed canary or change desired state outside the ledger.

## 7. Cross-feature supervision and Fly-outage fallback

Every 15m Hermes reads existing `jobs_summary({kind,machine_id,window,per_machine})`,
`approvals_summary({window})`, `hub_status({})`; supported windows are 24h/7d.
Extend projections with feature metrics and persisted pending-approval age/counts.
Today's unavailable metrics stay null until backed by a ledger; null is not zero.
Keep evidence source/sample count on rates. Warn at >=3 failures among >=10 terminal
jobs/24h; >=5 security denials/minute or a cross-machine attempt pages Ted and
suspends delegation. Hermes summarizes daily; Hub sends urgent notifications directly.

C4 has an independent watchdog and separate private notifier credentials.
Three failed one-minute Hub probes raise outage; five healthy probes clear it.
Use a second observer to distinguish C4 network failure where available, otherwise
report uncertainty. During Fly outage Hermes reports cached evidence age and starts
no mutations. Local rollback watchdogs continue; bounded active cleanup may finish.
Cached grants never authorize new starts; detached login scopes expire locally.

Ted may activate retained local cleanup timers via SSH during prolonged outage,
recording a local ownership epoch and disabling Hub execution admission on-host.
On reconnect reconcile that epoch before enqueueing work; never blindly re-enable
schedules or replay missed slots. Backfill summaries with original timestamps and
mark evidence gaps. C4 is not a second Hub writer or approval authority.
If C4 also fails, Ted uses SSH/Tailscale with Grok Bot by hand. Private recovery
instructions and address mappings remain outside the public repository.

## 8. Delivery milestones and PR breakdown

| Phase / PR | Deliverable | Exit criterion |
| --- | --- | --- |
| P2-01 | Policies, approval ledger, capabilities/runtime profiles | Denial/replay/revocation tests; writes disabled |
| P2-02 | Safe disk adapters/root helper/summary compatibility | Safety fixtures and canary dry-run parity |
| P2-03 | Deep report and conditional pressure trigger | No-write proof, bounded scan/protection |
| P2-04 | Manifest/quarantine/restore and optional Hermes decision | Race/budget tests, restore drill, security review |
| P2-05 | Timer handoff and disk alerts | Week canary, 93% critical, one apply owner |
| P2-06 | Credential advisories and sensitive transport | No-secret persistence; starts disabled |
| P2-07 | Provider adapters/UI/notifier/cancel recovery | Ted completes supported flows; Claude manual guide |
| P2-08 | App inventory/desired/adoption/Orca denylist | Coverage complete, unknowns explicit |
| P2-09 | Durable installer backups/helper/watchdog | Power-loss and missing-check-in recovery |
| P2-10 | App rollout adapters/gates | Canary soak, automatic rollback, access-path drill |
| P2-11 | Supervision/outage recovery | Fly/C4 exercises and ownership reconciliation |

Review security before enabling delegated approvals, root cleanup, login transport
or upgrade helper. Ship default-off gates. Each PR updates relevant source docs,
MCP schemas, route manifest and tests; run focused Go packages/shell fixtures and
`go test ./internal/scrubguard`. Ted approves concrete policy and canary evidence
before fleet enablement. Separate implementation from deployment; never merge
without Ted's request.

## 9. Open questions for Ted

- Enable the proposed bounded Hermes quarantine policy or remain human-only?
  Default is human-only; no delegation inferred from this draft.
- Telegram or Discord private recipient? Default login delivery is a banner link;
  direct short-lived codes require explicit acceptance of chat retention.
- Confirm Claude renewal reminders and record existing setup dates privately.
- Select C1/C2 canaries after workload review and C3/C4 maintenance windows.
- Approve seven-day quarantine TTL and capacity; no emergency automatic TTL reduction.
- Confirm helper-eligible hosts and one-time W1/W2 sudo bootstrap/recovery access.
- Decide signing-key custody/recovery before helper rollout.
- Confirm pinned app sources/ownership, especially BAT, agy and Grok; unsupported
  adapters remain inventory-only.

## 10. Summary matrix

| Feature | Catalog scripts | Schedules | MCP tools | Scope | Approval | Hermes role | Grok Bot role |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Disk safe | `disk-safe-preview-v2`, `disk-safe-clean-v2` | Daily root/user | Generic scripts/schedules, `disk_ops_status` | View; admin setup | Ted standing policy after canary | Review pressure/skips | Investigate exceptional locks with Ted |
| Disk deep | `disk-deep-report-v1`, `disk-approved-quarantine-v1`, `disk-approved-delete-v1`, `disk-quarantine-expire-v1`, `disk-quarantine-restore-v1` | Weekly/>80% report; daily approved TTL | `disk_report_get`, action preview/decide, restore preview/apply | Operate only for explicit low-risk delegation; otherwise admin | Exact digest; Ted outside policy | Rank/recommend; bounded quarantine decisions | Supervised recovery/process investigation |
| AI login | `ai-credential-report-v1`, `ai-cli-check-v1`, `ai-login-start-v1`, `ai-login-cancel-v1` | Six-hour metadata/daily hygiene; no login schedule | Credentials status; login start/status/cancel | View; human admin mutations/reveal | Ted starts/completes provider auth | Remind/diagnose; rotate own service token | Private setup assistance when asked |
| Managed apps | Inventory/plan/apply/health/rollback/remove scripts | Daily inventory/15m health | Status, desired, rollout, continue, rollback, decisions | View; admin writes | Ted adoption/exact rollout/continuation | Explain drift and gate evidence | Approved repair/recovery |
| Agent upgrade | `agent-self-upgrade-v1` | Approved windows only | App rollout/status/rollback | Admin rollout; machine-bound fetch | Ted helper bootstrap/target approval | Observe check-in/rollback | Supervised SSH recovery; Ted handles sudo |
