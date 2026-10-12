# Disk-clean maintenance

Disk-clean is a maintenance profile. The Hub stores it as desired state
`resource_kind=maintenance`, `resource_id=disk-clean`. The agent runs the
script embedded in the agent binary. The Hub, not the script, decides the
verdict.

This is not an artifact deployment. `CreateDeployment` always mints a new
desired revision, snapshots every non-retired member of a channel, and is
shaped around an artifact digest. Disk-clean keeps the same preview, digest,
idempotency, audit, and pause-after-canary rules on its own ledger:
`maintenance_rollouts`. The operator names the target list. That list does not
have to be every machine in the channel. A machine-scoped profile's only legal
target is that machine. A channel-scoped profile's targets must exist, not be
retired, and currently sit in that channel.

## Flow

1. Publish a profile revision. Preview, then apply with `preview_digest`,
   `expected_revision` (the scope's current revision, or 0), `confirm_scope_id`,
   a reason, and an `Idempotency-Key`. The same rendered conf does not mint a
   new revision. The preview does not promise the next number: the revision
   counter is shared by every scope.
2. Dry-run the named machines. The job is reversible. The agent always passes
   `--dry-run`, which forces dry-run even when the conf says `DRY_RUN=0`.
   Read the summary before anything that can delete.
3. Apply a canary of exactly one machine from that list. Every target,
   including the machines that will wait, must already have a succeeded dry-run
   of this same revision whose summary digest matches. Only the canary gets a
   job. The rollout pauses when that job succeeds.
4. Continue, with a new preview, opens the rest. The digest includes the
   rollout state, the control revision, and the opened batch. Abandon opens
   nothing more and refuses while a job is still running. The assignment stays
   after abandon.

Publishing alone does not assign the profile. Assignment is written when a
dry-run or a canary is applied.

A job is dry-run or apply by `irreversible`, not by a second desired revision.
The conf bytes and `config_digest` are the same for both.

## What the agent runs

The agent does not search `PATH`. It writes the embedded copy of
`ops/maintenance/disk-clean` to a private directory under its cache
(`clawctl/maintenance/disk-clean`, mode `0700`), checks the bytes, writes the
conf mode `0600`, checks that digest, then execs that absolute path with
`--scope` and `--conf`. `--dry-run` is added only when the job is not
irreversible. Before writing, the agent refuses the directory if it is a
symlink, not owned by the agent's euid, or group/other-writable.

The job passes only when the script exits 0, the summary parses, the echoed
`config_digest` matches, and the summary `mode` is the one the job implies:
`dry-run` for a dry-run job; for an apply job, `apply` when the profile has
`dry_run: false`, `mixed` when `dry_run: true` with `apply_categories`, and
otherwise `dry-run` (an apply of a pure dry-run profile is a no-op).

`--scope root` requires the agent process itself to be root. This agent runs
as the configured user (`User=@@CLAWCTL_AGENT_USER@@` in
`ops/clawctl-agent.service`). If it is not root, the job is rejected with
`PRECONDITION_FAILED`. There is no sudo. The user summary's `root` object, when
the host's root timer has written `/var/lib/disk-clean/last.json`, is evidence
only.

The spec carries `kind`, `schema_version`, `resource_id`, `scope`,
`config_digest`, the rendered conf, and the profile. It has no shell, no
operator command, and no path outside the closed keys. The agent validates the
spec again with the same Go rules and refuses otherwise.

Old agents are not sent this job. Check-in advertises
`maintenance_disk_clean_v1`. The Hub stores that on the exact check-in and
does not infer it from `agent_version`. Startup readiness still requires only
`device_sync_v1`, so a new agent talking to an older Hub is not stuck.

The flock stays at the script default (`~/.local/state/disk-clean`) so a user
timer already on the host shares the lock and `last.json`.

## Closed profile

Unknown JSON keys are refused. Bounds are enforced and the error names the
key. User categories are `user_tmp`, `tmp_globs`, `npm_cache`, `pip_cache`,
`uv_cache`, `go_cache`, `thumbnails`, `trash`. Root categories are `tmpfiles`,
`journal`, `pkg_cache`, `docker`, `snap`. `docker` prunes dangling images and
old build cache only. There is no volume, container, or `docker system prune`
option, and none can be added.

`tmp_dirs` is user-only and only `/tmp` and `/var/tmp`. `mount` is only `/`.
`extra_protect_names` can add tokens. It cannot remove the built-in list.
`tmp_glob_rules` are user-only, one segment under a directory in `tmp_dirs`,
and are refused when the glob would match protected data.

The Hub renders a deterministic conf. Header comments are part of the digest.
`config_digest` is `sha256:` of those exact bytes, the same value the script
prints for the file it was given. The job ships the conf and the digest. The
agent checks the file it wrote. The summary echoes the digest. The Hub
compares that echo to the assignment's expected digest.

## Protected names

The list lives in `maintenance.BuiltinProtect` and in the script's
`BUILTIN_PROTECT`. They are tested to be the same list. The Hub always renders
it. The script always merges it back in, so a conf that omits `PROTECT_NAMES`
or replaces it still protects every entry. The same names are excluded from
tmpfiles cleanup. A glob rule that targets one of them is refused by profile
validation and again by the agent. Because a pattern check cannot prove that
a glob never matches a protected name (`foo*` vs `foo-clawctl`), the script
also skips every individual glob match whose name is protected.

```text
systemd-private-* .X11-unix .ICE-unix .XIM-unix .font-unix .Test-unix
tmux-* ssh-* snap-private-tmp
*openclaw* *clawctl* *claude* *codex* *grok* *agy* *cursor* *vscode*
*backup* *snapshot* *.sock *.pid *.lock .X*-lock .s.PGSQL*
*odoo* *postgres* pulse-* dbus-* gpg-* krb5cc* hsperfdata_*
```

The script does not reboot, restart a service, install a package, or remove a
Docker volume or container.

## Evidence and verdict

A successful run prints one JSON line, schema `fleet-disk-clean/v1`. The agent
returns it as executor evidence: command, exit code, and that line as
`stdout_excerpt`, rule `disk_clean_summary`. The Hub stores a projection of
the line. The job can succeed on that evidence alone. The Hub verdict is a
separate reading and can fail after the job succeeded.

Verdict order:

- digest mismatch, including `none(defaults)` when a profile was expected: fail
- disk still under the assigned `disk_free_min_percent` after an apply or mixed run: fail
- attention non-empty: attention
- summary missing or older than 48 hours: stale
- otherwise: pass

The 48 hours is `maintenance.StaleAfter`. It is not a profile key. Age uses the
Hub clock (`received_at`). A summary that is exactly 48 hours old is not stale.
A missing summary is stale, not a digest failure.

The disk check uses the latest `resources` observation and the machine's
assigned `disk_free_min_percent` rule. No rule, or no usable byte counts, is
`unmeasured` and does not fail the verdict by itself. After an apply or
mixed run, an observation the Hub received before the summary (or that the
agent measured before the summary `ts`) is a pre-clean reading: the disk is
`unmeasured` until a newer observation arrives, so the "still over threshold
after cleaning" fail and alert are based only on a post-clean reading. The compliance board
still evaluates disk from the latest check-in. Those two readings are not
forced to be the same number.

`attention` on the summary is a hint. It does not decide the verdict on its own
beyond the rule above, and it does not delete anything.

## Alerts

The Hub's notifier (`deliver`, the same path as the daily report) is the only
transport. Every attempt is recorded in `notifications`. The minute loop
reconciles rollouts, then sweeps disk-clean, then runs the daily report. The
daily stamp and the daily watchdog are not touched.

A failed send is not retried every minute. Each alert kind backs off on the
daily report's schedule: the next attempt is at the last failure plus
1m, 2m, 4m, 8m, 16m, 32m, then 60m, counting failures since that kind's last
delivery. One kind's backoff does not hold back another machine's alert. With
no notify command configured, each kind records one undelivered row per day and
logs one warning.

Verdicts are computed on the read pool. The sweep holds the single writer only
to update `maintenance_alert_state`, and only for rows that changed.

A machine that has this profile assigned alerts when attention is non-empty,
when its latest summary is stale, or when an apply/mixed run left disk under
the assigned threshold. A dry-run does not raise the disk alert. The same
fingerprint is not sent again until it clears; an undelivered one is retried on
the backoff above. A change of fingerprint alerts again. Kinds look like
`disk-clean:<machine id>:<condition>`.

## Operator surface

JSON, under `/v1/operator/disk-clean/`:

| Method | Path | Grant |
|---|---|---|
| GET | `/summaries` and `/summaries/{id}` | view |
| POST | `/profile-preview`, `/profiles` | admin |
| POST | `/dry-run-preview`, `/dry-runs` | admin |
| POST | `/canary-preview`, `/canaries` | admin |
| POST | `/continuation-preview`, `/continuations` | admin |
| POST | `/abandonment-preview`, `/abandonments` | admin |

The same twelve calls are `disk_clean_*` tools on `clawctl-operator` (MCP and
`call`). Schemas are closed. Writes require `preview_digest` and an
idempotency key before any HTTP call. Continue and abandon also require the
expected control revision and opened batch. Local argument errors are
`invalid_arguments`.

The maintenance page (`GET /tenant/maintenance`) shows the board read-only:
verdict, staleness, digest match, the Hub disk evaluation, attention, and the
embedded root summary when the agent reported one. Writes stay on the JSON API.

## What this does not do

- It does not reboot, restart services, install packages, or prune Docker
  volumes, containers, or the whole Docker system.
- It does not send the job to an agent that has not advertised
  `maintenance_disk_clean_v1`.
- It does not apply past the canary without Continue.
- It does not add a notify transport.
- It does not turn per-host glob rules into per-machine assignments. One
  profile document is one scope (one machine, or the canary channel, or the
  stable channel).
- It does not migrate an existing hand-written conf. The rendered conf is the
  one the agent runs.
- It does not run `--scope root` unless the agent process is root.
- It does not choose the canary machine for you. The operator names it.


## Phase 2 disk foundation (P2-01)

`ops_policies` stores immutable canonical disk policy revisions and SHA-256
identities. `GET /v1/operator/disk-ops/policies` returns up to 500 revision rows;
`GET /v1/operator/disk-ops/policies/{id}` returns the latest revision. Both
require human view and remain token-ineligible because policies include additive
protect paths. Built-in credentials/backups, generated images, active models,
user data and all repository roots are always protected.

Human admin `POST /v1/operator/disk-ops/policies/preview` accepts `id`, typed
`body`, `expected_revision` (0 for create), and `reason`. It returns normalized
policy, preview digest, revision, 30-minute `expires_at`, and warnings.
`POST /v1/operator/disk-ops/policies` requires the same request plus the preview's
`preview_digest`, `expires_at`, and `Idempotency-Key`. Fresh/replay responses
are 201/200. Authorization precedes replay. Revision replacement, revocation of
pending/approved ledger entries and rejection of queued consumed jobs, receipt
and audit commit atomically. Audit stores
digests, never policy paths. `--disk-ops-v2-writes` (`disk_ops_v2_writes`) defaults
off and gates policy apply and approval writes; preview remains available.

MCP tools: `disk_policy_list`, `disk_policy_get`, `disk_policy_upsert_preview`,
`disk_policy_upsert_apply`; they share the operator service and strict HTTP client.
`GET /v1/operator/disk-ops/approvals` is the minimal view read (up to 500 rows),
with no paths/secrets; exact view-token allowlists may admit it. `approvals_summary`
adds `disk_ops` counts by state and oldest pending age across the complete ledger.
Expired pending/approved entries are projected as expired without authorizing work.

Approvals bind human actor, machine, operation, immutable policy revision/digest,
item/manifest digest and a 30-minute deadline. Trusted store entry points require
verified human admin authority; service tokens and optional agents cannot approve. A private
transaction helper consumes once together with job creation, receipt and audit;
retries return the same job receipt after authorization. Approval decisions have human-admin preview/apply pages and JSON routes.
Disk execution adapters are delivered separately. Future adapters must validate fresh
filesystem facts and dispatch admission; generic script routes grant no new writes.

Policy v1 defaults: user tmp 10 days, /var/tmp 14 days, Docker dangling/build cache
168 hours, journald 500 MiB, cargo 30 days, uv lock-aware native prune, npm verify
only, native holder-aware cache GC; thresholds warn 85%, critical 93%, deep report
strictly >80%; fixed quarantine TTL 7 days; scan maxima 500 items/200,000 entries/600s.
Unknown fields and unsafe bounds are rejected. Protection overrides approval.
Linux non-root agents advertise `disk_ops_v2` foundation support at check-in;
Hub reads only the exact latest receipt, never infers support from `script_v1`.
This capability alone does not provide a root helper or executable disk adapter.

Execution enablement requires reviewed adapters and a deployment-configured
canary. Deep operations must respect deployment-configured freeze windows;
planners and dispatch grants belong to later disk milestones.
Existing cleaner bytes, timers and fleet-disk-clean/v1 summaries are unchanged.


### Human-first disk administration

The Hub UI is complete without MCP, AI agents or chat notifications. Tenant
navigation includes **Disk policies** and **Approvals**. Human admin
`GET /tenant/disk-policies` and `GET /tenant/disk-policies/{id}` show immutable
revision history, canonical JSON/digest, safe-default creation and typed editing.
`?revision=N` selects a historical revision for inspection. Historical revisions
are read-only; changes start from the latest revision.

`POST /tenant/disk-policies/preview` displays a before/after diff and expiring
binding. `POST /tenant/disk-policies/apply` uses the same `DiskPolicyUpsert`
service as JSON/MCP. Local-account applies require the current password and an
enrolled authenticator code (unless MFA enforcement is explicitly disabled in
configuration). Tailscale applies reauthorize the human admin at the request
boundary and require typed ID confirmation; Tailscale provides no fresh MFA.
Credentials are never included in preview fields, receipts, audit details or errors.

Human view `GET /tenant/approvals` filters by `state`, `machine_id`, and `operation`
with pending/approved/rejected/expired/consumed states. Only admins see decision
buttons. `POST /tenant/approvals/preview` binds approve/reject to the current
pending record, original deadline, policy revision/digest, item digest, actor and
reason. `POST /tenant/approvals/apply` requires that binding, typed approval ID,
reauthentication and idempotency. A decision creates no execution job.
The canonical `DiskOpsApprovalDecision` service also backs human-admin JSON
`POST /v1/operator/disk-ops/approvals/{id}/decision/preview` and
`POST /v1/operator/disk-ops/approvals/{id}/decision`, plus optional MCP tools
`disk_approval_decision_preview` and `disk_approval_decision_apply`.
`disk_approval_list` and the JSON ledger read support the same filters.
All new mutations remain service-token-ineligible; disk writes default off.

Server-rendered forms use the existing operator CrossOriginProtection, pinned
Host and locked CSP. No new inline scripts are introduced. Public defaults are
generic; canaries, freeze windows and integration destinations come from deployment
configuration. Fixture screenshots and HTML are generated with
`ops/screenshots/phase2-disk.sh` into `docs/screenshots/phase2/p2-01/`.


Disk JSON policy and approval-decision applies accept only freshly boundary-verified
human Tailscale admins. Local-account sessions have no action-bound JSON reauthentication
proof and are rejected before idempotency lookup, including retries; use the Hub UI
password/TOTP apply flow. Previews remain available to authorized human admins.

A policy preview explicitly lists `removed_protect_paths`. Removing configured
protections requires the exact `acknowledge_removed_paths` array on apply, included
in the preview digest and checked against the current revision inside the write
transaction. The UI requires a separate **Remove protection** checkbox for each
path. Built-in protections remain unconditional. Success audits record only the
removed-path count and SHA-256 digest of the sorted removal set, never the paths.

MCP policy list/get and upsert receipts expose protected-path counts and per-path
SHA-256 digests instead of path strings, including previous policy bodies and
removed protections. Full policy bodies remain on the human UI/API. Approval
decision reasons are limited to 500 bytes, stripped of control characters before
digest binding, stored in `ops_approvals.decision_reason`, and included in the
success audit. Upgrades add this column without replacing existing ledger rows.

## Safe disk operations (P2-02)

The machine **Disk** page (`/machines/{id}/disk`) provides usage bars, policy
warning/critical thresholds (defaults 85/93), last safe-tier summary and skips,
an observation Preview, reviewed safe cleanup, and daily schedule creation/edit,
enable/disable, run-now review and recent job history. Forms use the existing
cross-origin/CSRF boundary and server-rendered templates without scripts. Apply
reauthenticates local human admins. Agents and notifiers are optional.

`disk-safe-preview-v2` (read) and `disk-safe-clean-v2` (write) have closed args:
`scope:user|root`, `policy_id`, `policy_digest`. The current canonical policy is
resolved inside the job transaction and pinned in the spec. The agent validates
that same closed contract and digest before executing its fixed adapter; arbitrary
configuration, commands, environment and executable paths are never job arguments.
Generic script preview/apply and schedule services supply digest binding,
idempotency and audit. Cleanup enqueue and claim require both the default-off
`disk_ops_v2_writes` flag and the exact latest `disk_ops_v2` capability. Disabled
flags, absent capabilities and revoked policy digests refuse execution. Scheduled
skips retain their reason in audit; manual admission returns the rejection.

Preview performs stat/no-atime observation only: no GC commands, locks, logs or
summary files. Directory traversal requires `O_NOATIME`; unavailable observation
or incomplete `/proc` descriptor visibility is a skip. Temporary-file cleanup is
owner-only, age-bound and descriptor-relative, with fresh inode/link/owner,
repository and holder checks immediately before unlink. Symlinks and non-regular
files are retained. User temp covers `/tmp`, `~/.cache/tmp`, `~/.local/tmp`; inaccessible
system temp is skipped rather than changing atime. All repository roots, credentials,
generated images, active models, lock files and additive protect paths override GC.

uv uses native prune, holder counts and a 60-second timeout (timeout is skipped,
never forced). npm uses native verify only with its locally fixed cache. Cargo is
explicitly unsupported until a tested native age-aware GC adapter exists. Docker
requires a verified local context/storage root and protection/holder visibility;
its only prune commands are `docker image prune -f --filter until=168h` and
`docker builder prune -f --filter until=168h`. Stronger Docker age policies are
skipped until a reviewed adapter supports them. Volumes, containers and system
prune are never permitted. Root scope returns category skips with the typed reason
`root_helper_missing`; this PR installs no helper, executes no journald vacuum,
and leaves root timers local-owned. The fixed future journald operation is vacuum
to 500 MiB only, without a restart.

Write runs share the existing user timer's scope lock. `last.json` retains only
`fleet-disk-clean/v1` fields; job output is `{summary, operation}` with separate
policy/ownership/protection/mount metadata. Cache estimates are upper bounds,
not promised GC savings. Reported freed bytes use observed file/cache shrinkage.

`GET /v1/operator/disk-ops/status/{machine_id}` and MCP `disk_ops_status` return
bounded mount usage, current policy thresholds, last safe-tier evidence, observation
preview, skips and ownership. Additional mounts come from adapter observations;
per-mount measurement times distinguish their age from the latest root check-in.
The read is human-view and service-token ineligible because mount paths are included.
MCP status uses mount/protection digests, fixed categories and note digests; private paths remain on the human API/UI. JSON script and schedule applies by admins require fresh LocalAPI authorization before decoding or replay; local sessions use reauthenticated UI applies.
No new token-eligible writes or delegated cleanup approvals are implemented.

Daily templates use UTC, `catch_up=false`, one machine per schedule and explicit
operator hour/minute offsets; public defaults contain no fleet names or dates.
Root templates cannot be enabled without reviewed helper readiness (unavailable
in this PR). Safe-tier schedules are unaffected by deployment freeze windows;
canary selection and fleet enablement remain human deployment choices.

Safety fixtures: `bash ops/test-disk-safe-v2.sh`. UI fixture export/render:
`bash ops/screenshots/phase2-safe-disk.sh`; output is under
`docs/screenshots/phase2/p2-02/`. If the sandbox prevents headless Chromium, the
same script retains fixture HTML for rendering outside the sandbox.

Safe-tier observations and unlinks stop before exceeding the policy `max_items`
budget; incomplete results retain bounded counts and freed-byte evidence. Descriptor
protection uses device/inode identity, including held-directory descendants, and is
rechecked immediately before unlink. uv/npm inherit an anchored, no-follow cache
directory descriptor; cache replacement causes a deferred result. Disk-v2 job
evidence is human-only even for read scripts because output and pinned policy specs
contain private paths. MCP status remains a path-safe digest/category projection.
Docker keeps only the two fixed §4.1 age-filtered commands, including confirmation `-f`.

### Native-cache ownership boundary

The v2 adapter delegates cache-internal garbage collection to the native tool:
`uv cache prune` owns its cache descendants and takes uv's exclusive cache lock;
`npm cache verify` / cacache verification touches content-addressed cache entries.
The adapter does not validate each descendant again at native-tool deletion time.
It admits only a real, user-owned cache directory, never a symlink root, and rejects
roots inside or containing configured protections or Git repositories. Both the
fixed location and its resolved location are checked to cover ancestor aliases.

Before admission, the bounded, no-atime safety scan rejects symlinks escaping the
cache root, including links at depths one and two. It also rejects unresolved links,
protected targets, inaccessible trees and exhausted entry/item/time budgets with
a skip reason; it never follows links while traversing. Contained links remain
native-tool owned. The current scan conservatively checks deeper descendants too.
uv/npm receive the cache location only as `/proc/self/fd/<n>`, with the no-follow
root directory descriptor inherited across spawn. Root replacement causes a skip.
The native lock, together with this explicit ownership boundary, governs mutations
inside the admitted cache; no arbitrary user temporary tree is delegated to GC.

Temporary-file unlink performs its final full identity comparison (device, inode,
file type, size, nanosecond modification/change times, owner and link count) after
holder scanning and protection checks, directly before unlink through the same
retained no-follow parent directory descriptor. Changed entries are retained.
Temporary directories are retained; the adapter never recursively removes them.

Protection admission normalizes configured paths and concrete built-in home paths
before each category scan. Each keeps its absolute lexical path and, when present,
its strict resolved path. Candidates and cache roots use both forms for containment
in either direction; a protection symlink into a cache or temporary subtree therefore
protects its destination. Built-in name patterns remain unconditional. Missing ordinary
paths retain lexical protection; dangling links, loops, inaccessible ancestors or
other resolution failures defer the category with an explicit reason.

Preview defers strict symlink resolution on filesystems without `noatime`: reading
an alias can update the symlink's access time. It checks ancestors before following
them and returns a resolution-failure skip instead of changing fixture timestamps.
Cleanup resolves aliases strictly; both modes retain the protected subtree.

A run retains the original protection specifications, resolved targets, and alias
`lstat` identities (including aliases in ancestor and target chains). Immediately
before unlink or native GC admission, it re-resolves those specifications and
compares the snapshot. Any change or resolution failure defers the item and latches
a protection-change skip for all remaining mutations in that run, even if the alias
is restored later. A new invocation establishes a fresh baseline. Alias access times
and ordinary directory modification times do not participate in identity checks.

## Deep reports (P2-03)

`disk-deep-report-v1` is a pinned read script with closed `policy_id`,
`policy_digest`, and `max_items` (1–500) args. It observes reviewed Linux roots
without following symlinks or crossing mounts. Enumeration and archive hashing
require no-atime descriptors; inaccessible roots and unknown generation/holder
facts remain partial or investigate-only. All repository roots, credentials,
secret backups, active/rollback names and configured protected paths are excluded
as aggregates. Access times are weak under relatime/noatime. Archive hashes have a
64 MiB content budget. Docker listing includes stopped-container references;
shared-layer reclaim and rollback references remain unknown.

The supervisor uploads typed records in memory to machine-authenticated
`POST /v1/disk-reports/{job_id}/chunks` and `/complete`: active assigned job,
64 KiB per chunk, 2 MiB total, 500 items, ordered sequence and digest replay
binding. Completion binds the canonical Go report JSON digest and item count.
Private paths live only in restricted report columns, never stdout or audit.
Final reports expire after 30 days; incomplete uploads after 24 hours.

Fresh usage (both observation and receipt within 15 minutes) strictly above the
policy threshold (default 80%) triggers minute reconciliation. All manual,
weekly and pressure deep jobs coalesce per machine for six hours, including
queued/running jobs. Only `disk_ops_v2` machines qualify. The machine's enabled
weekly schedule selects its policy; a single active tenant policy is an
unambiguous fallback. Multiple unassigned policies skip without durable trigger evidence.
Only active, expected, non-retired machines with recent check-ins are evaluated.
Routine below-threshold, stale, unavailable and unassigned evaluations create no
slot or audit rows. Enqueue and the first coalesce decision in each six-hour
interval use persisted minute slots and audit evidence. Writes need not be enabled for
read scans. Weekly templates use Sunday UTC and an explicit operator hour/minute.

Use the machine Disk page to preview/apply a report or weekly schedule and open
the ranked viewer. JSON and `disk_report_get` expose sanitized display paths;
human admins may view full paths in the no-store HTML viewer. Selection and
approve/reject controls are active for human admins in P2-04. No automatic cleanup or agent
approval delegation is implemented here. Deployment canaries and freeze windows
remain private configuration; reports are read-only.

### Deep-report no-atime capability model

The read scanner runs with the agent user identity. Linux permits `O_NOATIME`
when that user owns the inode or has `CAP_FOWNER` for it. Root-owned reviewed
roots such as `/tmp`, `/var/tmp`, and `/usr/local/bin` may therefore be skipped
by an ordinary agent user. No capability elevation or privileged helper is
installed by P2-03. The scanner never retries enumeration or content reads
without `O_NOATIME`: reports and the viewer clearly state
“skipped: no O_NOATIME permission”, and remain partial. Stat-only metadata does
not require content reads; archive hashing remains weak when a safe descriptor
cannot be opened. Protection aliases reuse safe-v2 lexical and strict resolved
snapshots; resolution on a filesystem lacking `noatime` defers rather than
changing a symlink's access time. Displayed paths replace Unicode format/control
characters using the shared bounded-text scrubber; exact raw paths remain only
in the private item binding after completion (chunk digest receipts retain no
payload). Docker stdout is streamed with a 2 MiB cap and deadline; overflow
kills the subprocess and produces partial inventory.

Deep-report chunk and completion uploads share process-local admission: at most
2 concurrent requests per authenticated machine and 16 globally, with a 64-request
per-minute machine token bucket (burst 64). Throttling returns HTTP 429 with
`Retry-After`; neither client IP nor job ID resets the machine allowance. The
limiter retains at most 4096 machine buckets, evicting only idle fully refilled
entries. Job ownership, running state, lease and pinned read-script identity are
checked through the query-only pool before acquiring the SQLite writer, then
rechecked inside the writer transaction. Item IDs allow only ASCII letters,
digits, underscores and hyphens (1–128 bytes); `last_used` is empty or canonical
RFC3339Nano, and evidence sources are a fixed allowlist (atime, all-container
references, process start ticks, unknown or empty). Displayed free text uses the
shared bounded-text scrubber; raw private paths remain identity bindings.

### P2-04 human decisions, quarantine and restore

Internal human-admin previews snapshot 1–100 unique regular-file item IDs from a
completed deep report no older than six hours. Quarantine and irreversible delete
use separate immutable manifests and approvals. SHA256 binds exact private paths,
device/inode, size, mtime/ctime, owner, category, action, initiator, reason, policy,
and the 30-minute deadline. Public projections scrub paths. Dedicated
`DiskActionDecide` approves, creates the pinned job and consumes the approval in
one transaction; replay returns the same job. Generic script runs and generic
schedules reject quarantine, delete and restore entries, including for human admins. Only the approved-item expiry adapter is admitted through the scheduler. Service
tokens cannot approve or run them. Agent delegation remains deferred.

The four generated helpers reuse P2-02 protection normalization/revalidation and
holder visibility. They take independently verified signed authority, not caller
paths. Every mutation boundary renews authority over supervisor pipes, without
passing machine credentials into the interpreter. Revoked policy, disabled writes,
expired approval/job/lease, missing helper key or Hub outage prevents the next
mutation. Private `GET /v1/ops-manifests/{id}?job_id=...&digest=...` returns only an
assigned running job's no-store signed grant. The grant expires within 15 seconds
and never outlives the approval or job lease.

Catalog pins (regenerate with `python3 ops/generate-disk-actions.py`, then review
both generated bytes and constant pin changes):

| Entry | SHA256 | Timeout |
| --- | --- | --- |
| `disk-approved-quarantine-v1` | `07b5f1f24a714cc9b2649cf18cafcbe993dd94d526bb53a964d9fd5a74791180` | 900s |
| `disk-approved-delete-v1` | `5a7eb5c2cac9d5da70d072161041a6bcedd8415dcfec8750891ac7d040f651d4` | 900s |
| `disk-quarantine-expire-v1` | `6ade73ba3e57a085c0f843639a09ed78a35714a006063ea7b21e7c02ac741550` | 600s |
| `disk-quarantine-restore-v1` | `a507640a1cd9a993a505200eff360001445f6796167aec43b83f0f15574b740c` | 600s |

Host state lives under the enrolled user's `.local/state/ai-intune/quarantine`,
with private 0700 directories and 0600 item journals. Helpers also acquire the
existing local disk-clean scope lock. Files with multiple links, shared write
permissions, symlinks, changed ancestors, repositories, protections or unknown/open
holders are skipped. A shared job item/time budget spans manifests. Same-filesystem
`RENAME_NOREPLACE` is mandatory; cross-filesystem items are skipped, including in
this delete adapter, and are never copied. Unsupported rename semantics are skipped.

Quarantine journals and fsyncs the intent before moving, then records the moved
identity and a fixed seven-day TTL. It reports quarantined bytes separately from
freed bytes. Direct delete first atomically stages the exact file in private
quarantine, checks the moved inode and fresh authority again, and uses descriptor-
relative unlink. A substituted entry is never deleted; rollback never overwrites.
An interrupted delete can retain quarantined data, requiring human recovery.
Uncertain deletions never claim freed bytes. Expiry validates original signed
identity, the journal's actual inode ctime and seven-day TTL, policy and holders.
Restore requires the original parent inode, opens all ancestors without following
links, creates no parent directories and atomically refuses occupied destinations.
Interrupted moves/restores reconcile conservatively; recovered quarantine starts a
new full seven-day clock.

Signing defaults off. The Hub's optional `--disk-manifest-signing-key` accepts a
0600 RSA private PEM (2048–4096 bits, exponent 65537). An admin must independently
install its public modulus/exponent JSON as root-owned
`/etc/clawctl/disk-manifest-key.json` (0644 public data) with root-owned, non-writable-by-others
ancestors. The JSON shape is `{"n":"<hex public modulus>","e":65537}`. Keep the
private key on the Hub; never distribute it to agents. This implementation changes
no deployment or local key installation.

Human UI controls now support per-item approve/reject and bulk selection of up to
100 reviewed IDs. Quarantine is the default; irreversible delete has a separate
warning and approval. Preview and confirmation require fresh human reauthentication.
Confirmation displays exact original items, identities, bytes, digest and deadline;
type the action to apply. Apply redirects to the existing job status page. The
per-machine **Quarantine and restore** page shows scrubbed original paths, bytes,
quarantine time and remaining TTL as a human duration with the absolute UTC deadline (refresh to update). Restore binds
the recorded moved identity and original parent, with a separate human approval.
Reject decisions persist without filesystem jobs.

| Operator route under `/v1/operator/disk-ops` | Permission | Contract |
| --- | --- | --- |
| POST `/actions/preview` | Human admin, fresh reauth | Report digest, action, <=100 item IDs, reason |
| POST `/actions/decide` | Human admin, fresh reauth | Without decision digest: preview. With exact bindings and idempotency key: consume and dispatch once |
| GET `/quarantine/{machine_id}` | View | Scrubbed retained items, no private identities |
| POST `/restores/preview` | Human admin, fresh reauth | Snapshot retained identity and original parent |
| POST `/restores` | Human admin, fresh reauth | Approved restore only; exact bindings and idempotency key |

MCP tools are `disk_action_preview`, `disk_action_decide`, `disk_quarantine_list`,
`disk_restore_preview`, `disk_restore_apply`, with closed schemas and redacted
projections. Use `disk_action_decide` to preview the restore decision before applying
it. These routes are not service-token eligible. Human JSON writes use P2-01
fresh-reauth-only API credentials. Agent delegation remains OFF/deferred; delete
and restore are never delegated. HTML uses the shared authenticated cross-origin
boundary and password/authenticator reauthentication.

A quarantine approval creates an enabled no-catch-up daily expiry schedule at
`10 6 * * *` UTC for that machine/policy. It never silently reenables an existing
disabled schedule. Each expiry job snapshots <=100 due items covered by consumed
original human approvals under the current policy. Empty selections create no job.
Original approval deadlines do not shorten the seven-day retention period; expiry
authority instead binds the original consumed approval and active expiry job lease.
Revoked policy, changed pins, missing helper, holds or uncertain identities defer
expiry. Review TTL backlog in supervision and pause schedules in the schedule UI.

Admission requires the latest check-in to advertise the action helper and the
fingerprint of its independently installed signing public key. Missing key/signer
fails closed. Generic script invocation cannot bypass exact manifest dispatch.

The machine-only POST `/v1/disk-actions/{job_id}/results` accepts bounded private
journal observations tied to assigned jobs and consumed approvals. Immutable
receipts deduplicate retries and terminal records cannot be resurrected. Normal
stdout strips private journals. Durable private result outboxes retry on heartbeat
after a Hub outage, even after termination or policy revocation; observations grant
no mutation authority. Item/time budgets persist across helper retries. A process
killed between a filesystem change and writing the complete result outbox can leave
an evidence gap in the Hub ledger. Retain its private item journals; reconcile only
under original active authority. After that authority expires, explicit human host
recovery is required. Never automatically replay destructive operations.

`disk_ops_status.actions` and `jobs_summary.disk_actions` expose current retained
quarantine bytes and TTL backlog, cumulative freed bytes, successful restores,
occupied-destination conflicts, protection denials and sample count/evidence source.
Quarantine is retained data, never freed bytes. These are authenticated observations,
not independently measured savings.

Production-template fixtures live in `docs/screenshots/phase2/p2-04/`. Regenerate
with `bash ops/screenshots/phase2-disk-actions.sh`; PNG rendering needs an environment
that permits Chromium's sockets. All fixture data is generic. Writes default off;
this delivery does not deploy or install host keys.

Approved delete, TTL expiry and restore first capture the stable quarantine entry
with descriptor-relative `RENAME_NOREPLACE` into a unique operation staging name.
The journal persists that name before capture. The captured inode is reverified
against the exact approved identity and current protections/holders before unlink
or final restore. Restore verifies the destination inode after its final rename.
Mismatches never claim freed bytes or successful restoration. Rollback never
replaces an occupied entry; blocked rollback retains the staging journal and
reports `stage_retained_for_recovery`. Preserve these journals for explicit human
recovery. Interrupted staging is retained rather than silently replayed.
