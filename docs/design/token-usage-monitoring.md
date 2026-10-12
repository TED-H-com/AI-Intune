# Token and Model Usage Monitoring for AI Coding CLIs

Status: DRAFT — proposed design, not authorization to implement or deploy.
Owner: The admin. Scope: account inventory across installed tools; usage parsing for Claude Code and Codex CLI.
Language: English. Implementation: later, by Codex CLI, in the PR order of §11.
Builds on: `docs/design/HUB-PHASE2-STANDARD-OPS.md` (Phase 2) and the shipped
P2-01..P2-05 disk work (policies, `ops_approvals` ledger, typed report upload,
alerts, Disk page UI). This document changes no code, policy or CLI configuration.

## 1. Operating principle

Same rules as Phase 2 §1A, restated for this feature:

- **Humans first, AI optional.** Every capability below is fully usable in the Hub
  web UI with no AI agent, no chat notifier and no reference-fleet conventions.
- **Same action, any caller.** The UI, JSON API and MCP call one canonical
  `usage` operator service, under the same scopes, ledger and audit. An agent
  (for example Hermes, or a Grok Bot acting for the admin) never gets a capability
  a human in the UI lacks.
- **Optional integrations.** Telegram/Discord notifications are opt-in layers over
  the existing notifier; every alert is also a Hub UI banner and list entry.
- **Generic public defaults.** All thresholds in this document are generic public
  defaults. Fleet-specific thresholds, host labels, pinned plan tiers/quota limits,
  notifier recipients and the host-to-label mapping live only in the private
  overlay (§10). Public code, fixtures and screenshots contain no real hostnames.
- **Suggestions only.** The Hub never changes a model, effort level, subagent
  configuration, cron entry or CLI setting on its own. Recommendations are cards a
  human approves, dismisses or snoozes; approval records intent in the ledger and,
  produces a human-reviewable change preview. Gated admin-approved application
  with rollback is a later phase (§7.3).

Reference-deployment labels follow Phase 2: W1/W2 workstations, C1–C4 cloud VMs,
C3 production web app, C4 agent runtime, plus **D1**, the admin's Windows desktop.
The real mapping lives in the private overlay.

## 2. Evidence: why this feature

The admin ran manual 30-day diagnostics on the reference deployment. They define
what the collector must measure; any metric that would not have surfaced one of
these findings is out of scope for v1.

| # | Tool | Finding | Metric that must exist |
| --- | --- | --- | --- |
| E1 | Claude Code | Effort `max` was 98.6% of estimated spend | Spend/tokens by effort |
| E2 | Claude Code | Calls with >100k context drove 82% of orchestrator spend | Long-context call counts/tokens by bucket |
| E3 | Claude Code | Orchestrator running many small Bash commands = 76% | Calls per user turn, tool-call mix, main vs subagent |
| E4 | Claude Code | Cache rebuilds after >1h idle gaps only 3.6% | Inter-call gap histogram + cache-creation after gap |
| E5 | Claude Code | 5-hour limit hit 4×, weekly limit 3× | Rolling 5h / 7d window consumption vs limit |
| E6 | Codex | ~21.2B tokens, 95.6% cached | Cached vs uncached input |
| E7 | Codex | `xhigh` + `ultra` = 54% of tokens | Tokens by effort (per call where present) |
| E8 | Codex | Calls with >100k input = 66.5% of tokens | Long-context buckets |
| E9 | Codex | Standalone `exec` = 64% of uncached input; one fixed model made 183k calls (likely cron) | Source type `exec`, recurring-job fingerprint, top jobs |
| E10 | Codex | `cache_write` always 0/missing | Explicit `unknown` (null), never 0 |
| E11 | Codex | Last 7d tokens/day +82.7%, driven by longer contexts | Daily baseline + spike detection + context trend |

Conclusions that shape the design: the cheap wins are **effort level**, **context
length** and **unattended loops/cron jobs**, not cache tuning (E4). Limits are the
user-visible pain (E5), so early warning before quota exhaustion is the primary
value; catching runaway agents and cron jobs is second.

## 3. Goals and non-goals

### 3.1 Goals

1. **Quota early warning.** Show, per account and machine, consumption of rolling
   provider windows (Claude 5h and weekly; Codex equivalents where known) and warn
   before the limit is hit, with a projected time-to-limit.
2. **Runaway detection.** Detect runaway turns (too many calls in one user turn),
   very long sessions, sudden daily spikes and recurring unattended jobs.
3. **Explainability.** Break usage down by machine, tool, model, effort, source
   type (main / subagent / exec), day, context bucket; show top sessions and
   recurring jobs, so a human can see *why* usage moved.
4. **Actionable suggestions.** Rules map evidence to recommendation cards (§7).
   Each card is approved, dismissed or snoozed in the UI and recorded in the ledger.
5. **Cheap and safe collection.** Read-only, incremental, CPU/IO-budgeted scanning
   that handles very large logs (hundreds of GB of Codex sessions) without
   impacting interactive work.
6. **Optional AI layer.** Hermes/Grok Bot can query the same aggregates and propose
   recommendations through MCP; notifiers can relay alerts.

### 3.2 Non-goals

- No automatic change of model, effort, subagent model, cron schedules or any CLI
  config in the advice-only first phase. No killing processes or sessions.
  Gated application is a later phase (§7.3).
- No collection of prompt text, response text, tool arguments/outputs, file paths
  inside sessions, or repository contents (§4).
- Not a billing system. Dollar figures are **estimates** from a versioned public
  price table; provider invoices remain authoritative.
- No live paid probes. Discover accounts/plans and cross-check available read-only
  provider/GitHub dashboards/APIs (§5.7); label local quota estimates explicitly.
- Other CLI usage parsers come later; account inventory includes grok, gh/Copilot,
  agy/Gemini and other installed tools now.
- No modification, rotation, compaction or deletion of session logs. Session-store
  cleanup stays in disk deep analysis (Phase 2 §4.3).

## 4. Privacy and data classification

### 4.1 Tiers

| Tier | Content | Leaves machine? |
| --- | --- | --- |
| Aggregate | Counts and token sums keyed by machine/tool/model/effort/source/day/bucket; gap histograms; quota-window sums | Yes — default upload |
| Session metadata | Keyed-HMAC session ID, start/end, call count, token sums, max context, model/effort mix, source type, project **HMAC** (never the path) | Yes — for top-N sessions only |
| Account inventory | Stable account hash, provider, plan, machines; display-safe identity | Yes — no credentials |
| Task label | First ≤40 chars of first user message, redacted | Default **on**, all machines; admin may disable |
| Confidential | Prompts, responses, tool inputs/outputs, raw paths, cwd, git remotes, env, raw JSONL lines | **Never** |

The scanner parses each JSONL line in memory, extracts only whitelisted numeric and
enum fields (§5.4), account metadata (§5.7) and redacted labels (§4.3), and discards the rest. No raw line is buffered to disk,
logged, included in errors or sent. Parser errors report file HMAC, byte offset and
error class only.

### 4.2 Identifiers

- Session IDs, project directories and job fingerprints are reported as
  `HMAC-SHA256(machine_secret, value)` truncated to 16 bytes, hex. The machine
  secret is generated on the agent at enrollment of this feature, stored 0600, and
  never uploaded. The UI can therefore group and rank sessions but cannot reverse
  them; the local machine can map back for a human using a local-only CLI
  (`clawctl-agent usage resolve <id>`, prints to the local terminal only).
- Project display: the Hub shows `project-<first 6 hex>` unless the admin assigns a
  friendly alias in the UI (stored Hub-side, never derived from the path).
- Model names, effort levels and source types are closed enums plus `other`;
  unknown model strings are mapped to `other:<HMAC>` to avoid leaking custom names.

### 4.3 Task label

- On by default on all enabled machines; admin may disable per machine
  (preview/apply, audited). Default and hard maximum `N = 40` characters.
- Source: first user message of the session (not tool results, not system/
  injected content). Truncated to N characters **before** redaction, then redacted.
- Redaction runs on-agent: emails, URLs, IPs, hostnames matching the scrubguard
  denylist digests, file paths, anything matching secret/token patterns (provider
  key prefixes, JWTs, long hex/base64 runs ≥20), digits runs ≥6. If more than 30%
  of characters are redacted the label is dropped entirely.
- Labels are stored in a restricted column, retained 14 days, excluded from audit,
  notifications and MCP outputs unless the MCP caller has an explicit
  `usage.labels.read` route grant (default not granted).

### 4.4 Retention

Daily aggregates 400 days; hourly quota-window rollups 30 days; session metadata
90 days; task labels 14 days; recommendation and decision records follow
`ops_approvals` retention. Disabling the feature on a machine stops upload and
offers a Hub-side purge (admin, preview/apply, audited).

## 5. Collector design

### 5.1 Placement and permissions

- New read-only catalog script `ai-usage-scan-v1` (mode **read**), run by the
  existing agent executor under a reviewed runtime profile that grants read access
  to the enrolled user's real HOME (same mechanism Phase 2 §3.1 introduced; not
  BAT's special case). It needs no root; network access is limited to Hub upload and allowlisted
  read-only account/usage APIs (§5.7), with authentication kept local.
- Read roots (fixed, not caller-selected):
  - Claude: `~/.claude/projects/**/*.jsonl` including `*/subagents/*.jsonl`.
  - Codex: `~/.codex/sessions/**/*.jsonl` and `~/.codex/archived_sessions/**`.
  - Windows: `%USERPROFILE%\.claude\...` and `%USERPROFILE%\.codex\...`;
    `CODEX_HOME`/`CLAUDE_CONFIG_DIR` honored only if set in the agent's trusted
    config, never from request args.
- D1 runs as the interactive user through the existing Windows agent, with load
  guard on and battery guard where available (proposed default Q8).
- Never follow symlinks out of the root, never cross mounts, open with `O_NOATIME`
  where permitted, `O_RDONLY`, no locks taken on session files.
- Writes only its own state file (§5.2) under the agent's state dir
  (`~/.local/state/clawctl-agent/usage/`, 0700/0600). That is the single,
  declared exception to read-only; it is executor-private like script staging.

### 5.2 Incremental state

Per file, keyed by `(device, inode)` with path HMAC as secondary key:

```
{ file_key, path_hmac, size, mtime_ns, offset, last_line_hash,
  tool, session_hmac, parser_version, codex_cum_state }
```

- On each run: stat files (directory walk is itself budgeted, resumable by cursor).
  Skip if `size == recorded size && mtime == recorded mtime`.
  If `size > offset`, verify `last_line_hash` at `offset` still matches (detects
  rewrite), then read from `offset` to the last complete newline.
  If size shrank or hash mismatches: treat as rewritten, rescan from 0 and
  subtract the file's previously contributed aggregates (kept per file per day in
  state as compact deltas) so totals stay idempotent.
- Moving `sessions/` → `archived_sessions/` keeps the inode; the move is recognized
  and not double counted. Cross-filesystem moves fall back to `session_hmac` +
  per-event dedupe keys (§5.3).
- `parser_version` bump forces a controlled backfill of the affected tool, still
  under the budget.
- State is crash-safe: write temp + fsync + rename after each committed batch; a
  batch is uploaded and acknowledged by the Hub *before* offsets advance.
  Uploads carry `(machine, file_key, offset_from, offset_to)` so a replay after a
  lost ack is deduplicated by the Hub.

### 5.3 Tool-specific parsing

**Claude Code.** Each assistant line has `message.model` and `message.usage` with
four counts: `input_tokens`, `cache_creation_input_tokens`,
`cache_read_input_tokens`, `output_tokens`. Streaming can emit several lines with
the same `message.id`/`requestId`; dedupe on `(session, message.id, requestId)`
keeping the last (largest) usage. Source type: `subagent` when the file is under
`subagents/` or the line marks a sidechain, else `main`; non-interactive `-p`
runs (including `claude-automation`) are `exec` when the session entrypoint
indicates it. Effort: derived from the session's thinking/effort setting when
recorded per call; else session-level inference marked `inferred`, otherwise
`unknown` (proposed default Q3). A *turn* begins at a genuine user message (not a tool
result); calls per turn = assistant API calls until the next genuine user message.
Tool-use counts by tool **name** (enum: Bash, Read, Edit, Task, …, other) — never
arguments. Limit events: lines that indicate a usage-limit error are counted as
`limit_hit{window}` with timestamp only.

**Codex CLI.** Usage arrives as `token_count`-style events with **cumulative**
totals per session (`total_token_usage`) and sometimes `last_token_usage`.
- Prefer per-call `last` values when present; otherwise compute deltas of the
  cumulative total.
- Dedupe identical consecutive cumulative events (same totals = no new call).
- **Counter reset**: if any cumulative field decreases, treat it as a new segment
  (resume/compaction/restart): delta = new value, not negative. Record
  `counter_resets` in metrics.
- Persist the last cumulative tuple per session in `codex_cum_state` so deltas
  survive incremental reads and file rotation.
- Model from session/turn context events; effort per call (`reasoning_effort`)
  when present; else session-level inference marked `inferred`, otherwise
  `unknown` (proposed default Q3).
- Source type: `exec` for `codex exec`/non-interactive sessions, `subagent` for
  spawned sub-sessions where marked, else `main`.
- `cache_write` is reported as **null** when absent or always zero in a file
  (E10); the UI shows "not measured", and no rule uses it.
- Cached input is a subset of input for Codex; uncached = input − cached. Claude
  reports them separately. The normalized schema (§5.4) stores both conventions
  unambiguously.

Formats change: each parser declares supported CLI version ranges via observed
schema fingerprints. Unknown shapes are counted as `unparsed_lines` per file and
surface as a collector health warning — never guessed.

### 5.4 Metrics schema (uploaded)

Normalized token fields per call: `input_uncached`, `cache_read`, `cache_write`
(nullable), `output`, `reasoning` (nullable), `context_tokens` (= uncached +
cache_read + cache_write for Claude; = input for Codex).

**Account inventory (`usage_accounts`)**: `account_id` (stable keyed hash, §5.7),
`provider, plan, machines[]`, optional display-safe identity, discovery source and
last-seen/freshness. No credential fields. Usage carries the discovered account ID;
unresolved attribution stays `unknown`. Effort metadata includes `effort_source`
(`recorded|inferred|unknown`) for visible session-level inference.

**`usage_daily`** — key: `machine_id, tool, account_id, model, effort,
source_type (main|subagent|exec), day (UTC), project_hmac?`

| Field | Meaning |
| --- | --- |
| `calls`, `sessions`, `turns` | Counts |
| token fields | Sums (nullable fields stay null if every contributing call is null) |
| `est_cost_usd` | Estimate, with `price_table_version` |
| `ctx_bucket_calls[5]`, `ctx_bucket_tokens[5]` | Buckets `<32k, 32–100k, 100–200k, 200–500k, >500k` |
| `calls_per_turn_p50/p90/max` | Turn shape |
| `tool_calls{name}` | Tool-use counts by tool name enum |
| `gap_hist[6]` | Inter-call gaps `<1m, 1–5m, 5–60m, 1–4h, 4–24h, >24h` |
| `cache_rebuild_after_gap_tokens` | Cache-creation tokens on first call after gap >1h (Claude) / uncached spike after gap (Codex) |
| `limit_hits{5h,weekly,other}` | Observed limit events |
| `counter_resets`, `unparsed_lines`, `deduped_events` | Collector quality |

**`usage_window`** — hourly rollup per `machine, tool, account_id` for rolling
5h / 7d window math (calls, normalized tokens and estimated cost units per hour).
Hub sums member machines into one account window, retaining machine contributions.
Proposed default Q2: estimated cost units calibrated by observed limit hits; show
calibration confidence and distinguish estimates from provider-reported usage.

**`usage_sessions`** — top N (default 50 per machine per day by tokens, plus any
session that tripped an alert): `session_hmac, tool, source_type, models[],
efforts[], start, end, calls, turns, tokens, max_context, max_calls_per_turn,
job_fingerprint?, task_label?`.

**`usage_jobs`** — recurring job fingerprints: for `exec` sessions,
`HMAC(cwd + model + effort + first-user-message-shape-hash)` where the shape hash
is a hash of the redacted, number-stripped first 200 chars (computed locally,
never sent). Fields: `runs/day`, `median interval`, tokens/run, model, effort,
first/last seen. Two jobs with the same fingerprint on different machines are
flagged as possible duplicates (E9) by comparing fingerprints built with a
fleet-shared salt in the private overlay (proposed default Q6: enabled on the
reference fleet; public default per-machine only).

Upload channel mirrors disk reports: `POST /v1/usage-reports/{job_id}/chunks` and
`/complete`, 64 KiB per chunk, 2 MiB per run, sequence numbers and digests;
Hub merges idempotently by `(machine, file_key, offset range)`.

### 5.5 Budget

Public defaults (overridable per machine in policy):

| Budget | Default |
| --- | --- |
| CPU | `nice 19`, `ionice -c3` (idle) on Linux; Windows below-normal + low I/O priority |
| Read rate | 20 MiB/s token bucket |
| Bytes per run | 2 GiB |
| Wall time per run | 300 s |
| Memory | 128 MiB RSS cap; streaming line parser, 1 MiB max line (longer lines skipped, counted) |
| Files stat'ed per run | 200,000 (resumable cursor) |
| Pause | Skip run if 1-min load > cores × 0.8 or on battery where detectable (workstations) |

Initial backfill of very large stores (reference: ~371 GB of Codex logs) proceeds
newest-first over many runs, so the last 7 days appear within the first runs and
the last 90 days fill in later under the same scan budget; the UI shows
`backfill: 38% (est. 3 days)`. Ignore events older than 90 days even in recently
modified files; skip files
known to contain only older data. The 400-day Hub retention does not expand
the initial backfill horizon. Cheap
pre-filter: Codex lines are only fully JSON-decoded if they contain the substring
`token_count` (or the turn-context marker); Claude lines only if they contain
`"usage"`. Also decode required session/user-message metadata for attribution,
effort inference and redacted labels. This keeps CPU dominated by I/O.

### 5.6 Schedule

| Schedule | UTC baseline | Purpose |
| --- | --- | --- |
| Incremental scan | `*/15 * * * *` (per-host minute offsets) | Fresh quota-window data |
| Backfill continuation | Same slot while backfill incomplete | Budgeted history |
| Daily close | `20 0 * * *` | Finalize previous UTC day, compute baselines |

`catch_up=false`, overlap prevention and the per-machine maintenance lock from
Phase 2 §3.3 apply; usage scans are read and yield to cleanup/upgrade jobs.
Quota-window freshness target: data ≤ 20 minutes old. Machines offline report on
reconnect; the window view marks stale machines rather than assuming zero.

### 5.7 Account inventory

The Hub discovers logged-in accounts and plans through each agent for Claude
Code, Codex, grok, gh/Copilot, agy/Gemini and other installed tools. Read status
commands and whitelisted non-secret auth metadata (email/login, plan/tier,
expiry); never read token fields, serialize auth files or upload token bytes.
Hash normalized provider identity locally with a stable fleet-wide private
inventory key provisioned from the private overlay to produce `account_id`;
keep the key separate from the job salt
and never upload it. Upload only the hash or redacted display-safe identity,
provider, plan, source/freshness and machine membership.

Refresh each scan; the Hub joins matching IDs into `machines[]` and pools/sums
usage in the account's provider quota windows. Bind usage to the account active
at collection; unresolved historical attribution stays unknown. Cross-check with
existing provider/GitHub dashboards/APIs where available (e.g. GitHub API for
gh/Copilot and exposed provider usage endpoints), keeping credentials local.
Record source, freshness and conflicts; unavailable APIs do not block collection.
Discovery is the default; private overlay overrides/pins of plans or limits take
precedence with visible provenance.

## 6. Hub UI

New top-level **Usage** page (view scope), consistent with the Disk page.

### 6.1 Usage overview

- Range selector (24h / 7d / 30d / custom), filters: machine, tool, model,
  effort, source type, account.
- Charts: stacked daily tokens (uncached / cache read / output) and estimated cost;
  share by effort; share by context bucket; main vs subagent vs exec; 7-day trend
  vs 28-day baseline.
- **Quota-risk indicator** per account: gauges for 5h and weekly windows, current
  pooled consumption across member machines vs discovered/pinned limit, burn rate,
  projected time-to-limit, machine contributions, discovery freshness and
  observed limit hits. Colors: ok / watch (≥70%) / risk (≥85% or projected hit
  within window) / hit. Inventory lists provider, display-safe identity, plan and
  machines. Unknown limit shows consumption only with "set limit".
- **Anomaly list**: open alerts (§8) with severity, machine, first seen, link to
  evidence; acknowledge/resolve actions.
- **Recommendations** panel: cards (§7) with evidence chart, estimated savings,
  confidence and Approve / Dismiss / Snooze (1d, 7d, 30d, custom).
- Collector health strip: last scan per machine, backfill progress, unparsed
  lines, budget exhaustion.

### 6.2 Machine drill-down

Per machine: the same charts scoped to it, per-tool tabs, hourly heatmap, gap
histogram, calls-per-turn distribution, tool-call mix, collector state and the
task-label toggle (admin, preview/apply, on by default, max 40 chars).
Session-level effort inference is shown as "inferred"; missing evidence as "unknown".

### 6.3 Top sessions and recurring jobs

- Top sessions table: session ID (short HMAC or label if enabled), machine, tool,
  source, model/effort mix, duration, calls, max calls/turn, max context, tokens,
  est. cost, alert badges. Sort and filter; detail drawer with per-hour calls.
- Recurring jobs table: fingerprint, machine(s), runs/day, interval, model, effort,
  tokens/day, share of uncached input, duplicate-across-machines flag.

### 6.4 Settings

Usage policy editor (admin, preview/apply, revisioned like disk policies):
discovered account plans/limits with overlay pins, alert thresholds, budgets,
retention, label N (≤40), price
table version. Shows which values come from public defaults vs deployment config.

UI evidence follows §1A: fixture data, no real hostnames, rendering tests and
screenshots in each UI PR.

## 7. Recommendations

### 7.1 Lifecycle and ledger

`usage_recommendations`: `id, rule_id, rule_version, machine_id, scope (account/
machine/session/job), evidence_digest, evidence_window, est_savings_tokens,
est_savings_usd, confidence, state (open|approved|dismissed|snoozed|expired|
superseded), reopen_at, proposer (rule|agent:<token-id>), created_at`.

Every decision goes through the existing `ops_approvals` ledger with a new
operation class `usage-recommendation-v1` (extend `diskOperationValid` into a
generic operation registry), binding `evidence_digest`, recommendation ID and
rule version as the item digest:

- **Approve** → ledger `approved`; recommendation `approved`. Effect: the
  recommendation becomes a tracked action item with an optional generated
  *suggested change* (text snippet / diff for the human to apply, e.g. a config
  line). Nothing is applied by the Hub in this first phase (§7.3). Follow-up measurement compares the next
  7 days against the evidence window and shows "realized savings".
- **Dismiss** → ledger `rejected` with reason; the same rule on the same scope
  is suppressed until the evidence changes materially (digest of bucketed values).
- **Snooze** → ledger `rejected` with `decision_reason` prefix `snooze:` and the
  recommendation's `reopen_at`; it reopens automatically if still valid.
  Proposed default Q5: no new ledger state; `snoozed` is a recommendation state only.

Human decisions require admin (consistent with Phase 2 mutations). Agents may
*propose* (create `open` cards) but not decide.

### 7.2 Rules (generic defaults)

| Rule | Trigger (default) | Evidence | Suggestion |
| --- | --- | --- | --- |
| R1 `lower-effort` | One effort level (max/xhigh/ultra) ≥60% of tokens for a machine/account over 14d, and median calls/turn low or tasks are exec/subagent | E1, E7 | Default to a lower effort; reserve max/xhigh for explicit hard tasks. Show tokens and $ at the lower level using price table |
| R2 `explicit-subagent-model` | Subagent calls inherit the orchestrator's top model/effort and are ≥25% of tokens | E1, E3 | Set an explicit cheaper model/effort for subagents |
| R3 `handoff-new-session` | ≥50% of a session's tokens from calls with context >100k, or session max context >200k | E2, E8, E11 | Write a handoff/summary and start a new session; enable earlier compaction |
| R4 `batch-small-commands` | Main-agent turn with ≥30 calls where ≥70% are short Bash tool calls | E3 | Batch commands into a script or delegate to a cheaper subagent |
| R5 `dedupe-exec-jobs` | Recurring exec job with ≥100 runs/day, or same fingerprint on ≥2 machines, or exec ≥40% of uncached input | E9 | Dedupe/merge jobs, lower frequency, pin a cheaper model, cache results |
| R6 `call-budget` | Any runaway-turn alert in 7d or job tokens/run p90 > 3× median | E3, E9 | Add a per-turn/per-run call budget or max-turns flag to the job/wrapper |
| R7 `quota-pacing` | ≥2 limit hits in 14d, or projected weekly hit | E5 | Shift scheduled exec jobs off peak windows / reduce effort for unattended work |
| R8 (informational) `cache-gap` | Cache rebuild after >1h gap ≥15% of tokens | E4 | Keep-alive not recommended by default; informational only (E4 shows 3.6%) |

Each card shows the evidence chart, the calculation, confidence (high/medium/low,
lowered when effort is `unknown` or data is partial/backfilling), and the
explicit statement "No configuration will be changed" in the advice-only phase;
later-phase cards clearly identify the preview/approval/apply step (§7.3).

### 7.3 Later phase: gated application

First phase is advice-only. Later, a separately reviewed
`ai-cli-config-apply-v1` follows **preview (diff) → admin approval → auto-apply**
for pinned config keys, saving the prior revision for one-click rollback.
Approval binds the exact diff/revision; agents cannot approve. Enable only after
recommendations prove accurate: proposed gate is ≥20 approved, manually applied
recommendations with verified intended results and zero rollbacks over a trailing
30-day window. Unmeasured approvals do not count. Record outcomes in the ledger;
a rollback disables application pending admin review. The gate never replaces
approval of each change.

## 8. Alerts

Evaluated by the Hub after each upload and at daily close; reuse the notifier,
dedup and backoff of Phase 2 §3.4. All alerts are visible in the Usage anomaly list
and UI banners; chat delivery is opt-in. Alerts carry label, severity, safe reason
and an authenticated link — never labels/task text or session paths.

| Alert | Generic default | Severity |
| --- | --- | --- |
| Daily spike | Day tokens > 2.0× trailing 14-day median (same machine+tool) and > 5M tokens | warn; critical at 4× |
| Sustained growth | 7-day avg/day > 1.5× prior 28-day avg (E11) | warn |
| Runaway turn | > 150 calls in one turn, or > 60 calls in 10 min within a turn | warn; critical at 400 or still growing on next scan |
| Long session | Session wall time > 8h with activity in last hour, or > 2,000 calls | warn |
| Context threshold | ≥ 20 calls/day with context > 200k on one session, or any call > 500k | info / warn |
| Quota risk | Window consumption ≥ 85% of discovered/pinned limit, or projected to hit before window reset | warn; critical at 95% / projected < 30 min |
| Limit hit | Observed limit event | info (feeds R7) |
| Exec job burst | Recurring job runs/hour > 3× its median | warn |
| Collector health | No successful scan > 2h (online machine), unparsed lines > 1%, backfill stalled 24h | warn |

Clear after two consecutive evaluations below threshold minus 10%; send recovery
once. Thresholds live in the usage policy; the reference fleet's values are in the
private overlay (§10).

## 9. MCP tools

Proposed prefix `/v1/operator/usage`. Reads require view and are eligible for
service-token route allowlists (default off); propose requires operate plus an
explicit route grant; decisions are human-admin-only and not exposed to tokens.

| MCP tool | Inputs | Output / route |
| --- | --- | --- |
| `usage_summary` | range, group_by (machine/tool/model/effort/source/day), filters | Aggregates; GET `/summary` |
| `usage_machine` | machine_id, range | Drill-down aggregates + collector health; GET `/machines/{id}` |
| `usage_quota_status` | account?, machine? | Window consumption, limit, burn rate, ETA; GET `/quota` |
| `usage_top_sessions` | range, machine?, limit ≤50, sort | Session metadata (no labels unless granted); GET `/sessions` |
| `usage_jobs` | range, machine? | Recurring jobs; GET `/jobs` |
| `usage_anomalies` | state, range | Alerts; GET `/anomalies` |
| `usage_recommendations_list` | state | Cards with evidence digests; GET `/recommendations` |
| `usage_recommendation_propose` | rule_id or `custom`, scope, evidence refs (IDs only), rationale ≤1,000 chars, idempotency key | Creates `open` card marked `proposer=agent`; POST `/recommendations/propose` |

No tool returns raw paths, prompts, task labels (without grant) or session file
names. Agent-proposed cards must reference Hub-held evidence IDs; free-text
rationale is displayed as untrusted text. Rate limit: 20 proposals/day per token.

## 10. Deployment configuration (private overlay only)

| Choice | Public default | Reference deployment (values in private overlay) |
| --- | --- | --- |
| Enabled machines | None; admin enables per machine | The six Linux hosts and D1 |
| Account plans/limits | Discovery + available API/dashboard cross-check; unknown limits show consumption only | Optional overlay pins override discovery with provenance |
| Alert thresholds | §8 values | Tuned from the 30-day baseline |
| Notifier | UI only | Private Telegram/Discord recipient |
| Task labels | On, redacted, max 40 chars | On for all machines; admin may disable |
| Cross-machine job salt | Off | On (to detect duplicated cron jobs) |
| Budgets | §5.5 | Higher read rate on large-store hosts; workstation battery rule on D1 |

## 11. Phased PR plan

| PR | Deliverable | Exit criterion |
| --- | --- | --- |
| U-01 | Schema + store (`usage_accounts`, `usage_daily`, `usage_window`, `usage_sessions`, `usage_jobs`, `usage_recommendations`), generic ops-operation registry, usage policy revisions | Migration tests; idempotent merge tests; ledger accepts `usage-recommendation-v1` |
| U-02 | Agent parsers (Claude, Codex) as pure libraries with golden fixtures | Fixture parity incl. streaming dedupe, cumulative deltas, counter resets, null cache_write, subagent/exec classification |
| U-03 | `ai-usage-scan-v1` collector: account discovery, state, budgets, 90-day backfill, upload channel, schedule; Linux + Windows | Budget/resume/rewrite tests; 50 GB synthetic store stays within budgets |
| U-04 | Usage page: overview, account inventory + pooled quota gauges, machine drill-down, top sessions/jobs, collector health | Rendering tests + fixture screenshots |
| U-05 | Alerts engine + anomaly list + notifier integration | Threshold, dedupe, recovery tests |
| U-06 | Recommendation rules R1–R8, cards, approve/dismiss/snooze via ledger, realized-savings follow-up | Rule fixture tests mapped to E1–E11; ledger tests |
| U-07 | MCP tools + service-token route eligibility | Scope/denial tests; no-leak tests |
| U-08 | Default-on task labels (redaction, restricted storage, grant) | Redaction corpus tests; all-machines default-on/max-40 test |
| U-09 (private) | Overlay config for reference fleet; canary on one workstation for a week, then fleet | Admin reviews canary numbers vs manual diagnostics |
| U-10 (later) | Gated preview → admin approval → auto-apply; one-click rollback | Accuracy gate (§7.3), exact-diff approval, revision conflict and rollback tests |

Each PR: UI + screenshots where applicable, docs, route manifest, MCP schema,
`go test ./internal/scrubguard`. Feature enrollment stays default-off; labels default on once enabled.
U-10 stays disabled until its accuracy gate passes. Never merge without the
admin's request.

## 12. Acceptance tests

1. Re-running the scan on unchanged files changes no aggregate (idempotence).
2. Appended lines are counted exactly once; a truncated/rewritten file is
   recounted with previous contribution subtracted; moved-to-archive files are not
   double counted.
3. Codex cumulative events: duplicates ignored; a decrease starts a new segment;
   totals match a hand-computed fixture to the token.
4. Claude streaming duplicates by `message.id` collapse to one call.
5. `cache_write` missing → stored null; UI shows "not measured"; no rule fires on it.
6. Subagent files classified `subagent`; `codex exec` sessions `exec`.
7. Budgets: run stops at byte/time caps, persists cursor, resumes; load guard skips; Windows uses interactive user and battery guard where available.
8. Reproduce the evidence table: on a synthetic fixture modeled on E1–E11, the
   Usage page and rules show effort share, long-context share, exec share,
   gap rebuild share and limit hits within ±0.5 percentage points.
9. Quota gauge projects time-to-limit and raises quota-risk before a fixture
   limit event.
10. Runaway-turn fixture (200 calls/turn) raises an alert within one scan.
11. Approve/dismiss/snooze each create exactly one ledger row; snooze reopens
    after expiry; no CLI config file on the agent is modified (file hash check).
12. Privacy: canary strings planted in prompts, responses, tool args, paths and
    env appear nowhere in uploads, DB dumps, logs, audit, notifications or MCP
    output. Labels default on, all enabled machines, ≤40 chars; redaction corpus passes.
    Auth/status/API token canaries are never uploaded; token fields are never read.
13. MCP: tokens without grants are denied; propose cannot decide; outputs pass
    the no-leak check.
14. UI works with every integration disabled.
15. Two machines sharing one discovered account sum into one pooled quota window;
    distinct/unknown accounts remain separate. Test plan/membership discovery,
    unavailable APIs, conflicts and overlay pins.
16. Backfill counts only the last 90 days under scan budgets, including mixed-age
    files; older events are ignored.
17. Later application stays disabled below the accuracy gate; exact preview approval
    is required and one-click rollback restores the prior revision.

## 13. Security review notes

- **Read scope.** Runtime profile grants read of fixed session roots and allowlisted
  non-secret account metadata/status sources only; verify no
  path from Hub args, no symlink escape, no mount crossing, `O_NOATIME`.
- **Data minimization.** Field whitelist parser; raw lines never leave the
  function scope; error messages carry no content. Fuzz the parser.
- **HMAC identifiers.** Machine secret 0600, not uploaded, rotated on re-enroll;
  rotation breaks session continuity by design (documented).
- **Task labels.** Highest-risk feature; on by default, redacted, max 40 chars, admin-only toggle,
  restricted column, short retention, no MCP exposure without explicit grant.
- **Upload integrity.** Machine-authenticated, job-bound chunks, size limits,
  digests, idempotent merge; a machine cannot write another machine's usage.
- **Poisoned logs.** Session files are user-writable and may contain adversarial
  content; parser treats all fields as untrusted, clamps numbers (reject negatives,
  > 10M tokens per call flagged), and enum-maps strings.
- **Agent proposals.** Free text is rendered escaped and labeled untrusted; cannot
  approve; rate-limited.
- **Account discovery.** Metadata-only adapters never read token fields or upload
  credentials; status/API outputs are whitelist-filtered locally.
- **No side effects on CLIs (first phase).** No writes to `~/.claude` or `~/.codex`; test by
  hashing the trees before/after.
- **Resource exhaustion.** Budgets and line-length cap protect hosts; Hub caps
  per-run upload size.
- **Cost estimates** are labeled estimates; price table is versioned and public.

## 14. Decisions

**Answered by owner**

- Q1. Agent-mediated account/plan discovery across installed tools is the default;
  non-secret metadata only, with available provider/GitHub dashboards/APIs as
  cross-checks. Stable account hashes join machines into pooled quota windows;
  overlay pins may override discovery (§5.7, §6).
- Q4. Task labels on by default, redacted, max 40 chars, all machines (§4.3).
- Q7. Backfill last 90 days only under scan budgets; ignore older data (§5.5).
- Q9. Advice-only first; later preview → admin approval → auto-apply with one-click
  rollback, enabled only after proven recommendation accuracy (§7.3, U-10).

**Default (proposed, not confirmed by owner)**

- Q2. Estimated cost units calibrated by observed limit hits (§5.4).
- Q3. Session-level effort inference shown as "inferred"; else "unknown" (§5.3).
- Q5. Ledger `rejected` + `snooze:` reason with recommendation `reopen_at`;
  no new ledger state (§7.1).
- Q6. Salted cross-machine job fingerprints enabled on the reference fleet;
  salt in private overlay (§5.4, §10).
- Q8. D1 runs as interactive user through existing Windows agent, load guard on,
  battery guard where available (§5.1, §5.5).
- Q9 accuracy gate parameter: ≥20 approved recommendations with verified intended
  results and no rollback over 30 days (§7.3); later-phase direction is answered.
