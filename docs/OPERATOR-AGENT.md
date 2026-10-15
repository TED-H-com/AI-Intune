# Operator MCP and CLI

`clawctl-operator` is a client of the existing Hub JSON API (`/v1/operator/*`).
The Web UI uses the same routes. This process does not open SQLite and does
not add an operator login.

Deploy Hub first: [DEPLOY-OSS.md](DEPLOY-OSS.md). The agent procedure is
[`skills/clawctl-operator/SKILL.md`](../skills/clawctl-operator/SKILL.md).

## Identity

Run `clawctl-operator` on a tailnet node that already has the Hub grants
(`view`, `operate`, `admin` as separate keys). Hub calls Tailscale LocalAPI
`WhoIs` on the TCP source of each request. The source address is the node
this process runs on.

Set the origin with `--hub-url` or `CLAWCTL_HUB_URL`:

```text
http://<hub-tailscale-ipv4>:<port>
```

`<port>` is the port in Hub's `CLAWCTL_LISTEN`. Hub has no production default
port. `8787` in other examples is only the conventional example. The `--listen`
flag default `127.0.0.1:8770` is refused.

That is the same literal Tailscale listener as the operator UI. There is no
path, userinfo, query, or `https` hostname for this client. The command sends
no `Authorization` header and does not read `X-Forwarded-*`. A proxy in the
environment is not used.

`clawctl-hub` subcommands can still discover `operator.json`. This binary does
not. Pass the origin explicitly so an agent does not pick up another file.

The HTTP user agent is the shared operator client. It is a label in the audit
trail, not a credential.

Capability is still the route's existing requirement. A read uses `view`. A
deployment continue preview uses `operate`. Enrollment, deployment create,
abandon, profile assignment, and every disk-clean write use `admin`.
Disk-clean reads use `view`. Missing a grant is an error from Hub. The tool
does not retry with a different identity.

## Commands

```bash
make operator
./build/clawctl-operator --hub-url "$CLAWCTL_HUB_URL" tools
./build/clawctl-operator --hub-url "$CLAWCTL_HUB_URL" call fleet_overview
./build/clawctl-operator --hub-url "$CLAWCTL_HUB_URL" mcp
```

`mcp` speaks newline-delimited JSON-RPC on stdin/stdout (one JSON object per
line). It also accepts a `Content-Length` request frame and still answers with
one JSON line. Logs stay off stdout.

`call <tool> [json]` prints the tool result as one JSON line. Errors go to
stderr as `{"code","message"}`.

Local argument errors use code `invalid_arguments`: bad JSON, a missing or
invalid field, an unknown tool, and an unknown field. An unknown field is
named, and the message lists the allowed fields for that tool (`(none)` when
the tool takes no fields). Errors that come back from Hub keep the Hub code.
A transport failure that is not a Hub error object stays `hub_error`.
`preview_digest_required`, `expected_revision_required`, and `canary_blocked`
stay their own codes. The MCP `tools/call` path and the CLI `call` path use
the same `Call` result.

`initialize` reports `serverInfo.version` as this binary's build version
(`main.version`, injected with `-ldflags`, `dev` when unset). That is not a
protocol constant. Protocol version negotiation is unchanged.

`tools/list` includes MCP `annotations` on every tool: `readOnlyHint` (true
for reads and previews), `destructiveHint` (true for apply, continue, expand,
abandon, and profile assignment; false for `enroll_ticket_create`),
`idempotentHint` (true for reads, previews, and writes that take an
idempotency key), and `openWorldHint: false`. Input schemas set `enum`,
`minLength` / `maxLength` / `pattern`, and `minimum` / `maximum` from the Hub
validators, plus `additionalProperties: false` and `required`. They do not
add a tighter limit than Hub enforces. `expected_control_revision` has a
minimum and no JSON Schema maximum, because the Hub maximum is the maximum
int64.

## Tools

Reads: `fleet_overview`, `machines_list`, `machine_get`, `machine_evidence`,
`jobs_list`, `job_get`, `job_evidence`, `deployments_list`, `deployment_get`,
`software_report`, `compliance`, `rollout_status`, `disk_clean_summaries`,
`disk_clean_summary`.

Previews (they return `preview_digest`): `enroll_ticket_preview`,
`deployment_create_preview`, `deployment_continue_preview`,
`deployment_abandon_preview`, `profile_assignment_preview`, `rollout_preview`,
`disk_clean_profile_preview`, `disk_clean_dry_run_preview`,
`disk_clean_canary_preview`, `disk_clean_continue_preview`,
`disk_clean_abandon_preview`.

Writes: `enroll_ticket_create`, `deployment_create`, `deployment_continue`,
`deployment_abandon`, `profile_assignment_apply`, `rollout_apply`,
`rollout_expand`, `disk_clean_profile_publish`, `disk_clean_dry_run_apply`,
`disk_clean_canary_apply`, `disk_clean_continue_apply`,
`disk_clean_abandon_apply`.

A write requires `preview_digest` copied from a preview response
(`sha256:` and 64 lowercase hex). The write call does not create a preview
for you. Deployment continue, abandon, and `rollout_expand` also require
`expected_control_revision` and `expected_opened_batch` from the deployment
you just read, plus an `idempotency_key` you choose and reuse for a retry.
Disk-clean continue and abandon use the same two fields from
`disk_clean_continue_preview` or `disk_clean_abandon_preview`. Profile publish
uses `expected_revision` from `disk_clean_profile_preview` (`current_revision`,
which is 0 when the scope has no revision yet).

## Disk-clean

`disk_clean_*` does not call the artifact deployment tools. Publish a profile,
run a dry-run, read the evidence, then open a canary of exactly one machine.
`disk_clean_continue_apply` is the only way to open the rest.
`disk_clean_abandon_apply` opens nothing more. The design is
[MAINTENANCE-DISK-CLEAN.md](MAINTENANCE-DISK-CLEAN.md).

`fleet_overview` is the first page of `GET /v1/operator/machines`. Totals are
the fleet index. `page_truncated: true` means `items` are not every machine.

## Canary rollout

The phase names live in `internal/rollout`. The deployment page, `rollout_status`,
and `rollout_preview` all use `AssessCanary`.

1. `rollout_preview` calls deployment create preview with `batch_size` 1
   (omit the field, or set 1). Any other batch size is rejected before HTTP.
2. Read `canary.phase` and `preview.create_allowed`. The first included batch
   must be exactly one machine (`singular_canary`). The preview lists that
   machine.
3. `rollout_apply` sends that `preview_digest`. It does not preview again.
4. Poll `rollout_status`.
   - `canary_pending`: Hub has not marked the canary job `succeeded`. Wait.
   - `canary_stopped` or `expand_stopped`: stop. `rollout_expand` returns
     `canary_blocked` and does not send Continue.
   - `ready_to_expand` while the deployment is `running`: poll. A new
     deployment pauses after the Hub `succeeded` verdict; `rollout_expand`
     does not open the next batch while it is still running. A deployment
     created before that hold (`pause_after_canary` false) still lets the
     driver open the next batch.
   - `ready_to_expand` while `paused`: `deployment_continue_preview`, then
     `rollout_expand` with that digest and the revision from the status.
   - `expanding`: a later batch is open. Poll.
   - `finished`: included machines are `succeeded`.
   - `not_a_single_canary`: this deployment's first batch is more than one
     machine. Do not treat it as this rollout.

`succeeded` is the state Hub writes after the stored verification evidence.
An agent `finish_work` only enters `verifying`. The cross-failure-domain
verdict is reported as `canary_independent` and does not move the phase.
Stable promotion stays on the existing gate (`promotion_gate`).

The deployment page shows the same phase, the same reason, and the same
rollback lines. Continue, skip failed batch, and Abandon stay on that page.
Plain Continue refuses a failed batch. skip failed batch is a separate
button and `POST /v1/operator/deployments/{id}/skip-failed-batches`. It has
its own preview digest and records a reason. MCP tools do not send that skip.
`deployment_continue` returns `failed_batch_skip_refused` and does not write.

New operator creates and retries set `pause_after_canary`. The first included
machine is batch 1. An omitted `batch_size` means later batches are also 1.
An explicit `batch_size` of 2–5 sizes only the later batches. Existing
in-flight rows stay `pause_after_canary` 0, so their driver still opens the
next batch after a succeeded canary. Continue's refusal of a failed batch
applies to those paused deployments too.

The new-deployment form defaults the later batch size to 1. `rollout_preview`
and `rollout_apply` still reject any batch size other than 1 before HTTP.

## Rollback

`canary.rollback` is the list. In short:

- Nothing rolls the whole fleet back to the previous artifact.
- Abandon stops new jobs. A machine whose job already succeeded stays that way.
- `failed` is Hub closing a reversible job as returned to the previous version.
- `manual_intervention` has no rollback evidence.
- `rejected` means the machine did not apply the job.
- `lease_expired` means the agent stopped reporting. The machine contents are unknown.
- Stable promotion is a separate preview. A passed canary batch is not that promotion.

## Unreachable machine

Hub judges reachability from outbound check-ins. A missing check-in is not a
successful machine. Read `machine_get` and `machine_evidence`. Leave the
deployment paused.

The machine page's Connect BAT line shows the Tailscale address and a command
for the BAT client. Hub does not open that session. Where this build has the
Linux terminal action, it is on that machine page for the assigned user.
SSH you already have is the other break-glass path. None of those is a Hub
verdict. Do not call `rollout_expand` or `deployment_continue` to skip the
machine, and do not report the rollout succeeded.

## Secrets

Do not commit `hub.env`, enrollment tokens, or `CLAWCTL_HUB_URL` values that
are private to a tailnet if your policy treats them as secret. The example
files in `ops/docker/` stay examples.

## Embedded script catalog

`script_catalog_list` reads the view-scoped build-time allowlist.
`script_run_preview` validates hash, closed args, timeout, reason and 1–50 explicit
machine IDs. `script_run_apply` requires that preview's `preview_digest` and an
`idempotency_key`; it never calls preview itself. Read scripts require `operate`;
write scripts require `admin`. Only the harmless
Linux `fleet-probe-v1` is registered in phase 1. The agent runs without elevation
and refuses root execution. Output is capped/redacted job evidence; audit stores
only metadata/digests. Use `job_get` / `job_evidence` to inspect resulting jobs.

Script preview/apply, schedule upsert/set-enabled preview/apply, and schedule
run-now share a process-local token bucket: 30 requests/minute per
verified authenticated subject (burst 30), plus 300 requests/minute globally (burst 300).
Changing node, source address, forwarded headers, action, or idempotency key does not
reset a subject's allowance. Admission runs before decoding or auditing and includes
apply replays and rejected requests. Exhaustion returns HTTP 429 with the existing
JSON `RATE_LIMITED` error, `Cache-Control: no-store`, and `Retry-After: 2`; it does not
write an audit row. Buckets reset on Hub restart and are not shared across processes.
Each admitted preview/apply request records one bounded audit row: script/hash and args
digest, counts and digests of the full ordered target/job lists. Apply receipts retain
all job IDs; completion audit remains per job. Job fanout, receipt, and request audit
still commit atomically.

Schedule tools: `schedule_list`, `schedule_get` (view),
`schedule_upsert_preview` / `schedule_upsert_apply`,
`schedule_set_enabled_preview` / `schedule_set_enabled_apply`, and
`schedule_run_now` (operate for read scripts; admin for write scripts).
Apply requires the matching preview digest, idempotency key, and current
`expected_revision`; use zero for a new schedule. Cron is five-field numeric,
evaluated in optional `tz` (IANA location; omitted means `UTC`), with a
five-minute minimum. Missed runs are discarded, overlaps are audited and skipped.
A changed catalog hash pauses the schedule until an upsert approves the new hash.
Run-now requires an `idempotency_key` and replays the original job IDs across
minutes and restarts. Manual receipts use a separate operation namespace from
cron slots. Late ticks and startup record `skipped_late` / `skipped_restart`
receipts and bounded scheduler audit entries describing the discarded range.

For the report-only BAT pilot, use `bat-sweep-report-v1` from
`script_catalog_list` with connector host keys in `args.hosts` and the connector
runtime machine in `targets`. Supply the reviewed `connector_tree_sha256`;
admin scope is required to run/schedule this report-only, write-equivalent entry.
`include_excerpts` defaults to false; the mapping filename is fixed. Its timeout
is bounded at 600 seconds. The
[runbook](runbooks/BAT-SWEEP-PILOT.md) includes the disabled schedule example,
preview/apply workflow and one-week comparison criteria.

## Supervision tools

`jobs_summary`, `approvals_summary`, and `hub_status` call the corresponding
`GET /v1/operator/{jobs-summary,approvals-summary,hub-status}` APIs with `view`.
All have `readOnlyHint=true` and closed argument schemas. Jobs accept `kind`,
`machine_id`, `per_machine`, and `window` (`24h` or `7d`); approvals accept
`window`; status accepts no arguments. Omit window for both rolling windows.
Null metrics/flags mean unavailable evidence, not healthy or zero. In particular,
this branch does not persist successful previews or pending approvals, scheduler
cadence, or Litestream sync telemetry. Partial scans explicitly return
`truncated`; clients must not treat their counts as complete. See
[the supervision contract](API-SURFACE.md#read-only-supervision) for definitions.

Supervision replies include `cached_at`: successful data is reused for up to
30 seconds. All three tools share the authenticated subject's request budget
(burst 10, refill 30/minute), including cache hits. Saturated computations or
exhausted budgets return 429 (`SUPERVISION_BUSY` / `SUPERVISION_RATE_LIMITED`)
with `Retry-After: 2`; retry after that delay rather than issuing parallel reads.

## Service token client

For a public HTTPS Hub, use `clawctl-operator --hub-url https://hub.example.com --token-file /path/to/token mcp` (or `call <tool> [json]`). The file must be regular, mode 0600, and not a symlink. Redirects and ambient proxies remain disabled. Tailnet literal-origin mode is unchanged when no token file is supplied.

Create and revoke tokens at `/account/service-tokens` with a human admin session and MFA. Tokens expire within 90 days and support `view`, `operate`, and `operator-admin`. A nonempty allowlist is required. Entries are exact method plus registered eligible route pattern, such as `GET /v1/operator/machines` or `GET /v1/operator/machines/{id}`. Read-only view JSON routes and the two read-script routes described below are service-token eligible. The routine administration routes below additionally accept `operator-admin`; other admin and approval-gated routes require a human. Source CIDRs and failure limiter keys use the configured client-IP resolver. Forwarded client headers are accepted only from configured trusted proxies.


### Service tokens and ad hoc catalog scripts

Hermes service tokens with `operate` scope may allowlist exactly
`POST /v1/operator/script-runs/preview` (`script_run_preview`) and
`POST /v1/operator/script-runs` (`script_run_apply`). The manifest uses
`serviceEligibleReadScriptsOnly`; view-scope tokens cannot include these routes.
Both handler and store re-check the current embedded catalog on every preview
and apply, before digest validation or idempotency replay. The script must exist
with mode `read`. Unknown scripts and every other mode return 403
`SERVICE_TOKEN_READ_SCRIPTS_ONLY` with a denial audit row. Write scripts,
including the admin-approved write-equivalent `bat-sweep-report-v1`, remain
human admin only. A human write preview cannot authorize a token apply, and a
token preview cannot authorize an apply after the script becomes write-class.
The catalog includes read-class `fleet-probe-v1` and write-class
`bat-sweep-report-v1`.

Script request rate limits still apply to service tokens, shared across preview
and apply by stable `service:<name>` subject. Success and denial audits retain
that service identity. Existing bounded rate-limit denial auditing still applies.

Schedule list/get, upsert and set-enabled preview/apply
(`POST /v1/operator/schedules/{operation}/{phase}`), and run-now
(`POST /v1/operator/schedules/{id}/run-now`) accept explicitly allowlisted
`operator-admin` tokens. `view` and `operate` tokens cannot manage schedules.
Catalog approval, revision, preview digest, idempotency and rate-limit checks
still apply to delegated actions.
No routes or capability tallies changed.

## Hermes credential lifecycle

Create a token through the admin Account security → Service tokens page:
name `hermes`, scope `operate`, 90 days, **Create with Hermes default**.
The preset includes jobs_summary, approvals_summary, hub_status, job
list/get/evidence, and READ-only script-runs preview/apply. Save the displayed
credential immediately into a regular mode-0600 file on the Hermes host.

Service tokens cannot mint or rotate credentials, including their own. The
legacy `token rotate` command and POST rotate route return 403
`SERVICE_TOKEN_ACTION_FORBIDDEN`. Have a human admin create a replacement token
at `/account/service-tokens`, install it in the bot's regular mode-0600 file,
and revoke the old token. Do not enable unattended rotation timers. Existing
rotation-chain metadata does not grant permission to rotate.

### Delegating routine administration

Choose **Operator admin — routine fleet administration** on the token creation
page (`scope=operator-admin` in the creation form). The scope includes eligible
view/read-script access and allows these explicitly allowlisted JSON operations:

- Create enrollment tickets (preview and apply).
- List/read, create/edit, enable/disable and run schedules, including approved write schedules.
- Assign profiles (preview and apply).
- Create and run deployments, including continuation and retry.

Bots of every scope are forbidden from deleting machines or tenants, changing
MFA/authentication settings, creating or editing users, and minting or rotating
service tokens. These return `SERVICE_TOKEN_ACTION_FORBIDDEN`; lower scopes
requesting routine admin operations return `SERVICE_TOKEN_SCOPE_REQUIRED`.
The allowlist, CIDRs, catalog approval, preview digest, revision and idempotency
requirements remain in force. Unknown routes default to human-only.

For example, an enrollment bot can allowlist just:

```text
POST /v1/operator/enrollment-tokens/preview
POST /v1/operator/enrollment-tokens
```

A scheduling bot can allowlist:

```text
GET /v1/operator/schedules
GET /v1/operator/schedules/{id}
POST /v1/operator/schedules/{operation}/{phase}
POST /v1/operator/schedules/{id}/run-now
```

Use the registered route patterns literally in the allowlist; substitute IDs and
operations in actual requests. Supply a normal audit reason such as
`rotate disk on sampleagent1, per ticket #42`; never include credentials. Keep
fleet-specific bot names, routes, hostnames and configuration in the Private overlay.


### Human schedules UI and timezone behavior

The Hub’s **Schedules** entry beside Disk pages opens `/tenant/schedules`.
View permits list/detail access; Operate permits preview/apply/run-now. Catalog
write scripts require Admin, including changes to an existing write schedule.
Human admin apply and run-now use the same session MFA window as Disk; expired forms prompt for MFA and retain their inputs.
The pages use session authentication, cross-origin protection, audit, script
mutation rate limits, catalog approvals and the shared operator/store functions.
Changes and enable/disable require preview digest, idempotency key and expected
revision. Run-now requires confirmation and an idempotency key; retrying a
confirmed form replays the original receipt rather than enqueueing another run.

Schedule JSON now includes `tz`. Upsert accepts optional `tz`; existing rows
migrate to `UTC`. The timezone is validated with `time.LoadLocation` and bound
into the normalized preview digest. The UI defaults new schedules to
`America/New_York`; API omission continues to mean UTC. Set-enabled preserves
the stored timezone and does not accept a timezone change.

Cron slots are wall-clock times in that location, persisted as UTC instants.
For example `0 12 * * *` with `America/New_York` stays noon across DST.
Nonexistent wall minutes during the spring gap are skipped. Repeated wall
minutes during the autumn overlap run **once, at the first occurrence**.
No catch-up is performed after restart or late scheduler ticks. Next-run
previews show three local times alongside UTC. Disabled schedules show their
computed next slot for reference; they are not dispatched.
