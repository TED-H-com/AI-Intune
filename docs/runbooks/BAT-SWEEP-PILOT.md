# BAT sweep report pilot

`bat-sweep-report-v1` requests report-only observations. Its catalog mode is
**write** (write-equivalent approval), so running, scheduling, enabling, and
manually triggering it require **admin**, not operate. The agent still runs it
as a non-root user on Linux with a ten-minute timeout and 64 KiB output cap.
Approving the installed connector implementation is an admin trust decision;
Python attribute wrappers and audit hooks are defense in depth, not a sandbox
or an authorization boundary. This pilot does not request connector writes.

## Connector trust and prerequisites

Choose the enrolled connector-runtime host (neutral example `connector-node`)
where `/usr/bin/python3` is Python 3.11+. Install `bat_agent_connector` into
one of the fixed search locations, in priority order:
`~/.local/lib/pythonX.Y/site-packages`, `/usr/local/lib/pythonX.Y/site-packages`,
`/usr/local/lib/pythonX.Y/dist-packages`, `/usr/lib/python3/dist-packages`.
X.Y is the executor interpreter version. No virtualenv, PYTHONPATH, user-site
startup hooks or `.pth` files are loaded. The agent account must be able to
read its own connector configuration and channel mapping. Keep credentials
on that host, outside Hub arguments and this repository.

An admin reviews the connector source and obtains its tree digest **by hand**,
as the same agent account, with the same interpreter:

```sh
/usr/bin/python3 -I -S -B bat-sweep-report-v1.py --print-connector-digest
```

Use the catalog-pinned copy of the script for this helper; it imports no
connector code. Supply the result as the required `connector_tree_sha256`
argument (64 lowercase hex). The helper and runner use the same deterministic
algorithm: sort all file relative POSIX paths, hash a four-byte big-endian
UTF-8 path length, path bytes, eight-byte big-endian file length and complete
file bytes for each file. Every file, including caches/data, participates.
Keep the tree stable and remove obsolete caches before approving a digest.
The package directory, subdirectories and files must not be group/other
writable; symlinks, nonregular files, `.so`, `.pyd`, `.dll` and `.dylib` files
are refused. Tree contents are limited to 32 MiB. A digest mismatch returns
`status: refused`, `reason: connector_digest_mismatch`, before import.

Python starts with `-I -S -B`. The runner copies every regular connector file
through an `O_NOFOLLOW` source fd into a private `mkdtemp` snapshot (0700),
hashing the exact bytes written with the algorithm above. Only a matching
snapshot is imported. Its isolated search path contains the interpreter's
standard library and the snapshot parent; the original installation is never
an import path. A restricted finder permits only standard-library imports and
that snapshot tree. Unpinned third-party dependencies fail closed. The snapshot
is removed at exit, including digest refusal and connector errors. Source-file
replacement after hashing cannot change the bytes imported.

Digest approval remains an admin trust decision, not an OS sandbox: an approved
implementation can call standard-library/native facilities. Review its internal
HTTP behavior and configuration loaders before approval; wrappers/audit hooks
are defense in depth. The remaining resource-limit open item is streaming
response limits in the bat-agent-connector transport: its dict-returning API
currently decodes responses before the launcher can enforce its decoded budget.
The connector follow-up should enforce limits while streaming and provide
purpose-built read-only HTTP methods/routes below the Python process.

## Arguments and fixed mapping

`hosts` contains 1–8 connector host keys matching `[a-z0-9-]{1,32}`, not Hub
machine IDs. Hub `targets` identifies the single executor host. Optional
`include_excerpts` is a boolean, default false. `channels_file` was removed.

The mapping filename is always
`~/.config/bat-agent-connector/discord-channels.toml`. Each directory component
is opened with a retained directory fd and `O_NOFOLLOW`; the file is opened
relative to that fd with `O_NOFOLLOW`, checked with `fstat`, then read from
that same descriptor. Configuration directories and the regular mapping file
must belong to the agent uid and must not be group/other writable. Symlinks
are refused. Mapping input is limited to 64 KiB. Missing package/configuration
returns exit 0 with `status: unavailable`; missing coverage is not a successful
sweep. Inspect report status independently of job exit status.

## Schedule and evidence

Use [the disabled example](bat-sweep-report-schedule.example.json). Replace
neutral targets/connector keys and the all-zero connector digest placeholder
with private deployment values and the reviewed digest. Confirm the launcher
hash through `script_catalog_list`. As an admin, call `schedule_upsert_preview`
with the example object, review its target, digests, args, disabled flag and
hourly UTC cron `17 * * * *`, then call `schedule_upsert_apply` with the same
object plus its `preview_digest` and a fresh `idempotency_key`. Updates need
the schedule ID and current revision from `schedule_get`. No catch-up is enabled.

Use `schedule_run_now` for the initial report. After verifying coverage,
enable via `schedule_set_enabled_preview` / `schedule_set_enabled_apply`,
preserving revision/digest/idempotency. Connector upgrades require a new
reviewed connector digest and schedule preview/apply; launcher hash changes
also require approving the new catalog hash.

Read the job on `/jobs` or `job_get` / `job_evidence`. Verification stdout is
one JSON report with version, timestamp, per-host lists, counts, would-actions,
needs-human and digest fields. Decision entries contain only the host key,
SHA-256 session ID prefix (12 hex), action category and reason code by default.
No tool-use IDs, raw session IDs, pending prompt text or transcripts are returned.
For local comparisons, hash the old sweep's session IDs using the same algorithm.
Opt-in excerpts redact Basic/Bearer auth, cloud access IDs, private-key blocks,
credential URLs, labeled/structured secrets and long tokens before their
120-character cap. Unknown secrets cannot be guaranteed safe; leave excerpts
disabled for routine evidence/UI output.

## Budgets and comparison

A run requests at most 50 sessions per host and 200 read calls total (including
registry reads). Reaching the 50-session boundary conservatively stops rather
than asserting complete coverage. Each session is fetched once, cached, with
at most 20 messages and 2,000 decoded characters per message. Total decoded
response UTF-8 content is capped at 2 MiB. Oversized responses, excessive
nesting or budgets stop the run with `status: partial`, an explicit reason and
`truncated: true`. A 256 MiB address-space limit backs up checks on responses
already decoded inside the approved connector. Its current dict-returning
API cannot provide pre-decode streaming rejection; the transport follow-up
above must close that remaining resource boundary. Calls inside approved read
implementations also require source review; the launcher counts its own calls.
No `sessions_triage` fanout or Jev call is made: quota classification uses
session state and pinned quota patterns on bounded cached transcripts.

The output stays valid JSON within 64 KiB; `truncated` means shortened output
lists and counts describe the unshortened decisions. The evidence API has
smaller excerpt limits: inspect its truncation metadata before parsing stdout.
No supervisor state is read/written under `~/.local/state`.

For seven days, compare against the old sweep's manual `--dry-run` on the same
keys/mapping and comparable timestamps. Record job IDs, timestamps, structured
count differences and explanations, never credentials/raw transcripts. Compare
permission classifications, recent quota failovers, milestones, nudge caps and
Ted-active skips. The reference regexes/time windows remain: Ted-active 30m,
idle 10m, keep-going 72h, failover 2h, 3 nudges/2 failovers per host,
6 nudges per session per local day. Retired/superseded sessions are excluded.
Bounded transcript history can be incomplete; a full 20-message window prevents
a nudge recommendation. Cleanup gates (`session_cleanup` even dry-run) and
ambiguous Jev judgments are explicitly unknown and need human review. Persistent
notification dedup is absent; repeated needs-human items remain visible.

Design §4 success criteria: same digest as the old script, zero unapproved
destructive actions, every action visible in the audit log. Account for all
bounded-history, quota, cleanup/Jev and dedup differences before declaring full
parity. Verify every scheduled run's evidence/audit attribution and no connector
writes. Review hourly for two missed intervals, >10% failures in 24h or >15m
schedule lag, per design §5. Auto-approval remains a separate future change.

## Schedule approval-mode upgrade

Schedules retain the server-resolved `execution_mode` approved through upsert.
The additive migration leaves existing schedules at the empty value; it does
not infer historical approval from the current catalog. When a due schedule's
mode is missing or differs from the catalog, the Hub disables it, increments
its revision, records `mode_changed` in the scheduler audit, and emits no jobs.
A hash change still pauses with `script_changed`. Re-enable requires a fresh
upsert preview and approval; set-enabled cannot bypass either pause.

Before rollout, inspect a consistent backup of each target Hub. After applying
the additive migration to the backup, the following read-only query must return
zero to establish that no schedules need explicit mode reapproval:

```sql
SELECT COUNT(*) AS schedules_requiring_mode_reapproval
FROM schedules WHERE execution_mode = '';
```

The available upgrade database snapshot (669,442,048 bytes, file timestamp
2026-10-10 15:48 UTC) was checked read-only on 2026-10-11. It has no `schedules`
table and no WAL sidecar, so it contains no legacy schedules. This establishes
only the contents of that snapshot, not the current state of a running Hub or
other deployment databases. If a pre-upgrade backup has a schedules table but
no execution_mode column, every row requires reapproval after migration.

New immediate-script receipts use `script-v2:sha256:` request digests with the
approved mode bound into the hash. Existing unversioned `sha256:` receipts can
replay only when the exact historical normalized request digest matches (the
pre-mode format or the earlier mode-bound format). Reuse the original key and
request to recover its stored receipt; a legacy preview never authorizes a new
execution under a fresh key.
