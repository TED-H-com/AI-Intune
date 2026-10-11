# BAT sweep report pilot

`bat-sweep-report-v1` runs Python 3.11+ as the non-root agent user on Linux,
with a ten-minute timeout and a 64 KiB output cap. It produces one JSON report;
it never approves prompts, changes permissions, fails over, cleans up, nudges,
or calls Jev. Hub schedules and audits the normal `script_v1` job.

Choose the enrolled connector-runtime host (neutral example: `connector-node`)
where `/usr/bin/python3` can import `bat_agent_connector`. Install the optional
package into that interpreter's system or agent-user site directory; executor
jobs do not inherit virtualenv, PYTHONPATH, or credential environment variables.
The agent account must be able to read its own connector configuration and
`~/.config/bat-agent-connector/discord-channels.toml`. Python must support
`tomllib`. Keep credentials on that host, outside this repository and Hub args.
The fixed Python runner resolves HOME from the agent's OS account.

`args.hosts` contains 1–8 connector host keys matching `[a-z0-9-]{1,32}`,
not Hub machine IDs. Hub `targets` identifies the single executor host.
An optional `channels_file` must resolve inside that agent account's
`~/.config/bat-agent-connector/`; symlink escapes are refused. Missing package,
config, or channel mapping produces exit 0 and `status: unavailable`; this is
missing coverage, not a successful sweep. Connector read failures produce a
partial report. Review status as well as job exit status.

Use [the disabled schedule example](bat-sweep-report-schedule.example.json).
Replace only neutral targets/connector keys with private deployment values.
Read `script_catalog_list` and confirm the approved script hash. Call
`schedule_upsert_preview` with the example object, inspect the exact target,
args, disabled flag and hourly UTC cron `17 * * * *`, then call
`schedule_upsert_apply` with the identical object plus the returned
`preview_digest` and a fresh `idempotency_key`. These require `operate` for
this read script. For an update, include the schedule ID and current revision
from `schedule_get`. Creating the example leaves the schedule disabled.
Use `schedule_run_now` for an initial report. Once coverage is verified, enable
through `schedule_set_enabled_preview` / `schedule_set_enabled_apply`, preserving
the revision, digest and idempotency protocol. No catch-up is enabled.

Read the resulting job on `/jobs` or through `job_get` / `job_evidence`.
Verification stdout contains the JSON report: `schema_version`, UTC
`generated_at`, per-host decision lists, `counts`, `would_actions`,
`needs_human`, and the short `digest`. Excerpts are redacted before their
120-character cap. The report preserves valid JSON within 64 KiB and marks
`truncated` when lists are shortened; counts describe the unshortened report.
The evidence API has its own smaller field limits: inspect truncation metadata
before parsing stdout, and use stored job evidence when the API excerpt is
incomplete. Never place raw transcripts or credentials in comparison notes.

For seven days, run beside the old sweep's **manual `--dry-run`**, against the
same connector keys and channel mappings, at comparable timestamps. Compare
safe approvals, destructive escalations, recent quota failovers, milestones,
nudge eligibility, caps, Ted-active skips and digest counts. Record job IDs,
timestamps, redacted discrepancies and their explanations. Do not enable the
old sweep's write path during the pilot.

The reference's regexes and time windows are ported unchanged: Ted active 30m,
minimum idle 10m, keep-going 72h, recent failover 2h, at most 3 nudges and 2
failovers per host, at most 6 nudges per session per local day. Retired and
superseded registry sessions are excluded. Daily nudge history is inferred
from up to 500 transcript messages; incomplete history prevents a nudge.
No supervisor state is read or written under `~/.local/state`.

Two reference decisions cannot be reproduced through the permitted reads:
`session_cleanup` (even dry-run) is forbidden, so cleanup gates are explicitly
`cleanup_unknown` and need human review; ambiguous stop points formerly judged
by Jev also need human review. Explicit BAT-STATUS and milestone rules remain
available. Quota triage uses `use_jev="never"`. These are comparison gaps, never
positive cleanup or nudge recommendations. State-based notification dedup is
also absent, so recurring needs-human items remain visible in every report.

Design §4 success criteria are the same digest as the old script, zero
unapproved destructive actions, and every action visible in the audit log.
The report-only pilot must demonstrate equivalent deterministic classifications
and account for every digest difference above; unresolved cleanup/Jev/history
gaps prevent declaring full digest parity. Verify that every scheduled run has
job evidence and audit attribution, and that no connector writes occurred.
Review hourly for two missed intervals, failures above 10% in 24h, or schedule
lag above 15m, following design §5 supervision. Auto-approval is a separate
future change requiring a reviewed policy and human approval for exceptions.
