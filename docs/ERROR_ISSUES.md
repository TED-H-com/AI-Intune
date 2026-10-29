# Fleet error logging: implementation notes (issue filer)

Error records are defined by `internal/errlog`. The Hub stores telemetry in its
separate `.errors.sqlite` WAL database; ingestion and read access are documented
in [ERROR_API.md](../ERROR_API.md).

## Automatic GitHub Issues

The Hub issue filer is opt-in. It runs once at startup, then every 15 minutes,
using all error records in the preceding 24 hours. Only `level=error` fingerprints
with at least three occurrences or at least two distinct machine IDs qualify.
Future timestamps are excluded. Other levels do not contribute to promotion.

| Setting | Default |
| --- | --- |
| `ERROR_ISSUES_ENABLED` | `false` |
| `ERROR_ISSUES_DRY_RUN` | `false` |
| `ERROR_ISSUES_INTERVAL` | `15m` (positive Go duration) |
| `ERROR_ISSUES_TOKEN_FILE` | required outside dry run |
| `ERROR_ISSUES_INTUNE_REPO` | `TED-H-com/AI-Intune` |
| `ERROR_ISSUES_BAT_REPO` | `TED-H-com/bat-agent-connector` |

Components starting with `intune` go to the Intune repository. `bat-connector`,
`bat-tunnel`, `bat-session`, `fleet-monitor`, and `bat-server` go to the BAT
repository. Other components are excluded. The GitHub token must be in a regular
file owned by uid 0 with mode exactly 0600. It is never loaded from an environment
variable. Grant the token issue read/write access to the configured repositories.
The filer creates missing labels, requiring permission to manage issue labels.
Invalid token file configuration prevents Hub startup when filing is enabled.
The default disabled setting starts no filer job and reads no token file.

Issues carry `auto-filed`, `component:<name>`, and `fp:<fingerprint>` labels, plus
an HTML `<!-- fp:FINGERPRINT -->` marker. REST lookups use the fingerprint label
and include closed issues. Open issues receive updated counts at most once per
24 hours, and only after a newer occurrence. Recurrence after closure reopens the
issue and adds `regression`, without replacing existing labels. The closure time
and locally persisted last-seen timestamp prevent reopening on old evidence.

SQLite persists rolling hourly and daily creation reservations and successful
update timestamps across restarts. Each repository has a strict total cap of
five creations per rolling hour and twenty per rolling 24 hours. One slot in
each window is reserved for the overflow digest, leaving four ordinary creations
per hour and nineteen per day. Overflow is aggregated into a single repository
issue with `fp:error-overflow-digest`, updated at most daily and reopened on
recurrence. Existing issues and comments consume no creation slots. Reservations
are made before requests; failed requests release their reservation. An interrupted
request can conservatively retain its slot until the rolling window expires.

A 404 or 410 response marks the repository unavailable for the process lifetime,
logs once, and skips further work there without failing the job. Restart the Hub
after enabling Issues or changing repository access. Other repositories continue.

Issue content includes code, component, versions, machine IDs, 24-hour counts,
first/last seen, and at most five message samples per issue. Context maps
are excluded. Titles, bodies, and labels are redacted again before use; any
remaining recognized secret pattern rejects the action. Dry run makes no GitHub
calls and logs the sanitized candidate and possible file/comment/reopen actions;
it cannot determine remote issue state. It consumes no budget or update timestamp.
Successful external updates have structured `error_issue_updated` Hub audit events.

Enable on the Hub host by setting the variables above in its service environment,
installing the token file as root with `chmod 0600`, and restarting the Hub. Start
with `ERROR_ISSUES_DRY_RUN=true` to inspect redacted candidates, then switch it to
`false` and restart. No Web, CLI, or API control is added for this background job.
