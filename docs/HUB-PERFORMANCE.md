# Hub observation storage and diagnostics

`observed_latest` keeps one row per machine/kind/subject, ordered by Hub
`received_at`, then agent `measured_at`, then the history insertion sequence.
An insert trigger updates it inside the history writer transaction, including
non-agent insert paths. Startup backfills at most 2000 groups per transaction,
yields between batches, and safely repeats the same conditional upsert. Retention
continues to protect both clock maxima in history; it never prunes the projection.
The projection cascades on machine deletion, not retirement.

Current dashboard, fleet tools (including MCP), machine detail and verdict reads
use this projection. Historical evaluation instants fall back to history only for
groups whose current row is after the cutoff. Ticket windows, change comparisons,
credential history and source-specific identity evidence remain history queries.

`CLAWCTL_OBS_UNCHANGED_INTERVAL` (or `-obs-unchanged-interval`) defaults to `30m`.
`0` disables suppression. An identical `cli_tool` or `systemd` payload inside that
interval writes neither history nor the projection, including its timestamps.
Changed payloads are always recorded. The interval is measured with Hub receipt
time, not the agent clock. Grep review of the store, operator, web and MCP readers
found these kinds used for current facts, version/process/unit information and
change comparisons; none counts every report or imposes a shorter freshness
threshold on these rows. Machine freshness comes from check-ins. Displayed
observation timestamps therefore mean last stored evidence, not last report.
Change comparisons retain changed snapshots; repeated identical reports are not
evidence of additional changes.

HTTP request duration logs use structured fields `method`, `route`, `status`, and
`duration_ms`. Unmatched requests log `unmatched`. IDs and query strings are not
included. Requests over `CLAWCTL_SLOW_REQUEST_MS` (a positive integer in
milliseconds, default `1000`) log at WARN; other requests log at INFO. Invalid
thresholds emit a warning and use the default. Streaming and websocket upgrades
are retained.

`-pprof` or `CLAWCTL_HUB_PPROF=1` enables `/debug/pprof/`. It defaults off and
uses the existing operator boundary with human admin permission, pinned authority
and no service-token access. The default HTTP mux is never served.

Run the local performance comparison with:

```sh
CLAWCTL_PERF=1 go test -run TestHubPerfCompare -v ./internal/store/
```

The dashboard case seeds 400,000 history rows across 50 machines and compares the
former fleet-tools MAX-subquery with the projection. Cold means a fresh SQLite
reader connection/page cache; it does not flush the operating system's file cache.
