# Hub reliability: database contention, notify delivery, metrics

This page describes how the Hub behaves under SQLite lock contention, how the
daily report notification retries, and which metrics and alert rules cover
both. It complements [DEPLOY-OSS.md](DEPLOY-OSS.md) and
[OPERATOR-AUTH.md](OPERATOR-AUTH.md).

## SQLite: one writer, a reader pool

- The store opens the database file twice:
  - a **writer** pool with exactly one connection (`journal_mode=WAL`,
    `synchronous=NORMAL`, `foreign_keys=ON`, `busy_timeout=10000`,
    `BEGIN IMMEDIATE` for write transactions);
  - a **reader** pool of up to 8 `query_only` connections
    (`synchronous=NORMAL`, `busy_timeout=10000`).
- In-process writers queue for the single writer connection instead of racing
  SQLite's busy handler. A writer waits at most 15 seconds for the queue; after
  that the request fails with a "hub busy" error instead of hanging.
- `busy_timeout` remains the backstop for other processes that touch the file
  (Litestream, an offline CLI, upgrade scripts).
- WAL with `synchronous=NORMAL` cannot corrupt the database. A power loss can
  drop the most recent commits that were not yet checkpointed.
- The agent job poll (`GET /v1/jobs/next`) reads on the reader pool and only
  takes the writer when a dependency-blocked child job actually has to be
  rejected.
- Scheduled retention prune deletes in batches of 5000 rows. Each batch and
  its `retention_log` row commit in one transaction, so the writer is never
  held for one unbounded `DELETE` and evidence never disappears without its
  log row.

## Busy responses: 503 + Retry-After

When a request loses on lock contention (SQLite `SQLITE_BUSY`/`SQLITE_LOCKED`,
or the 15 second writer-queue timeout):

- the machine plane (check-in, observations, readiness, enroll, jobs,
  artifacts, verifier routes) answers **503** with `Retry-After: <5..15>`
  seconds (random, to spread retries) and body
  `{"code":"HUB_BUSY","message":"the hub is busy; retry shortly"}`;
- agent authentication answers 503 on contention, 401 only for an invalid
  token, and 500 for other errors. Contention never looks like a revoked
  token;
- operator JSON/HTML errors that go through `operator.HTTPError` map
  contention to the same 503 + `HUB_BUSY`.

The agent honors `Retry-After` (capped at 5 minutes) on 503 and 429:

- job event/verification POSTs retry with full-jitter exponential backoff
  (500 ms base, 30 s cap), never sooner than `Retry-After`;
- the job poll backs off exponentially from the poll interval up to 5 minutes
  and resets after a successful poll;
- check-in and observation loops wait `max(Retry-After, interval)` (check-in
  is clamped to twice its interval so the systemd watchdog does not fire) and
  log one `hub busy, retrying in Ns` line.

## Daily report notification

`CLAWCTL_NOTIFY_CMD` is optional. Delivery goes through a small notifier
interface; the command notifier runs `sh -c "$CLAWCTL_NOTIFY_CMD"` with the
report on stdin.

- **Configured**: the Hub logs once at startup that a notify command is
  configured (without running it or printing it). Each attempt logs one line
  (`kind`, `bytes`, `attempt`, `outcome`, `next`) and never the report body.
  A failed delivery does not consume the day. The next attempt is
  `last failed attempt + min(1m × 2^(failures since due − 1), 60m)`. The count
  and the last failure time are read from the `notifications` table, so a
  restart keeps the same schedule. A delivered row after today's due time
  finishes the day. The report watchdog `/fail` ping is sent on the first
  failure and when the backoff reaches the 60 minute cap.
- **Not configured**: one undelivered row per kind per day with error
  `notify not configured`, one warning, the body logged once, one `/fail`
  ping, and no retries that day.
- **Retention**: notification rows are pruned after the observation horizon
  (30 days by default). The newest delivered row of each kind is kept.

## Metrics

`GET /metrics` is an operator `view` route. Prometheus must scrape it from a
tailnet node that holds the `<prefix>-view` grant for the Hub; a managed
machine or any other peer without that grant receives **403**. `GET /healthz`
stays a public, content-free liveness probe.

| Metric | Meaning |
|---|---|
| `clawctl_notify_configured` | 1 when a notify command is set, otherwise 0 |
| `clawctl_notify_last_success_timestamp_seconds{kind}` | Latest delivered notification. Omitted until one exists |
| `clawctl_notify_last_attempt_timestamp_seconds{kind}` | Latest attempt. Omitted until one exists |
| `clawctl_notify_consecutive_failures{kind}` | Undelivered rows since the latest delivered row |
| `clawctl_db_busy_total` | SQLite busy/locked errors and writer-queue timeouts seen by the Hub |
| `clawctl_db_write_wait_seconds{name}` | Histogram: time waiting for the single writer connection |
| `clawctl_db_write_hold_seconds{name}` | Histogram: time a write transaction held the writer |

A writer wait or hold longer than 1 second also logs
`WARN db writer slow name=... wait=... hold=...`.

## Alert rules

`ops/prometheus/rules/clawctl.yml`, group `clawctl-notify`:

```yaml
- alert: NotifyFailing
  expr: clawctl_notify_consecutive_failures{kind="daily"} >= 3
  for: 30m
- alert: NotifyNotConfigured
  expr: clawctl_notify_configured == 0
  for: 30m
```

Useful ad-hoc queries for contention:

```promql
rate(clawctl_db_busy_total[5m])
histogram_quantile(0.99, sum by (le, name) (rate(clawctl_db_write_wait_seconds_bucket[5m])))
histogram_quantile(0.99, sum by (le, name) (rate(clawctl_db_write_hold_seconds_bucket[5m])))
```

## Immediate machine offline notifications

The Hub checks offline alerts every minute on a loop separate from the daily
report. It uses the existing configured notifier (`--notify-cmd`, including
`ops/notify-telegram.sh`, or built-in Telegram/webhook configuration); it creates
no channel and makes no additional paid-service dependency.

**Tenant administration → 離線通知** (`/tenant/offline-alerts`) reads the threshold
and provides admin preview/apply, typed `OFFLINE ALERTS` confirmation, reason,
revision comparison, preview digest, idempotency and audit. The default is **10
minutes**, configurable from 1 to 1440 minutes. The timer starts at the machine
page's Hub-derived Unreachable deadline (assigned check-in interval + existing
90-second grace), not the agent's sent timestamp. Lowering the threshold applies
to existing outages on the next sweep. Monitor-only machines participate;
NeverReported and retired machines do not send alerts.

One delivered offline notification is latched per episode. Returning heartbeats
start a **two-minute stable reporting hold**, followed by one recovery message
only if the offline message was delivered. A relapse during the hold remains
in the same episode. A heartbeat also resets an unnotified outage, even between
sweeps. Recovery means reporting resumed; the machine may still be Degraded.
IdentityConflict without reporting is not a recovery.

Per-machine state is bounded to one row and survives restart and notification
retention. Delivery attempts use fenced two-minute reservations outside SQLite
transactions, recheck retirement/lifecycle/latest heartbeat, lease expiry and the current
threshold before sending, and
retry failures after 1, 2, 4, 8, 16, 32 and then 60 minutes. Unknown outcomes after
a process crash or network timeout can be retried: Telegram and shell commands
do not provide transactional exactly-once delivery. A crash between provider
acceptance and the durable success latch can therefore duplicate that message.
No reminders are sent for a delivered long outage. Retiring cancels the episode;
restoring a machine cannot replay the previous lifecycle's recovery.

The daily report schedule, `daily` notification kind, retry policy, watchdog
pings and delivery stamp remain independent. Offline attempts use
`machine-offline:<episode>` / `machine-offline:<episode>:recovery` in the existing
notification ledger. Without a configured notifier there are no sends or claims.
No credentials or destination secrets are added to settings or alert state.

CLI (normal HTTP discovery; no writable-DB mode):

```sh
clawctl-hub offline-alerts
clawctl-hub offline-alerts --set-minutes 5 --preview
clawctl-hub offline-alerts --set-minutes 5 --reason 'Notify sooner' --confirm 'OFFLINE ALERTS'
```

On an ambiguous apply response, repeat the same arguments with the original
`--idempotency-key`, `--expected-revision`, and `--preview-digest` printed on stderr.
Tests inject a clock and notifier; they never call Telegram.
