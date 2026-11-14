# Hub settings

`clawctl-hub serve` reads its settings from flags and environment variables. A
flag on the command line wins over its variable, and a variable wins over the
default. The systemd unit `ops/clawctl-hub.service` reads the variables from
`~/.config/clawctl/hub.env`. Durations use Go syntax, such as `30m` or `720h`.

## Flags of `clawctl-hub serve`

### Network and sign-in

| Flag | Variable | Default | Effect |
|---|---|---|---|
| `--listen` | `CLAWCTL_LISTEN` | `127.0.0.1:8770` | The `IP:port` the Hub listens on. `tailscale` mode needs the host's Tailscale IP. In `local` and `both` modes, a listener that is not loopback needs an HTTPS `CLAWCTL_PUBLIC_URL`. `report` and `--operator-auth-check` read the same variable. |
| `--auth-mode` | `CLAWCTL_AUTH_MODE` | `tailscale` | `tailscale` (Tailscale identity and grants), `local` (local admin accounts) or `both`. See [OPERATOR-AUTH.md](OPERATOR-AUTH.md) and [AUTOPILOT.md](AUTOPILOT.md). |
| `--operator-capability-prefix` | `CLAWCTL_OPERATOR_CAPABILITY_PREFIX` | none | The `<domain>/cap/<app>` prefix of the operator grants. Required in `tailscale` mode, and in `both` mode on a Tailscale listener. `local` mode without it uses `local/cap/clawctl`. |
| `--hub-host` | — | the host name | The Hub machine's host name. When a managed machine has this host name or display name, the dashboard shows that the Hub runs on it. |

### Database and retention

| Flag | Variable | Default | Effect |
|---|---|---|---|
| `--db` | `CLAWCTL_DB` | `~/.local/share/clawctl/clawctl.sqlite` | The SQLite database. The path must resolve to a clean absolute path. |
| `--keep-observations` | `CLAWCTL_KEEP_OBSERVATIONS` | `720h` | How long observations, silent canary failures and notifications are kept; longer than `168h`. A variable that is not a duration stops the Hub, even when the flag is set. |
| `--keep-checkins` | — | `336h` | How long check-ins are kept; longer than `168h`. |
| `--keep-occupancy` | — | `9600h` | How long ticket occupancy observations are kept; longer than `168h`. |
| `--obs-unchanged-interval` | `CLAWCTL_OBS_UNCHANGED_INTERVAL` | `30m` | An unchanged CLI tool or systemd snapshot that arrives within this interval is not stored again. `0` stores every snapshot. |

### Notifications and reports

| Flag | Variable | Default | Effect |
|---|---|---|---|
| `--notify-env` | `CLAWCTL_NOTIFY_ENV` | none | File with the Telegram or webhook settings of the built-in notifier ([DEPLOY-OSS.md](DEPLOY-OSS.md)). `notify-check` reads the same variable. |
| `--notify-cmd` | `CLAWCTL_NOTIFY_CMD` | none | Shell command that delivers each notification, with the message on standard input. When set, it replaces the built-in notifier. |
| `--report-at` | — | `08:00` | Local time of the daily report, `HH:MM`. A value that does not parse sends no daily report. |
| `--report-stamp` | `CLAWCTL_REPORT_STAMP` | none | File the Hub writes the Unix time to after each delivered daily report. |

### Disk operations

| Flag | Variable | Default | Effect |
|---|---|---|---|
| `--disk-growth-gb-per-hour` | `CLAWCTL_DISK_GROWTH_GB_PER_HOUR` | `10` | Threshold of the disk growth alert, 1–1000000 GB per hour. A machine policy or the `disk-default` policy overrides it. |
| `--disk-growth-window-minutes` | `CLAWCTL_DISK_GROWTH_WINDOW_MINUTES` | `30` | Window of that threshold, 10–1440 minutes. |
| `--disk-ops-v2-writes` | — | off | Allows disk policy apply and approval writes; preview works without it ([MAINTENANCE-DISK-CLEAN.md](MAINTENANCE-DISK-CLEAN.md)). |
| `--disk-manifest-signing-key` | — | none | A 0600 RSA private key (PEM, 2048–4096 bits, exponent 65537) that signs disk action manifests. Without it, an approval that would dispatch a disk action fails. |

### Terminal, usage and diagnostics

| Flag | Variable | Default | Effect |
|---|---|---|---|
| `--terminal-idle-timeout` | `CLAWCTL_TERMINAL_IDLE_TIMEOUT` | `30m` | An idle operator terminal closes after this long: 1m–24h in whole seconds, not longer than the maximum lifetime. |
| `--terminal-max-lifetime` | `CLAWCTL_TERMINAL_MAX_LIFETIME` | `12h` | An operator terminal closes after this long: 1m–720h in whole seconds. |
| `--usage-tool-call-limit` | `CLAWCTL_USAGE_TOOL_CALL_LIMIT` | `1000` | Maximum tool-call entries in one usage upload; a larger upload is rejected. |
| `--pprof` | `CLAWCTL_HUB_PPROF` | off; on when the variable is `1` | Serves Go profiles at `/debug/pprof/` to admins. |

## Variables without a flag

| Variable | Read by | Default | Effect |
|---|---|---|---|
| `CLAWCTL_PUBLIC_URL` | `serve`, `report`, `--operator-auth-check` | none | The console's HTTPS origin in `local` and `both` modes; HTTP only on a loopback listener. In `tailscale` mode, a set value must be `http://` and the listen address. |
| `CLAWCTL_REQUIRE_MFA` | `serve` in `local` and `both` modes | on | `0`, `false` or `off` lets local admins sign in with a password only. |
| `CLAWCTL_ADMIN_MFA_WINDOW` | `serve` in `local` and `both` modes | `12h` | How long an MFA confirmation covers routine admin actions. Dangerous actions need one from the last 5 minutes. |
| `CLAWCTL_SETUP_CODE` | `serve` in `local` and `both` modes, before the first account | a random code, written to the log | First-run setup code: at least 16 characters, not counting spaces and hyphens. |
| `CLAWCTL_TRUSTED_PROXIES` | `serve` | none | Proxy addresses or prefixes (IPv4 /8 or narrower, IPv6 /16 or narrower) whose client address header the Hub uses. |
| `CLAWCTL_CLIENT_IP_HEADER` | `serve` | `X-Forwarded-For` | That header: `X-Forwarded-For`, `Fly-Client-IP` or `CF-Connecting-IP`. |
| `CLAWCTL_HUB_ARGON_CONCURRENCY` | `serve` | `2` | Maximum password hashes computed at once. |
| `CLAWCTL_SLOW_REQUEST_MS` | `serve` | `1000` | Requests slower than this many milliseconds are logged as `slow request`. |
| `CLAWCTL_EXPECTATIONS` | `serve`, `machines`, `deployment`, `report` | none | Expectations file in the format of `ops/expectations.example.json`: each rule names a machine or `*`, a unit, an artifact file, the age the file must stay under, and why. The Hub logs an invalid file and runs without rules. With `--db`, the commands refuse to judge when this file differs from the policy the Hub last published. |
| `CLAWCTL_SECRETS_CONFIG` | `serve` | none | Secret providers file ([SECRETS.md](SECRETS.md)). |
| `CLAWCTL_CHANNELS_INBOUND_CONFIG` | `serve` | none | Inbound chat channels file ([CHANNELS.md](CHANNELS.md)). Without it, inbound channel requests receive 404. |
| `CLAWCTL_REPORT_PING_URL` | `serve` | none | URL the Hub requests after each delivered daily report. When delivery fails, it requests the URL with `/fail` appended. |
| `CLAWCTL_REPORT_PING_FAIL_URL` | `serve` | the ping URL with `/fail` | URL requested when the daily report is not delivered. Set it when the ping URL has a query string. |
| `CLAWCTL_RESTORE_DRILL_STAMP` | `serve`, `report` | `restore-drill.stamp` next to the database | Stamp file of the last passed restore drill, which the dashboard shows ([RESTORE-DRILL.md](runbooks/RESTORE-DRILL.md)). |
| `CLAWCTL_HUB_URL` | `machine`, `job`, `artifact` | the Hub URL in `~/.config/clawctl/operator.json` | The Hub these commands call when neither `--hub-url` nor `--db` is given. |
| `ERROR_INGEST_ENABLED` | `serve` | off | `true` or `1` turns on the error API ([ERROR_API.md](ERROR_API.md)); otherwise its routes return 404. |
| `ERROR_READ_TOKEN_FILE` | `serve` | none | File with the bearer token that reads errors. |
| `XDG_STATE_HOME` | `deployment`, `catalog`, `artifact fetch` | `~/.local/state` | Directory of the recovery files these commands keep in `clawctl/deployment-recovery`; a clean absolute path. |
| `NOTIFY_SOCKET` | `serve` | set by systemd | Socket of the ready and watchdog notifications. |
| `WATCHDOG_USEC` | `serve` | set by systemd | Watchdog interval. The Hub notifies every third of it while the database answers. |

## Object storage

The Hub keeps blobs in local files unless one group of these variables is set.
Set the R2 group or the S3 group, not both; an incomplete group stops the Hub.

| Variable | Default | Effect |
|---|---|---|
| `R2_ACCESS_KEY_ID` | required | Cloudflare R2 access key ID. |
| `R2_SECRET_ACCESS_KEY` | required | R2 secret access key. |
| `R2_BUCKET` | required | R2 bucket. |
| `R2_ENDPOINT` | required | R2 endpoint: an `https` URL without a path. |
| `R2_ACCOUNT_ID` | none | 32 hexadecimal characters; the endpoint host must contain it. |
| `R2_REGION` | `auto` | R2 region. |
| `S3_ACCESS_KEY_ID` | required | S3 access key ID. |
| `S3_SECRET_ACCESS_KEY` | required | S3 secret access key. |
| `S3_BUCKET` | required | S3 bucket. |
| `S3_ENDPOINT` | required | S3 endpoint: an `https` URL without a path. |
| `S3_REGION` | `us-east-1` | S3 region. |
| `S3_ACCOUNT_ID` | none | Not accepted; a set value stops the Hub. |

## Error issue filer

The filer opens GitHub issues for fleet errors ([ERROR_ISSUES.md](ERROR_ISSUES.md)).

| Variable | Default | Effect |
|---|---|---|
| `ERROR_ISSUES_ENABLED` | `false` | `true` starts the filer. |
| `ERROR_ISSUES_DRY_RUN` | `false` | `true` logs what would be filed without calling GitHub. |
| `ERROR_ISSUES_INTERVAL` | `15m` | Time between runs. |
| `ERROR_ISSUES_TOKEN_FILE` | none | GitHub token file, owned by root or the service user, mode 0600 or 0400. Required unless `ERROR_ISSUES_DRY_RUN` is `true`. |
| `ERROR_ISSUES_INTUNE_REPO` | `TED-H-com/AI-Intune` | Repository for errors of `intune` components. |
| `ERROR_ISSUES_BAT_REPO` | `TED-H-com/bat-agent-connector` | Repository for errors of the BAT components. |
