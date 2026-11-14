# Monitoring: Prometheus, Alertmanager and Grafana

`ops/prometheus/` installs a monitoring stack on one Debian or Ubuntu host:
Prometheus scrapes node_exporter on every fleet machine and the Hub's
`/metrics`, Alertmanager sends the alerts to Telegram, and Grafana shows the
fleet dashboard. The Hub's own metrics and the notify alert rules are in
[HUB-RELIABILITY.md](HUB-RELIABILITY.md#metrics).

## Before you install

- A fleet list in the format of `ops/prometheus/fleet.example.json`: one entry
  per machine, with the node_exporter address (`IP:9100`) and a `machine`
  label. Machines on the list that do not answer show as `up == 0`.
- The host's tailnet address. `tailscale ip -4` prints it, or set
  `CLAWCTL_MONITOR_ADDR`. The fleet list names this host's node_exporter at
  that address (`<address>:9100`).
- Your own copy of `ops/prometheus/prometheus.yml`. Its `clawctl-hub` target is
  a sample: set it to the Hub's tailnet listen address (`CLAWCTL_LISTEN`, an
  `IP:port`). The Hub answers a request that names it any other way with 421.
  Do not add a `machine` label to the `clawctl-hub` job, and keep the
  `alerting` section.
- A tailnet grant of `<prefix>-view` for the Prometheus host
  ([OPERATOR-AUTH.md](OPERATOR-AUTH.md), "Tailnet policy configuration").
  Without it the Hub answers `/metrics` with 403. With `--auth-mode local`,
  `/metrics` needs a signed-in session, so Prometheus cannot scrape it.
- For alerts: `~/.config/clawctl/hub.env` of the user who runs `sudo` sets
  `CLAWCTL_NOTIFY_ENV`, and that file sets `TELEGRAM_CHAT_ID` and
  `TELEGRAM_BOT_TOKEN`.

## Install everything

```bash
sudo CLAWCTL_FLEET_JSON=/path/to/fleet.json \
  CLAWCTL_PROMETHEUS_YML=/path/to/prometheus.yml \
  ./ops/prometheus/install.sh
```

`install.sh` runs the three stages below in order and stops at the first one
that fails. Each stage script can also run alone, as root.

**Telegram messages start about 5 minutes after stage 2** (Alertmanager's
`group_wait`), without another prompt. To see what will be sent, open
`http://127.0.0.1:9090/alerts` on the Prometheus host after stage 1.

### 1. Prometheus and node_exporter

`ops/prometheus/install-prometheus.sh` installs the `prometheus` and
`prometheus-node-exporter` packages and copies:

| From | To |
|---|---|
| `CLAWCTL_PROMETHEUS_YML` (default `ops/prometheus/prometheus.yml`) | `/etc/prometheus/prometheus.yml` |
| `CLAWCTL_FLEET_JSON` (required) | `/etc/prometheus/targets/fleet.json` |
| `ops/prometheus/rules/*.yml` | `/etc/prometheus/rules/` |

It backs up a different `/etc/prometheus/prometheus.yml` as
`prometheus.yml.bak-<time>`, enables node_exporter's textfile collector on
`/var/lib/prometheus/node-exporter`, checks the configuration with `promtool`
before it restarts anything, and prints `up` for each fleet machine. Prometheus
listens on `127.0.0.1:9090` and node_exporter on `<address>:9100`. A rerun
installs your copy as is: without its `alerting` section, Prometheus stops
sending alerts to Alertmanager.

### 2. Alertmanager

`ops/prometheus/install-alertmanager.sh` reads `CLAWCTL_NOTIFY_ENV` from
`hub.env`, then the chat ID and the bot token from that file. It never sources
either file and never prints the token.

- The token goes to `/etc/prometheus/telegram.token` (mode 0600, owner
  `prometheus`).
- `/etc/prometheus/alertmanager.yml` is generated from
  `ops/prometheus/alertmanager.yml.tmpl` with the chat ID (mode 0640). The
  previous file is kept as `alertmanager.yml.bak-<time>`.
- `/etc/prometheus/prometheus.yml` gets an `alerting` section for
  `localhost:9093` when it has none.

Alertmanager listens on `127.0.0.1:9093` with its cluster listener off.

Alertmanager sends one message per machine, repeats an unchanged group every
24 hours (`severity="info"`: 72 hours), and holds back a machine's warning and
info alerts while that machine does not answer.

To silence a machine:

```bash
amtool --alertmanager.url=http://127.0.0.1:9093 silence add machine=<machine> -d 720h -c 'Handling manually'
amtool --alertmanager.url=http://127.0.0.1:9093 silence query
```

### 3. Grafana

`ops/prometheus/install-grafana.sh` adds Grafana's APT repository and signing
key, installs `grafana`, and provisions the data source `clawctl-prom`
(`http://localhost:9090`) and the dashboard `clawctl-fleet` from
`ops/prometheus/grafana/`. Grafana listens on `<address>:3000`. Changes made in
the browser cannot be saved (`allowUiUpdates: false`); change
`ops/prometheus/grafana/clawctl.json` and rerun the script. It turns off usage
reporting, update checks, sign-up and anonymous access in
`/etc/default/grafana-server`.

The first login is `admin` / `admin`, and Grafana asks for a new password.
Reruns log in with `GF_ADMIN` / `GF_PASS` (default `admin` / `admin`):

```bash
read -rsp 'Grafana admin password: ' GF_PASS && export GF_PASS
sudo --preserve-env=GF_ADMIN,GF_PASS ./ops/prometheus/install-grafana.sh
```

## Grafana without root

`ops/prometheus/install-grafana-docker.sh` runs Grafana in Docker
(`grafana/grafana-oss:13.0.2`, container `clawctl-grafana`) as a user in the
`docker` group, with the same data source and dashboard. Use it instead of
stage 3.

| Variable | Default |
|---|---|
| `CLAWCTL_GRAFANA_ADDR` | The host part of `CLAWCTL_LISTEN` in `~/.config/clawctl/hub.env`, else `127.0.0.1` |
| `CLAWCTL_GRAFANA_PORT` | `3000` |
| `CLAWCTL_GRAFANA_HOME` | `~/.local/share/clawctl/grafana` (copied configuration) |

Grafana data, including the admin password, stays in the Docker volume
`clawctl-grafana-data`. Reruns log in with `GF_ADMIN` / `GF_PASS`.

## Network exposure

| Service | Listens on |
|---|---|
| Prometheus | `127.0.0.1:9090` |
| Alertmanager | `127.0.0.1:9093`, cluster listener off |
| node_exporter | `<address>:9100` |
| Grafana (APT, `install-grafana.sh`) | `<address>:3000` |
| Grafana (Docker) | `$CLAWCTL_GRAFANA_ADDR:$CLAWCTL_GRAFANA_PORT` |

`<address>` is `CLAWCTL_MONITOR_ADDR`, else the first address of
`tailscale ip -4`. node_exporter and Grafana start once that address exists;
until then systemd restarts them every 5 seconds
(`/etc/systemd/system/<unit>.service.d/clawctl-listen.conf`).

From another machine, forward the port over SSH:
`ssh -L 9090:127.0.0.1:9090 <host>` for Prometheus,
`ssh -L 9093:127.0.0.1:9093 <host>` for Alertmanager.

## Check the dashboard

```bash
./ops/prometheus/check-dashboard.sh [http://localhost:9090]
```

It runs every panel query of `ops/prometheus/grafana/clawctl.json` against
Prometheus and changes nothing. It exits 1 when a query is broken or returns
no series. An empty panel is either an event that did not happen or a wrong
metric name, label or scrape job: query the metric without its label filter;
if the whole metric is empty, the query or the scrape is wrong.

## Tests

`bash ops/test-ops.sh` checks the rules with `promtool` (set
`CLAWCTL_REQUIRE_PROMTOOL=1` to fail when `promtool` is missing), that
`install.sh` calls existing stage scripts, the installers' refusals and
Grafana login checks, and the functions of `ops/prometheus/listen.sh`.
