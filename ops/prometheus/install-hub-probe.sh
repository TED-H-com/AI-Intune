#!/usr/bin/env bash
# Tests set:
# CLAWCTL_HUB_PROBE_ETC: configuration root; CLAWCTL_HUB_PROBE_SKIP_ROOT=1: skip root.
# CLAWCTL_HUB_PROBE_PROMETHEUS: API URL; CLAWCTL_HUB_PROBE_EXPORTER: listener.
# CLAWCTL_HUB_PROBE_TRIES: API polls; CLAWCTL_HUB_PROBE_WAIT: poll delay in seconds.
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SCRIPT_PATH=$HERE/$(basename "${BASH_SOURCE[0]}")
# shellcheck source=listen.sh
. "$HERE/listen.sh"
ETC=${CLAWCTL_HUB_PROBE_ETC:-/etc}
DEFAULTS=$ETC/default/prometheus-blackbox-exporter
PROM_YML=$ETC/prometheus/prometheus.yml
MODULES=$ETC/prometheus/clawctl-blackbox.yml
SCRAPE_DIR=$ETC/prometheus/scrape.d
SCRAPE=$SCRAPE_DIR/clawctl-hub-healthz.yml
RULE=$ETC/prometheus/rules/clawctl-hub-healthz.yml
REMOVE_PENDING=$ETC/prometheus/.clawctl-hub-probe-remove-pending
PROM_API=${CLAWCTL_HUB_PROBE_PROMETHEUS:-http://127.0.0.1:9090}
EXPORTER=${CLAWCTL_HUB_PROBE_EXPORTER:-127.0.0.1:9115}
TRIES=${CLAWCTL_HUB_PROBE_TRIES:-36}
WAIT=${CLAWCTL_HUB_PROBE_WAIT:-5}
STAMP=$(date +%Y%m%d-%H%M%S)

usage() {
	cat >&2 <<'USAGE'
Usage:
CLAWCTL_HUB_URL=https://hub.example.com ./ops/prometheus/install-hub-probe.sh --check
sudo CLAWCTL_HUB_URL=https://hub.example.com ./ops/prometheus/install-hub-probe.sh
sudo ./ops/prometheus/install-hub-probe.sh --remove
USAGE
	exit 2
}
if [ "$#" -gt 1 ]; then usage; fi
MODE=${1:-install}
case $MODE in
--check|--remove) ;;
install) if [ "$#" -ne 0 ]; then usage; fi ;;
*) usage ;;
esac

root_required() {
	if [ "${CLAWCTL_HUB_PROBE_SKIP_ROOT:-}" != 1 ] && [ "$(id -u)" -ne 0 ]; then
		if [ "$MODE" = --remove ]; then
			printf 'Run as root: sudo %s --remove\n' "$SCRIPT_PATH" >&2
		else
			printf 'Run as root: sudo CLAWCTL_HUB_URL=%s %s\n' "$URL" "$SCRIPT_PATH" >&2
		fi
		exit 1
	fi
}

if [ "$MODE" = --remove ]; then
	root_required
	if [ ! -e "$SCRAPE" ] && [ ! -e "$RULE" ] && [ ! -e "$REMOVE_PENDING" ]; then
		echo 'The Hub probe is not installed.'
		exit 0
	fi
	: >"$REMOVE_PENDING"
	rm -f -- "$SCRAPE" "$RULE"
	if ! systemctl reload prometheus; then
		printf 'Prometheus reload failed. Retry removal: sudo %s --remove\n' "$SCRIPT_PATH" >&2
		exit 1
	fi
	if ! systemctl disable --now prometheus-blackbox-exporter; then
		echo 'prometheus-blackbox-exporter was not stopped. Run: systemctl disable --now prometheus-blackbox-exporter' >&2
		exit 1
	fi
	rm -f -- "$REMOVE_PENDING"
	echo 'Removed the Hub probe. Prometheus is reloaded; prometheus-blackbox-exporter is stopped and disabled.'
	exit 0
fi

URL=${CLAWCTL_HUB_URL:-}
URL=${URL%/}
url_re='^https?://[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:[0-9]{1,5})?$'
if [[ ! $URL =~ $url_re ]]; then
	echo "CLAWCTL_HUB_URL must be the Hub's address: scheme, host and optional port, without a path. Example: https://hub.example.com" >&2
	exit 2
fi
TARGET=$URL/healthz
if [ ! -f "$PROM_YML" ]; then
	printf '%s not found. Install Prometheus first: sudo CLAWCTL_FLEET_JSON=/path/to/fleet.json %s/install-prometheus.sh\n' "$PROM_YML" "$HERE" >&2
	exit 1
fi
if ! command -v promtool >/dev/null 2>&1; then
	echo 'promtool is not on PATH. The prometheus package provides it.' >&2
	exit 1
fi
ADD_SCRAPE=1
if grep -q '^scrape_config_files:' "$PROM_YML"; then
	ADD_SCRAPE=0
	if ! grep -Fq -- "$SCRAPE_DIR/*.yml" "$PROM_YML"; then
		printf '%s sets scrape_config_files without %s/*.yml. Add that path to the list, then run this again.\n' "$PROM_YML" "$SCRAPE_DIR" >&2
		exit 1
	fi
fi
WORK=$(mktemp -d)
trap 'rm -rf -- "$WORK"' EXIT
if CODE=$(curl -s -m 10 -o "$WORK/body" -w '%{http_code}' "$TARGET"); then :; else CODE=000; fi
if [ "$CODE" != 200 ]; then
	printf '%s answered HTTP %s. Expected 200 with the body "alive". Nothing was changed.\n' "$TARGET" "$CODE" >&2
	exit 1
fi
printf alive >"$WORK/alive"
printf 'alive\n' >"$WORK/alive-newline"
if ! cmp -s "$WORK/body" "$WORK/alive" && ! cmp -s "$WORK/body" "$WORK/alive-newline"; then
	printf '%s answered 200 with another body. Expected "alive". Nothing was changed.\n' "$TARGET" >&2
	exit 1
fi
if [ "$MODE" = --check ]; then
	PACKAGE='to install'
	if STATUS=$(dpkg-query -W -f='${Status}' prometheus-blackbox-exporter) && [ "$STATUS" = 'install ok installed' ]; then PACKAGE=installed; fi
	CHANGE='no change'
	if [ "$ADD_SCRAPE" -eq 1 ]; then CHANGE='adds scrape_config_files'; fi
	printf 'Hub: %s answers 200.\nPackage: prometheus-blackbox-exporter, %s\nExporter: %s, modules %s\nScrape job: %s\nAlert rules: %s\nprometheus.yml: %s\nPrometheus: reload\nInstall: sudo CLAWCTL_HUB_URL=%s %s\n' \
		"$TARGET" "$PACKAGE" "$EXPORTER" "$MODULES" "$SCRAPE" "$RULE" "$CHANGE" "$URL" "$SCRIPT_PATH"
	exit 0
fi
root_required

echo '== 1/4 package'
if ! DEBIAN_FRONTEND=noninteractive apt-get install -y prometheus-blackbox-exporter; then
	echo 'apt-get could not install prometheus-blackbox-exporter. Nothing else was changed.' >&2
	exit 1
fi
printf '== 2/4 exporter on %s\n' "$EXPORTER"
if ! cmp -s "$HERE/hub-probe/blackbox.yml" "$MODULES"; then
	install -m 0644 "$HERE/hub-probe/blackbox.yml" "$MODULES"
fi
flag_is_set() {
	python3 -c 'import pathlib,sys
p=pathlib.Path(sys.argv[1])
if not p.is_file(): sys.exit(1)
lines=[s for s in p.read_text().splitlines() if s.startswith("ARGS=")]
if len(lines)!=1 or not lines[0].startswith("ARGS=\"") or not lines[0].endswith("\""): sys.exit(1)
w=lines[0][6:-1].split()
f=sys.argv[2]
v=[s for s in w if s==f or s.startswith(f+"=")]
sys.exit(v != [f+"="+sys.argv[3]])' "$DEFAULTS" "$1" "$2"
}
if ! flag_is_set --config.file "$MODULES"; then
	set_args_flag "$DEFAULTS" --config.file "$MODULES"
fi
if ! flag_is_set --web.listen-address "$EXPORTER"; then
	set_args_flag "$DEFAULTS" --web.listen-address "$EXPORTER"
fi
systemctl enable prometheus-blackbox-exporter
systemctl restart prometheus-blackbox-exporter
HEALTHY=0
for ((i=0; i<10; i++)); do
	if CODE=$(curl -s -m 5 -o /dev/null -w '%{http_code}' "http://$EXPORTER/-/healthy") && [ "$CODE" = 200 ]; then
		HEALTHY=1
		break
	fi
	if [ "$i" -lt 9 ]; then sleep "${CLAWCTL_HUB_PROBE_WAIT-1}"; fi
done
if [ "$HEALTHY" -ne 1 ]; then
	printf 'The exporter does not answer on %s. See: systemctl status prometheus-blackbox-exporter\n' "$EXPORTER" >&2
	exit 1
fi
SOCKETS=$(ss -ltnH)
ADDRESSES=$(awk -v port="${EXPORTER##*:}" '$4 ~ (":" port "$") {print $4}' <<<"$SOCKETS" | paste -sd ' ')
BAD_ADDRESS=0
if [ -z "$ADDRESSES" ]; then BAD_ADDRESS=1; ADDRESSES=none; fi
while IFS= read -r address; do
	if [ -n "$address" ] && [ "$address" != "$EXPORTER" ]; then BAD_ADDRESS=1; fi
done < <(printf '%s\n' "$ADDRESSES" | tr ' ' '\n')
if [ "$BAD_ADDRESS" -eq 1 ]; then
	systemctl stop prometheus-blackbox-exporter
	printf 'The exporter listens on %s. Expected %s only. Stopped it.\n' "$ADDRESSES" "$EXPORTER" >&2
	exit 1
fi
if PROBE=$(curl -s -m 15 -G --data-urlencode 'module=clawctl_hub_healthz' --data-urlencode "target=$TARGET" "http://$EXPORTER/probe") && grep -qx 'probe_success 1' <<<"$PROBE"; then :; else
	printf 'The exporter got no answer from %s. Prometheus was not changed.\n' "$TARGET" >&2
	exit 1
fi

CHANGED=()
EXISTED=()
RESTORE_ERRORS=()
replace_file() {
	local source=$1 destination=$2 existed=0
	if cmp -s "$source" "$destination"; then return; fi
	if [ -e "$destination" ]; then
		cp -a -- "$destination" "$destination.bak-$STAMP"
		existed=1
	fi
	CHANGED+=("$destination")
	EXISTED+=("$existed")
	if [ "$destination" = "$PROM_YML" ]; then
		cat "$source" >"$destination"
	else
		install -m 0644 "$source" "$destination"
	fi
}
restore_files() {
	local n file
	for n in "${!CHANGED[@]}"; do
		file=${CHANGED[$n]}
		if [ "${EXISTED[$n]}" -eq 1 ]; then
			if ! cp -a -- "$file.bak-$STAMP" "$file"; then
				RESTORE_ERRORS+=("$file: copy $file.bak-$STAMP over it")
			fi
		else
			if ! rm -f -- "$file"; then RESTORE_ERRORS+=("$file: remove it"); fi
		fi
	done
}
rollback() {
	local reload=$1 message=$2
	restore_files
	if [ "$reload" -eq 1 ]; then
		if ! systemctl reload prometheus; then RESTORE_ERRORS+=('Prometheus: run systemctl reload prometheus'); fi
	fi
	printf '%s\n' "$message" >&2
	if [ "${#RESTORE_ERRORS[@]}" -gt 0 ]; then
		printf 'Not restored:\n' >&2
		printf '  %s\n' "${RESTORE_ERRORS[@]}" >&2
	fi
	exit 1
}

# A failed backup or write must restore every earlier file in this install.
set -E
trap 'trap - ERR; rollback 0 "Could not write the probe configuration. Restored the previous files. Prometheus was not reloaded."' ERR

echo '== 3/4 scrape job and alert rules'
install -d -m 0755 "$SCRAPE_DIR" "$ETC/prometheus/rules"
cat >"$WORK/scrape" <<SCRAPE_CONFIG
# Written by ops/prometheus/install-hub-probe.sh.
scrape_configs:
  - job_name: clawctl-hub-healthz
    metrics_path: /probe
    params:
      module: [clawctl_hub_healthz]
    static_configs:
      - targets: ["$TARGET"]
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: $EXPORTER
SCRAPE_CONFIG
replace_file "$WORK/scrape" "$SCRAPE"
replace_file "$HERE/hub-probe/rules.yml" "$RULE"
if [ "$ADD_SCRAPE" -eq 1 ]; then
	cat "$PROM_YML" >"$WORK/prometheus"
	printf '\n# Scrape jobs added by other installers, one file each.\nscrape_config_files:\n  - %s/*.yml\n' "$SCRAPE_DIR" >>"$WORK/prometheus"
	replace_file "$WORK/prometheus" "$PROM_YML"
fi
trap - ERR
if promtool check config "$PROM_YML" >"$WORK/promtool" 2>&1; then :; else
	cat "$WORK/promtool" >&2
	rollback 0 'promtool rejected the configuration. Restored the previous files. Prometheus was not reloaded.'
fi

echo '== 4/4 reload Prometheus and check'
if ! systemctl reload prometheus; then
	rollback 0 'systemctl reload prometheus failed. Restored the previous files.'
fi
PROBE_OK=0
ALERTS_OK=0
for ((i=0; i<TRIES; i++)); do
	PROBE_OK=0
	ALERTS_OK=0
	if curl -s -m 5 -G --data-urlencode 'query=probe_success{job="clawctl-hub-healthz"}' "$PROM_API/api/v1/query" |
		python3 -c 'import json,sys
try:
 d=json.load(sys.stdin)
 ok=any(r.get("metric",{}).get("instance")==sys.argv[1] and str(r["value"][1])=="1" for r in d["data"]["result"])
except (ValueError,KeyError,TypeError,IndexError): ok=False
sys.exit(not ok)' "$TARGET"; then PROBE_OK=1; fi
	if curl -s -m 5 "$PROM_API/api/v1/rules" |
		python3 -c 'import json,sys
try:
 d=json.load(sys.stdin)
 names={r.get("name") for g in d["data"]["groups"] for r in g["rules"]}
 ok=set(sys.argv[1:]).issubset(names)
except (ValueError,KeyError,TypeError): ok=False
sys.exit(not ok)' HubNotAnswering HubProbeNotRunning; then ALERTS_OK=1; fi
	if [ "$PROBE_OK" -eq 1 ] && [ "$ALERTS_OK" -eq 1 ]; then break; fi
	if [ "$i" -lt "$((TRIES - 1))" ]; then sleep "$WAIT"; fi
done
if [ "$ALERTS_OK" -ne 1 ]; then
	rollback 1 'Prometheus did not load the alerts HubNotAnswering and HubProbeNotRunning. Restored the previous files and reloaded Prometheus.'
fi
if [ "$PROBE_OK" -ne 1 ]; then
	rollback 1 "Prometheus got no answer from $TARGET in $((TRIES * WAIT)) seconds. Restored the previous files and reloaded Prometheus."
fi
printf 'Prometheus probes %s through %s.\n' "$TARGET" "$EXPORTER"
echo 'Alerts: HubNotAnswering after 5 minutes without an answer, HubProbeNotRunning after 10 minutes without a probe result.'
printf 'Remove: sudo %s --remove\n' "$SCRIPT_PATH"
