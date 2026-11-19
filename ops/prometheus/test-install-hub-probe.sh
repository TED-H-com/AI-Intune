#!/usr/bin/env bash
# Run the Hub probe installer against a fake configuration tree.
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SCRIPT=$HERE/install-hub-probe.sh
ORIG_PATH=$PATH
REAL_PROMTOOL=$(command -v promtool || :)
SCRATCH=$(mktemp -d "${TMPDIR:-/tmp}/hub-probe-test.XXXXXX")
passed=0
failed=0
number=0
CASE=
rc=0

run_case() {
	local name=$1 status
	shift
	number=$((number + 1))
	CASE=$SCRATCH/$number
	set +e
	( set -euo pipefail; "$@" ) >"$SCRATCH/case-$number.log" 2>&1
	status=$?
	set -e
	if [ "$status" -eq 0 ]; then
		printf 'ok - %s\n' "$name"
		passed=$((passed + 1))
	else
		printf 'not ok - %s\n' "$name"
		cat "$SCRATCH/case-$number.log"
		if [ -f "$CASE/state/stderr" ]; then cat "$CASE/state/stderr"; fi
		failed=$((failed + 1))
	fi
}

setup() {
	mkdir -p "$CASE/bin" "$CASE/state" "$CASE/etc/default" "$CASE/etc/prometheus"
	ETC=$CASE/etc
	PROM=$ETC/prometheus/prometheus.yml
	SCRAPE=$ETC/prometheus/scrape.d/clawctl-hub-healthz.yml
	RULE=$ETC/prometheus/rules/clawctl-hub-healthz.yml
	DEFAULTS=$ETC/default/prometheus-blackbox-exporter
	MODULES=$ETC/prometheus/clawctl-blackbox.yml
	TEST_URL=https://hub.example.com
	SKIP_ROOT=1
	printf 'global:\n  scrape_interval: 15s\nrule_files:\n  - %s/prometheus/rules/*.yml\nscrape_configs: []\n' "$ETC" >"$PROM"
	printf 'ARGS=""\n' >"$DEFAULTS"
	cp -a "$PROM" "$CASE/state/original-prometheus"
	cp -a "$DEFAULTS" "$CASE/state/original-defaults"
	printf 200 >"$CASE/state/hub-code"
	printf 'alive\n' >"$CASE/state/hub-body"
	printf 200 >"$CASE/state/healthy"
	printf 'probe_success 1\n' >"$CASE/state/probe"
	printf '%s\n' 'LISTEN 0 128 127.0.0.1:9115 0.0.0.0:*' >"$CASE/state/ss"
	printf '%s\n' '{"data":{"result":[{"metric":{"instance":"https://hub.example.com/healthz"},"value":[0,"1"]}]}}' >"$CASE/state/query"
	printf '%s\n' '{"data":{"groups":[{"rules":[{"name":"HubNotAnswering"},{"name":"HubProbeNotRunning"}]}]}}' >"$CASE/state/rules"
	: >"$CASE/state/calls"
	cat >"$CASE/bin/stub" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
STATE=$(cd "$(dirname "${BASH_SOURCE[0]}")/../state" && pwd)
CMD=${0##*/}
printf '%s %s\n' "$CMD" "$*" >>"$STATE/calls"
case $CMD in
apt-get)
	# A first install starts the service from postinst unless it is masked.
	if [ ! -e "$STATE/installed" ] && [ ! -e "$STATE/masked" ]; then touch "$STATE/wildcard-start"; fi
	[ ! -e "$STATE/fail-apt" ]
	touch "$STATE/installed"
	;;
systemctl)
	case $1 in
	is-enabled) if [ -e "$STATE/masked" ]; then echo masked; else echo disabled; fi ;;
	mask) touch "$STATE/masked" ;;
	unmask)
		if [ -e "$STATE/installed" ] && [ ! -e "$STATE/../etc/prometheus/.clawctl-hub-probe-remove-pending" ] &&
			! grep -q -- '--web.listen-address=127.0.0.1:9115' "$STATE/../etc/default/prometheus-blackbox-exporter"; then
			touch "$STATE/premature-unmask"
		fi
		rm -f "$STATE/masked"
		;;
	show) if [ -e "$STATE/unit-absent" ]; then echo not-found; else echo loaded; fi ;;
	esac
	if [ "$1" = reload ] && [ -e "$STATE/fail-reload" ]; then exit 1; fi
	if [ "$1" = disable ] && [ -e "$STATE/fail-disable" ]; then exit 1; fi
	if [ "$1" = reload ] && [ -e "$STATE/fail-second-reload" ] &&
		[ "$(grep -c '^systemctl reload prometheus$' "$STATE/calls")" -eq 2 ]; then exit 1; fi
	;;
promtool)
	if [ -e "$STATE/fail-restore" ]; then
		rm -- "$3".bak-*
		echo 'configuration rejected'
		exit 1
	fi
	if [ -e "$STATE/fail-remove" ]; then
		file=${3%/*}/scrape.d/clawctl-hub-healthz.yml
		rm -- "$file"
		mkdir "$file"
		echo 'configuration rejected'
		exit 1
	fi
	if [ -e "$STATE/fail-promtool" ]; then echo 'configuration rejected'; exit 1; fi
	echo SUCCESS
	;;
dpkg-query)
	if [ -e "$STATE/installed" ]; then printf 'install ok installed'; else exit 1; fi
	;;
ss) cat "$STATE/ss" ;;
sleep) ;;
curl)
	URL=${!#}
	BODY=
	while [ "$#" -gt 0 ]; do
		if [ "$1" = -o ]; then BODY=$2; shift; fi
		shift
	done
	case $URL in
	*/-/healthy) cat "$STATE/healthy" ;;
	*/probe) cat "$STATE/probe" ;;
	*/api/v1/query) cat "$STATE/query" ;;
	*/api/v1/rules) cat "$STATE/rules" ;;
	*/healthz)
		if [ -e "$STATE/fail-curl" ]; then printf 503; exit 7; fi
		cp "$STATE/hub-body" "$BODY"
		cat "$STATE/hub-code"
		;;
	*) exit 2 ;;
	esac
	;;
*) exit 2 ;;
esac
STUB
	chmod 0755 "$CASE/bin/stub"
	for cmd in apt-get systemctl promtool curl ss dpkg-query sleep; do
		ln -s stub "$CASE/bin/$cmd"
	done
}

installer() {
	set +e
	env "PATH=$CASE/bin:$ORIG_PATH" "CLAWCTL_HUB_PROBE_ETC=$ETC" \
		"CLAWCTL_HUB_PROBE_SKIP_ROOT=$SKIP_ROOT" "CLAWCTL_HUB_URL=$TEST_URL" \
		CLAWCTL_HUB_PROBE_WAIT=0 CLAWCTL_HUB_PROBE_TRIES=2 \
		bash "$SCRIPT" "$@" >"$CASE/state/stdout" 2>"$CASE/state/stderr"
	rc=$?
	set -e
}
need_rc() { [ "$rc" -eq "$1" ]; }
need_out() { grep -Fq -- "$1" "$CASE/state/stdout"; }
need_err() { grep -Fq -- "$1" "$CASE/state/stderr"; }
need_call() { grep -Fxq -- "$1" "$CASE/state/calls"; }
no_call() { if grep -Fq -- "$1" "$CASE/state/calls"; then return 1; fi; }
no_backups() { [ -z "$(find "$ETC" -name '*.bak-*' -print -quit)" ]; }
no_prom_changes() {
	cmp -s "$PROM" "$CASE/state/original-prometheus"
	[ ! -e "$SCRAPE" ]
	[ ! -e "$RULE" ]
	no_call 'reload'
}
no_changes() {
	no_prom_changes
	cmp -s "$DEFAULTS" "$CASE/state/original-defaults"
	[ ! -e "$MODULES" ]
	no_backups
	no_call 'apt-get'
	no_call 'systemctl'
}
signature() {
	find "$ETC" -printf '%y %p %m %u %g %T@\n' | LC_ALL=C sort
	find "$ETC" -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum
}
expected_scrape() {
	cat <<SCRAPE_CONFIG
# Written by ops/prometheus/install-hub-probe.sh.
scrape_configs:
  - job_name: clawctl-hub-healthz
    metrics_path: /probe
    params:
      module: [clawctl_hub_healthz]
    static_configs:
      - targets: ["$TEST_URL/healthz"]
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: 127.0.0.1:9115
SCRAPE_CONFIG
}
check_plan() {
	setup
	signature >"$CASE/state/before"
	installer --check
	need_rc 0
	cat >"$CASE/state/expected" <<PLAN
Hub: https://hub.example.com/healthz answers 200.
Package: prometheus-blackbox-exporter, to install
Exporter: 127.0.0.1:9115, modules $MODULES
Scrape job: $SCRAPE
Alert rules: $RULE
prometheus.yml: adds scrape_config_files
Prometheus: reload
Install: sudo CLAWCTL_HUB_URL=https://hub.example.com $SCRIPT
PLAN
	cmp -s "$CASE/state/expected" "$CASE/state/stdout"
	[ ! -s "$CASE/state/stderr" ]
	no_changes
	signature >"$CASE/state/after"
	cmp -s "$CASE/state/before" "$CASE/state/after"
	[ "$(wc -l <"$CASE/state/calls")" -eq 2 ]
}
check_installed() {
	setup
	touch "$CASE/state/installed"
	installer --check
	need_rc 0
	need_out 'Package: prometheus-blackbox-exporter, installed'
	no_changes
}
add_directory() { printf 'scrape_config_files:\n  - %s/prometheus/scrape.d/*.yml\n' "$ETC" >>"$PROM"; }
check_directory() {
	setup
	add_directory
	cp -a "$PROM" "$CASE/state/original-prometheus"
	installer --check
	need_rc 0
	need_out 'prometheus.yml: no change'
	no_changes
}
hub_failure() {
	setup
	case $1 in
	500) printf 500 >"$CASE/state/hub-code" ;;
	body) printf 'alive\n\n' >"$CASE/state/hub-body" ;;
	curl) touch "$CASE/state/fail-curl" ;;
	esac
	installer
	need_rc 1
	need_err "$2"
	no_changes
	[ "$(wc -l <"$CASE/state/calls")" -eq 1 ]
}
bad_urls() {
	setup
	for TEST_URL in https://hub.example.com/path hub.example.com https://user@hub.example.com 'https://hub.example.com space' ''; do
		installer --check
		need_rc 2
		need_err "CLAWCTL_HUB_URL must be the Hub's address: scheme, host and optional port, without a path. Example: https://hub.example.com"
		no_changes
	done
	[ ! -s "$CASE/state/calls" ]
}
trailing_slash() {
	setup
	TEST_URL=https://hub.example.com/
	printf alive >"$CASE/state/hub-body"
	installer --check
	need_rc 0
	need_out 'Hub: https://hub.example.com/healthz answers 200.'
	no_changes
}
missing_prometheus() {
	setup
	rm "$PROM"
	installer
	need_rc 1
	need_err "$PROM not found. Install Prometheus first: sudo CLAWCTL_FLEET_JSON=/path/to/fleet.json $HERE/install-prometheus.sh"
	[ ! -e "$PROM" ]
	[ ! -e "$MODULES" ]
	[ ! -s "$CASE/state/calls" ]
}
wrong_directory() {
	setup
	printf 'scrape_config_files:\n  - elsewhere/*.yml\n' >>"$PROM"
	cp -a "$PROM" "$CASE/state/original-prometheus"
	installer
	need_rc 1
	need_err "$PROM sets scrape_config_files without $ETC/prometheus/scrape.d/*.yml. Add that path to the list, then run this again."
	no_changes
	[ ! -s "$CASE/state/calls" ]
}
install_files() {
	setup
	chmod 0640 "$PROM"
	installer
	need_rc 0
	need_out 'Prometheus probes https://hub.example.com/healthz through 127.0.0.1:9115.'
	need_out 'Alerts: HubNotAnswering after 5 minutes without an answer, HubProbeNotRunning after 10 minutes without a probe result.'
	need_out "Remove: sudo $SCRIPT --remove"
	expected_scrape >"$CASE/state/expected"
	cmp -s "$CASE/state/expected" "$SCRAPE"
	printf 'ARGS="--config.file=%s --web.listen-address=127.0.0.1:9115"\n' "$MODULES" >"$CASE/state/expected"
	cmp -s "$CASE/state/expected" "$DEFAULTS"
	cmp -s "$HERE/hub-probe/rules.yml" "$RULE"
	cmp -s "$HERE/hub-probe/blackbox.yml" "$MODULES"
	cat "$CASE/state/original-prometheus" >"$CASE/state/expected"
	printf '\n# Scrape jobs added by other installers, one file each.\nscrape_config_files:\n  - %s/prometheus/scrape.d/*.yml\n' "$ETC" >>"$CASE/state/expected"
	cmp -s "$CASE/state/expected" "$PROM"
	for file in "$SCRAPE" "$RULE" "$MODULES"; do [ "$(stat -c %a "$file")" = 644 ]; done
	[ "$(stat -c %a "$PROM")" = 640 ]
	[ "$(stat -c %a "${SCRAPE%/*}")" = 755 ]
	[ "$(stat -c %a "${RULE%/*}")" = 755 ]
}
install_order() {
	setup
	installer
	need_rc 0
	need_out '== 4/4 reload Prometheus and check'
	grep -E '^(apt-get|systemctl|promtool) ' "$CASE/state/calls" >"$CASE/state/order"
	printf '%s\n' 'systemctl is-enabled prometheus-blackbox-exporter' 'systemctl mask prometheus-blackbox-exporter' \
		'apt-get install -y prometheus-blackbox-exporter' 'systemctl unmask prometheus-blackbox-exporter' \
		'systemctl enable prometheus-blackbox-exporter' 'systemctl restart prometheus-blackbox-exporter' \
		"promtool check config $PROM" 'systemctl reload prometheus' >"$CASE/state/expected"
	cmp -s "$CASE/state/expected" "$CASE/state/order"
	[ -f "$SCRAPE" ]
}
second_install() {
	setup
	installer
	need_rc 0
	find "$ETC" -name '*.bak-*' -delete
	signature >"$CASE/state/before"
	installer
	need_rc 0
	need_out 'Prometheus probes https://hub.example.com/healthz'
	signature >"$CASE/state/after"
	cmp -s "$CASE/state/before" "$CASE/state/after"
	no_backups
	[ "$(grep -c '^systemctl reload prometheus$' "$CASE/state/calls")" -eq 2 ]
}
new_url() {
	setup
	installer
	need_rc 0
	cp "$SCRAPE" "$CASE/state/old-scrape"
	TEST_URL=https://hub.example.com:8443
	printf '%s\n' '{"data":{"result":[{"metric":{"instance":"https://hub.example.com:8443/healthz"},"value":[0,"1"]}]}}' >"$CASE/state/query"
	installer
	need_rc 0
	need_out 'Prometheus probes https://hub.example.com:8443/healthz'
	expected_scrape >"$CASE/state/expected"
	cmp -s "$CASE/state/expected" "$SCRAPE"
	cmp -s "$CASE/state/old-scrape" "$SCRAPE".bak-*
	need_call 'systemctl reload prometheus'
}
install_directory() {
	setup
	add_directory
	cp -a "$PROM" "$CASE/state/original-prometheus"
	installer
	need_rc 0
	need_out 'Prometheus probes https://hub.example.com/healthz'
	cmp -s "$PROM" "$CASE/state/original-prometheus"
	[ -z "$(find "${PROM%/*}" -maxdepth 1 -name 'prometheus.yml.bak-*' -print -quit)" ]
	need_call "promtool check config $PROM"
}
apt_failure() {
	setup
	touch "$CASE/state/fail-apt"
	installer
	need_rc 1
	need_err 'Package installation failed. Retry this install, or remove the probe:'
	no_prom_changes
	[ ! -e "$MODULES" ]
	cmp -s "$DEFAULTS" "$CASE/state/original-defaults"
	need_call 'systemctl mask prometheus-blackbox-exporter'
	no_call 'systemctl unmask'
	no_call 'systemctl enable'
	no_call 'systemctl restart'
	[ -e "$ETC/prometheus/.clawctl-hub-probe-mask-pending" ]
	no_call promtool
}
exporter_failure() {
	setup
	printf 503 >"$CASE/state/healthy"
	installer
	need_rc 1
	need_err 'The exporter does not answer on 127.0.0.1:9115. See: systemctl status prometheus-blackbox-exporter'
	no_prom_changes
	[ "$(grep -c '/-/healthy$' "$CASE/state/calls")" -eq 10 ]
	no_call promtool
}
wrong_listener() {
	setup
	printf '%s\n' 'LISTEN 0 128 127.0.0.1:9115 0.0.0.0:*' 'LISTEN 0 128 0.0.0.0:9115 0.0.0.0:*' >"$CASE/state/ss"
	installer
	need_rc 1
	need_err 'The exporter listens on 127.0.0.1:9115 0.0.0.0:9115. Expected 127.0.0.1:9115 only. Stopped it.'
	need_call 'systemctl stop prometheus-blackbox-exporter'
	no_prom_changes
	no_call promtool
}
probe_failure() {
	setup
	printf 'probe_success 0\n' >"$CASE/state/probe"
	installer
	need_rc 1
	need_err 'The exporter got no answer from https://hub.example.com/healthz. Prometheus was not changed.'
	no_prom_changes
	no_call promtool
}
promtool_failure() {
	setup
	touch "$CASE/state/fail-promtool"
	installer
	need_rc 1
	need_err 'configuration rejected'
	need_err 'promtool rejected the configuration. Restored the previous files. Prometheus was not reloaded.'
	no_prom_changes
	need_call "promtool check config $PROM"
}
reload_failure() {
	setup
	touch "$CASE/state/fail-reload"
	installer
	need_rc 1
	need_err 'systemctl reload prometheus failed. Restored the previous files.'
	cmp -s "$PROM" "$CASE/state/original-prometheus"
	[ ! -e "$SCRAPE" ]
	[ ! -e "$RULE" ]
	[ "$(grep -c '^systemctl reload prometheus$' "$CASE/state/calls")" -eq 1 ]
}
query_failure() {
	setup
	printf '%s\n' '{"data":{"result":[{"metric":{"instance":"https://hub.example.com/other"},"value":[0,"1"]},{"metric":{"instance":"https://hub.example.com/healthz"},"value":[0,"0"]}]}}' >"$CASE/state/query"
	installer
	need_rc 1
	need_err 'Prometheus got no answer from https://hub.example.com/healthz in 0 seconds. Restored the previous files and reloaded Prometheus.'
	cmp -s "$PROM" "$CASE/state/original-prometheus"
	[ ! -e "$SCRAPE" ]
	[ ! -e "$RULE" ]
	[ "$(grep -c '^systemctl reload prometheus$' "$CASE/state/calls")" -eq 2 ]
}
alerts_failure() {
	setup
	printf '%s\n' '{"data":{"result":[]}}' >"$CASE/state/query"
	printf '%s\n' '{"data":{"groups":[{"rules":[{"name":"HubNotAnswering"}]}]}}' >"$CASE/state/rules"
	installer
	need_rc 1
	need_err 'Prometheus did not load the alerts HubNotAnswering and HubProbeNotRunning. Restored the previous files and reloaded Prometheus.'
	cmp -s "$PROM" "$CASE/state/original-prometheus"
	[ ! -e "$SCRAPE" ]
	[ ! -e "$RULE" ]
	[ "$(grep -c '^systemctl reload prometheus$' "$CASE/state/calls")" -eq 2 ]
}
existing_failure() {
	setup
	installer
	need_rc 0
	cp "$SCRAPE" "$CASE/state/old-scrape"
	cp "$RULE" "$CASE/state/old-rule"
	printf '# site rule\n' >>"$RULE"
	cp "$RULE" "$CASE/state/old-rule"
	TEST_URL=https://hub.example.com:8443
	touch "$CASE/state/fail-promtool"
	: >"$CASE/state/calls"
	installer
	need_rc 1
	need_err 'promtool rejected the configuration. Restored the previous files. Prometheus was not reloaded.'
	cmp -s "$SCRAPE" "$CASE/state/old-scrape"
	cmp -s "$RULE" "$CASE/state/old-rule"
	no_call reload
}
restore_failure() {
	local base=$CASE kind
	for kind in copy remove reload; do
		CASE=$base/$kind
		setup
		case $kind in
		copy) touch "$CASE/state/fail-restore" ;;
		remove) touch "$CASE/state/fail-remove" ;;
		reload)
			touch "$CASE/state/fail-second-reload"
			printf '%s\n' '{"data":{"result":[]}}' >"$CASE/state/query"
			;;
		esac
		installer
		need_rc 1
		need_err 'Not restored:'
		case $kind in
		copy)
			grep -Eq "^  $PROM: copy $PROM.bak-[0-9-]+ over it$" "$CASE/state/stderr"
			[ ! -e "$SCRAPE" ]
			no_call reload
			;;
		remove)
			need_err "  $SCRAPE: remove it"
			cmp -s "$PROM" "$CASE/state/original-prometheus"
			no_call reload
			;;
		reload)
			need_err '  Prometheus: run systemctl reload prometheus'
			cmp -s "$PROM" "$CASE/state/original-prometheus"
			[ ! -e "$SCRAPE" ]
			[ "$(grep -c '^systemctl reload prometheus$' "$CASE/state/calls")" -eq 2 ]
			;;
		esac
		[ ! -e "$RULE" ]
	done
}

remove_probe() {
	setup
	installer
	need_rc 0
	signature >"$CASE/state/before"
	cp "$PROM" "$CASE/state/installed-prometheus"
	cp "$DEFAULTS" "$CASE/state/installed-defaults"
	: >"$CASE/state/calls"
	TEST_URL=
	installer --remove
	need_rc 0
	need_out 'Removed the Hub probe. Prometheus is reloaded; prometheus-blackbox-exporter is stopped and disabled.'
	[ ! -e "$SCRAPE" ]
	[ ! -e "$RULE" ]
	cmp -s "$PROM" "$CASE/state/installed-prometheus"
	cmp -s "$DEFAULTS" "$CASE/state/installed-defaults"
	cmp -s "$MODULES" "$HERE/hub-probe/blackbox.yml"
	printf '%s\n' 'systemctl reload prometheus' 'systemctl show prometheus-blackbox-exporter -p LoadState --value' 'systemctl disable --now prometheus-blackbox-exporter' >"$CASE/state/expected"
	cmp -s "$CASE/state/expected" "$CASE/state/calls"
}
remove_absent() {
	setup
	installer --remove
	need_rc 0
	need_out 'The Hub probe is not installed.'
	no_changes
	[ ! -s "$CASE/state/calls" ]
}
package_startup() {
	setup
	installer
	need_rc 0
	[ ! -e "$CASE/state/wildcard-start" ]
	[ ! -e "$CASE/state/premature-unmask" ]
	[ ! -e "$CASE/state/masked" ]
	[ ! -e "$ETC/prometheus/.clawctl-hub-probe-mask-pending" ]
	[ -e "$ETC/prometheus/.clawctl-hub-probe-managed" ]
}
foreign_mask() {
	local base=$CASE state
	for state in absent installed; do
		CASE=$base/$state
		setup
		if [ "$state" = installed ]; then touch "$CASE/state/installed"; fi
		touch "$CASE/state/masked"
		installer
		need_rc 1
		need_err 'prometheus-blackbox-exporter is masked.'
		[ -e "$CASE/state/masked" ]
		no_call 'apt-get'
		no_call 'systemctl unmask'
		no_prom_changes
	done
}
installed_package() {
	setup
	touch "$CASE/state/installed"
	installer
	need_rc 0
	no_call 'systemctl mask'
	no_call 'systemctl unmask'
	need_call 'systemctl restart prometheus-blackbox-exporter'
}

package_retry() {
	setup
	touch "$CASE/state/fail-apt"
	installer
	need_rc 1
	[ -e "$CASE/state/masked" ]
	rm "$CASE/state/fail-apt"
	installer
	need_rc 0
	[ ! -e "$CASE/state/masked" ]
	[ ! -e "$CASE/state/wildcard-start" ]
}
remove_package_failure() {
	setup
	touch "$CASE/state/fail-apt" "$CASE/state/unit-absent"
	installer
	need_rc 1
	installer --remove
	need_rc 0
	need_call 'systemctl unmask prometheus-blackbox-exporter'
	[ ! -e "$CASE/state/masked" ]
	[ ! -e "$ETC/prometheus/.clawctl-hub-probe-managed" ]
	no_call 'systemctl disable'
}
remove_failed_install() {
	local base=$CASE stage
	for stage in exporter probe config; do
		CASE=$base/$stage
		setup
		case $stage in
		exporter) printf 503 >"$CASE/state/healthy" ;;
		probe) printf 'probe_success 0\n' >"$CASE/state/probe" ;;
		config) touch "$CASE/state/fail-promtool" ;;
		esac
		installer
		need_rc 1
		[ ! -e "$SCRAPE" ]
		[ ! -e "$RULE" ]
		: >"$CASE/state/calls"
		installer --remove
		need_rc 0
		need_call 'systemctl disable --now prometheus-blackbox-exporter'
		need_out 'Removed the Hub probe.'
		: >"$CASE/state/calls"
		installer --remove
		need_rc 0
		need_out 'The Hub probe is not installed.'
		[ ! -s "$CASE/state/calls" ]
	done
}
remove_retry() {
	local kind base=$CASE
	for kind in reload disable; do
		CASE=$base/$kind
		setup
		installer
		need_rc 0
		touch "$CASE/state/fail-$kind"
		installer --remove
		need_rc 1
		[ -f "$ETC/prometheus/.clawctl-hub-probe-remove-pending" ]
		rm "$CASE/state/fail-$kind"
		: >"$CASE/state/calls"
		installer --remove
		need_rc 0
		need_call 'systemctl reload prometheus'
		need_call 'systemctl disable --now prometheus-blackbox-exporter'
		[ ! -e "$ETC/prometheus/.clawctl-hub-probe-remove-pending" ]
	done
}
missing_listener() {
	setup
	: >"$CASE/state/ss"
	installer
	need_rc 1
	need_err 'The exporter listens on none.'
	need_call 'systemctl stop prometheus-blackbox-exporter'
	no_prom_changes
}
write_failure() {
	setup
	# Fail the rule write after the scrape job was already installed.
	local real_install
	real_install=$(command -v install)
	printf '#!/usr/bin/env bash\ncase "${!#}" in */rules/clawctl-hub-healthz.yml) exit 1;; esac\nexec %q "$@"\n' "$real_install" >"$CASE/bin/install"
	chmod 0755 "$CASE/bin/install"
	installer
	need_rc 1
	need_err 'Could not write the probe configuration.'
	no_prom_changes
}
remove_reload_failure() {
	setup
	mkdir -p "${SCRAPE%/*}" "${RULE%/*}"
	touch "$SCRAPE" "$RULE" "$CASE/state/fail-reload"
	installer --remove
	need_rc 1
	need_err 'Prometheus reload failed. Retry removal:'
	[ ! -e "$SCRAPE" ]
	[ ! -e "$RULE" ]
	need_call 'systemctl reload prometheus'
	no_call disable
}
bad_arguments() {
	setup
	printf '%s\n' 'Usage:' \
		'CLAWCTL_HUB_URL=https://hub.example.com ./ops/prometheus/install-hub-probe.sh --check' \
		'sudo CLAWCTL_HUB_URL=https://hub.example.com ./ops/prometheus/install-hub-probe.sh' \
		'sudo ./ops/prometheus/install-hub-probe.sh --remove' >"$CASE/state/expected"
	for arg in --other install ''; do
		installer "$arg"
		need_rc 2
		cmp -s "$CASE/state/expected" "$CASE/state/stderr"
		no_changes
	done
	installer --check --remove
	need_rc 2
	cmp -s "$CASE/state/expected" "$CASE/state/stderr"
	[ ! -s "$CASE/state/calls" ]
}
needs_root() {
	setup
	SKIP_ROOT=0
	installer
	need_rc 1
	need_err "Run as root: sudo CLAWCTL_HUB_URL=https://hub.example.com $SCRIPT"
	no_changes
	installer --remove
	need_rc 1
	need_err "Run as root: sudo $SCRIPT --remove"
	no_changes
}
real_promtool() {
	setup
	rm "$CASE/bin/promtool"
	ln -s "$REAL_PROMTOOL" "$CASE/bin/promtool"
	installer
	need_rc 0
	need_out 'Prometheus probes https://hub.example.com/healthz'
	[ -f "$SCRAPE" ]
	[ -f "$RULE" ]
	need_call 'systemctl reload prometheus'
}

run_case 'check prints the plan and changes nothing' check_plan
run_case 'check reports a package that is already installed' check_installed
run_case 'check reports a prometheus.yml that already has the scrape directory' check_directory
run_case 'a Hub that answers 500 stops before any change' hub_failure 500 'answered HTTP 500. Expected 200 with the body "alive". Nothing was changed.'
run_case 'a Hub that answers 200 with another body stops before any change' hub_failure body 'answered 200 with another body. Expected "alive". Nothing was changed.'
run_case 'a Hub that does not answer stops before any change' hub_failure curl 'answered HTTP 000. Expected 200 with the body "alive". Nothing was changed.'
run_case 'a URL with a path is refused (also: no scheme, user@host, a space, empty)' bad_urls
run_case 'a trailing slash in the URL is accepted' trailing_slash
run_case 'a missing prometheus.yml stops before any change' missing_prometheus
run_case 'scrape_config_files without the scrape directory stops before any change' wrong_directory
run_case 'install writes the exporter settings, the scrape job, the rules and the scrape directory line' install_files
run_case 'install runs apt-get, the exporter restart, promtool and the reload in that order' install_order
run_case 'a second install changes no file and makes no backup' second_install
run_case 'an install with another URL replaces the target and keeps a backup of the old scrape job' new_url
run_case 'a prometheus.yml that already has the scrape directory is not edited' install_directory
run_case 'apt-get failing stops before any other change' apt_failure
run_case 'an exporter that does not answer stops before Prometheus is changed' exporter_failure
run_case 'an exporter on another address is stopped' wrong_listener
run_case 'an exporter that gets no answer from the Hub stops before Prometheus is changed' probe_failure
run_case 'a configuration promtool rejects is restored and not reloaded' promtool_failure
run_case 'a failing reload restores the files' reload_failure
run_case 'a probe that never reports 1 restores the files and reloads again' query_failure
run_case 'missing alerts restore the files and reload again' alerts_failure
run_case 'a failed install over an existing probe restores the previous scrape job' existing_failure
run_case 'a restore step that fails is listed under Not restored' restore_failure
run_case 'remove deletes the scrape job and the rules, reloads and disables the exporter' remove_probe
run_case 'remove without a probe changes nothing' remove_absent
run_case 'remove reports a reload that fails' remove_reload_failure
run_case 'package startup waits for the loopback flags' package_startup
run_case 'an installed package keeps its current mask state' installed_package
run_case 'an operator mask is preserved' foreign_mask
run_case 'package installation can resume after failure' package_retry
run_case 'remove cleans up after a package installation failure' remove_package_failure
run_case 'remove cleans up an exporter after failed installation' remove_failed_install
run_case 'removal can resume after reload or disable fails' remove_retry
run_case 'a missing listener stops the exporter' missing_listener
run_case 'a failed write restores previously written files' write_failure
run_case 'any other argument prints the usage' bad_arguments
if [ "$(id -u)" -eq 0 ]; then
	printf 'skip: install needs root (running as root)\n'
else
	run_case 'install needs root' needs_root
fi
if [ -n "$REAL_PROMTOOL" ]; then
	run_case 'the generated configuration passes the real promtool' real_promtool
else
	printf 'skip: promtool not on PATH\n'
fi
if [ "$failed" -eq 0 ]; then
	rm -rf -- "$SCRATCH"
else
	printf 'Scratch: %s\n' "$SCRATCH"
fi
printf 'passed: %s, failed: %s\n' "$passed" "$failed"
[ "$failed" -eq 0 ]
