#!/bin/sh
set -eu
LC_ALL=C
export LC_ALL
failed=null
case $(uname -s) in
  Linux)
    os=linux
    uptime=$(awk '{printf "%.0f", $1}' /proc/uptime)
    load=$(awk '{printf "[%s,%s,%s]", $1,$2,$3}' /proc/loadavg)
    disk=$(df -P / | awk 'NR==2 {gsub(/%/,"",$5); print $5}')
    if command -v systemctl >/dev/null 2>&1; then
      if units=$(systemctl --failed --no-legend --plain --no-pager 2>/dev/null); then
        failed=$(printf '%s\n' "$units" | awk 'NF {n++} END {print n+0}')
      fi
    fi
    ;;
  Darwin)
    os=darwin
    boot=$(sysctl -n kern.boottime | awk '{for (i=1;i<=NF;i++) if ($i=="sec") {gsub(/,/,"",$(i+2)); print $(i+2); exit}}')
    uptime=$(($(date +%s) - boot))
    load=$(sysctl -n vm.loadavg | awk '{printf "[%s,%s,%s]", $2,$3,$4}')
    volume=/
    if [ -d /System/Volumes/Data ]; then volume=/System/Volumes/Data; fi
    disk=$(df -P "$volume" | awk 'NR==2 {gsub(/%/,"",$5); print $5}')
    if services=$(launchctl list 2>/dev/null); then
      failed=$(printf '%s\n' "$services" | awk '$2 ~ /^-?[0-9]+$/ && $2 != 0 {n++} END {print n+0}')
    fi
    ;;
  *) exit 1 ;;
esac
printf '{"os":"%s","uptime_seconds":%s,"load":%s,"root_disk_use_percent":%s,"failed_service_count":%s}\n' "$os" "$uptime" "$load" "$disk" "$failed"
