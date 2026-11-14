# shellcheck shell=bash
# Library sourced by the monitoring install scripts.
# Resolves the tailnet listen address and edits unit defaults.

monitor_address() {
	local addr="" from_var=0
	local o1 o2 o3 o4 valid=0 ip_show
	local ipv4_re='^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$'

	if [ -n "${CLAWCTL_MONITOR_ADDR:-}" ]; then
		addr=$CLAWCTL_MONITOR_ADDR
		from_var=1
	elif command -v tailscale >/dev/null 2>&1; then
		addr=$(tailscale ip -4 2>/dev/null || true)
		addr=${addr%%$'\n'*}
	fi

	if [ -z "$addr" ]; then
		printf '%s\n' "No tailnet IPv4 address. Start Tailscale, or set CLAWCTL_MONITOR_ADDR to this host's tailnet address." >&2
		return 1
	fi

	if [[ $addr =~ $ipv4_re ]]; then
		o1=$((10#${BASH_REMATCH[1]}))
		o2=$((10#${BASH_REMATCH[2]}))
		o3=$((10#${BASH_REMATCH[3]}))
		o4=$((10#${BASH_REMATCH[4]}))
		if [ "$o1" -le 255 ] && [ "$o2" -le 255 ] && [ "$o3" -le 255 ] && [ "$o4" -le 255 ]; then
			valid=1
		fi
	fi
	if [ "$valid" -ne 1 ]; then
		if [ "$from_var" -eq 1 ]; then
			printf 'CLAWCTL_MONITOR_ADDR must be an IPv4 address: %s\n' "$addr" >&2
		else
			printf '%s\n' "tailscale ip -4 printed no IPv4 address" >&2
		fi
		return 1
	fi

	ip_show=$(ip -o -4 addr show || true)
	if ! grep -F -q -e " ${addr}/" <<<"$ip_show"; then
		printf 'No interface of this host has %s. Set CLAWCTL_MONITOR_ADDR to an address of this host.\n' "$addr" >&2
		return 1
	fi

	printf '%s\n' "$addr"
	return 0
}

set_args_flag() {
	local file=$1 flag=$2 value=$3
	local line args_count=0 bad=0 have_args=0 args_index=-1 args_value=""
	local -a kept=() words=() new_words=() out_lines=()
	local w i n joined new_line new_content old_content stamp
	local args_re='^ARGS="([^"]*)"$'

	case $value in
	*[[:space:]]*|*"\""*)
		printf 'invalid value for %s: %s\n' "$flag" "$value" >&2
		return 1
		;;
	esac

	if [ -f "$file" ]; then
		while IFS= read -r line || [ -n "$line" ]; do
			if [[ $line =~ $args_re ]]; then
				args_count=$((args_count + 1))
				if [ "$args_count" -eq 1 ]; then
					args_index=${#kept[@]}
					args_value=${BASH_REMATCH[1]}
					have_args=1
				fi
				kept+=("$line")
			elif [[ $line == ARGS=* ]]; then
				bad=1
				kept+=("$line")
			else
				kept+=("$line")
			fi
		done <"$file"
	fi

	if [ "$bad" -eq 1 ] || [ "$args_count" -gt 1 ]; then
		printf '%s: cannot edit ARGS. Set %s=%s in it by hand, then rerun.\n' "$file" "$flag" "$value" >&2
		return 1
	fi

	if [ -n "$args_value" ]; then
		IFS=' ' read -r -a words <<<"$args_value"
	fi
	i=0
	n=${#words[@]}
	while [ "$i" -lt "$n" ]; do
		w=${words[$i]}
		if [ "$w" = "$flag" ]; then
			i=$((i + 2))
			continue
		fi
		if [[ $w == "$flag="* ]]; then
			i=$((i + 1))
			continue
		fi
		new_words+=("$w")
		i=$((i + 1))
	done
	new_words+=("${flag}=${value}")
	joined=$(
		IFS=' '
		printf '%s' "${new_words[*]}"
	)
	new_line="ARGS=\"${joined}\""

	if [ "$have_args" -eq 1 ]; then
		i=0
		n=${#kept[@]}
		while [ "$i" -lt "$n" ]; do
			if [ "$i" -eq "$args_index" ]; then
				out_lines+=("$new_line")
			else
				out_lines+=("${kept[$i]}")
			fi
			i=$((i + 1))
		done
	else
		if [ "${#kept[@]}" -gt 0 ]; then
			out_lines=("${kept[@]}")
		fi
		out_lines+=("$new_line")
	fi

	new_content=$(printf '%s\n' "${out_lines[@]}"; printf x)
	new_content=${new_content%x}
	if [ -f "$file" ]; then
		old_content=$(cat -- "$file"; printf x)
		old_content=${old_content%x}
	else
		old_content=
	fi
	if [ "$new_content" = "$old_content" ]; then
		printf '   %s=%s already set in %s\n' "$flag" "$value" "$file"
		return 0
	fi
	if [ -e "$file" ]; then
		# shellcheck disable=SC2154 # STAMP belongs to the sourcing install script
		stamp=${STAMP:-$(date +%Y%m%d-%H%M%S)}
		cp -a -- "$file" "$file.bak-$stamp"
	fi
	printf '%s' "$new_content" >"$file"
	printf '   set %s=%s in %s\n' "$flag" "$value" "$file"
	return 0
}

set_env_line() {
	local file=$1 name=$2 value=$3
	local line found=0 new_content old_content stamp
	local -a out_lines=()

	case $value in
	*[[:space:]]*|*"\""*)
		printf 'invalid value for %s: %s\n' "$name" "$value" >&2
		return 1
		;;
	esac

	if [ -f "$file" ]; then
		while IFS= read -r line || [ -n "$line" ]; do
			if [[ $line == "$name="* ]]; then
				if [ "$found" -eq 0 ]; then
					out_lines+=("${name}=${value}")
					found=1
				fi
			else
				out_lines+=("$line")
			fi
		done <"$file"
	fi
	if [ "$found" -eq 0 ]; then
		out_lines+=("${name}=${value}")
	fi

	new_content=$(printf '%s\n' "${out_lines[@]}"; printf x)
	new_content=${new_content%x}
	if [ -f "$file" ]; then
		old_content=$(cat -- "$file"; printf x)
		old_content=${old_content%x}
	else
		old_content=
	fi
	if [ "$new_content" = "$old_content" ]; then
		printf '   %s=%s already set in %s\n' "$name" "$value" "$file"
		return 0
	fi
	if [ -e "$file" ]; then
		# shellcheck disable=SC2154 # STAMP belongs to the sourcing install script
		stamp=${STAMP:-$(date +%Y%m%d-%H%M%S)}
		cp -a -- "$file" "$file.bak-$stamp"
	fi
	printf '%s' "$new_content" >"$file"
	printf '   set %s=%s in %s\n' "$name" "$value" "$file"
	return 0
}

retry_until_bound() {
	local unit=$1
	local dir=${2:-/etc/systemd/system}
	local dropdir path content current
	dropdir="$dir/${unit}.service.d"
	path="$dropdir/clawctl-listen.conf"
	content="# Written by ops/prometheus/listen.sh. ${unit} listens on the tailnet address,
# which exists only after Tailscale is up: retry every 5 seconds until it does.
[Unit]
After=tailscaled.service
StartLimitIntervalSec=0

[Service]
Restart=on-failure
RestartSec=5s
"

	if [ -f "$path" ]; then
		current=$(cat -- "$path"; printf x)
		current=${current%x}
		if [ "$current" = "$content" ]; then
			printf '   %s retry drop-in already present (%s)\n' "$unit" "$path"
			return 0
		fi
	fi

	install -d -m 0755 "$dropdir"
	printf '%s' "$content" >"$path"
	chmod 0644 "$path"
	printf '   %s restarts every 5 seconds until it can listen (%s)\n' "$unit" "$path"
	return 0
}
