#!/usr/bin/env bash
# Run Go tests with a unique disk-backed TMPDIR under $HOME/agent-work/tmp.
set -euo pipefail

go_bin="${1:-}"
if [[ -z "$go_bin" ]]; then
	echo "test-go: Go executable argument is required" >&2
	exit 2
fi
shift
if [[ $# -eq 0 ]]; then
	set -- ./...
fi

scratch_root="${CLAWCTL_TEST_SCRATCH_ROOT:-${HOME:?}/agent-work/tmp}"
if [[ -z "$scratch_root" || "$scratch_root" != /* ]]; then
	echo "test-go: scratch root must be an absolute path: $scratch_root" >&2
	exit 1
fi

reject_ram_path() {
	local candidate=$1
	case "$candidate" in
	/dev/shm | /dev/shm/* | /run/shm | /run/shm/*)
		echo "test-go: memory-backed path is not permitted: $candidate" >&2
		exit 1
		;;
	esac
}

fs_type() {
	local target=$1 fstype=''
	if fstype="$(stat -f -c '%T' -- "$target" 2>/dev/null)" && [[ -n "$fstype" ]]; then
		printf '%s\n' "$fstype" | tr '[:upper:]' '[:lower:]'
		return 0
	fi
	if [[ "$(uname -s)" == Darwin ]]; then
		# BSD stat has no filesystem-type format. Use the most specific mount.
		mount | awk -v target="$target" '
			{
				line = $0
				sub(/^.* on /, "", line)
				sep = index(line, " (")
				if (!sep) next
				point = substr(line, 1, sep - 1)
				type = substr(line, sep + 2)
				sub(/[,)].*$/, "", type)
				if ((point == "/" || target == point || index(target, point "/") == 1) && length(point) > longest) {
					longest = length(point)
					found = type
				}
			}
			END { if (found == "") exit 1; print tolower(found) }
		'
		return
	fi
	return 1
}

assert_disk_backing() {
	local target=$1 fstype=''
	reject_ram_path "$target"
	if ! fstype="$(fs_type "$target")"; then
		echo "test-go: unable to determine filesystem type for $target" >&2
		exit 1
	fi
	case "$fstype" in
	tmpfs | ramfs)
		echo "test-go: refusing $fstype scratch filesystem for $target" >&2
		exit 1
		;;
	esac
}

reject_ram_path "$scratch_root"

probe="$scratch_root"
while [[ ! -d "$probe" ]]; do
	parent="$(dirname -- "$probe")"
	if [[ "$parent" == "$probe" ]]; then
		break
	fi
	probe="$parent"
done

resolved_probe="$(cd -- "$probe" 2>/dev/null && pwd -P)"
if [[ -z "$resolved_probe" || ! -e "$resolved_probe" ]]; then
	echo "test-go: unable to resolve existing ancestor for $scratch_root" >&2
	exit 1
fi

assert_disk_backing "$resolved_probe"

mkdir -p -- "$scratch_root"
canonical_root="$(cd -- "$scratch_root" && pwd -P)"
if [[ -z "$canonical_root" || ! -d "$canonical_root" ]]; then
	echo "test-go: unable to resolve scratch directory $scratch_root" >&2
	exit 1
fi

assert_disk_backing "$canonical_root"

scratch_dir=''
test_pid=''
# ShellCheck 0.9 does not follow these trap callbacks.
# shellcheck disable=SC2317
cleanup() {
	if [[ -n "$scratch_dir" && -d "$scratch_dir" ]]; then
		rm -rf -- "$scratch_dir"
		scratch_dir=''
	fi
}
trap cleanup EXIT
# shellcheck disable=SC2317
stop_tests() {
	local signal=$1 status=$2
	trap '' HUP INT TERM
	if [[ -n "$test_pid" ]]; then
		kill -s "$signal" -- "-$test_pid" 2>/dev/null || true
		wait "$test_pid" 2>/dev/null || true
	fi
	exit "$status"
}
trap 'stop_tests HUP 129' HUP
trap 'stop_tests INT 130' INT
trap 'stop_tests TERM 143' TERM

# Keep the prefix short enough for test-created Unix socket paths.
scratch_dir="$(mktemp -d "$canonical_root/g.XXXXXX")"
chmod 0700 -- "$scratch_dir"
export TMPDIR="$scratch_dir"
export GOTMPDIR="$scratch_dir"

# A separate process group lets signals stop tests before removing their files.
set -m
"$go_bin" test -timeout 30m "$@" &
test_pid=$!
status=0
wait "$test_pid" || status=$?
test_pid=''
exit "$status"
