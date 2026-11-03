#!/usr/bin/env bash
# Tests for ops/test-go.sh disk scratch placement, validation, and cleanup.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
RUNNER="$ROOT/ops/test-go.sh"
mkdir -p -- "$HOME/agent-work/tmp"
WORK=$(mktemp -d "$HOME/agent-work/tmp/clawctl-test-go-suite.XXXXXX")
trap 'rm -rf -- "$WORK"' EXIT

passed=0
failed=0

pass() {
	passed=$((passed + 1))
	printf 'ok - %s\n' "$1"
}

fail() {
	failed=$((failed + 1))
	printf 'not ok - %s\n' "$1" >&2
}

STUB_GO="$WORK/stub-go.sh"
cat >"$STUB_GO" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "${TMPDIR:-}" >"${STUB_GO_RECORD_TMPDIR:?}"
printf '%s\n' "$*" >"${STUB_GO_RECORD_ARGS:?}"
if [[ -z "${TMPDIR:-}" || ! -d "$TMPDIR" || "${GOTMPDIR:-}" != "$TMPDIR" ]]; then
	exit 91
fi
printf 'scratch-sentinel\n' >"$TMPDIR/sentinel.sqlite"
case "${STUB_GO_MODE:-ok}" in
	ok) exit 0 ;;
	socket)
		python3 - <<'PY'
import os, pathlib, socket
path = pathlib.Path(os.environ['TMPDIR']) / 'TestCaptureNotifyEnvironment1234567890' / '001' / 'notify.sock'
path.parent.mkdir(parents=True)
with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as listener:
    listener.bind(str(path))
PY
		exit 0
		;;
	fail) exit 23 ;;
	term)
		printf '%s\n' "$$" >"${STUB_GO_CHILD_PID:?}"
		kill -TERM "$PPID"
		sleep 5
		exit 0
		;;
	*) exit 92 ;;
esac
EOF
chmod +x "$STUB_GO"

# 1. Default scratch root under $HOME/agent-work/tmp, timeout flag, and cleanup on success.
default_root="$HOME/agent-work/tmp"
mkdir -p -- "$default_root"
canonical_default_root="$(cd "$default_root" && pwd -P)"
rec_tmp1="$WORK/tmp1"
rec_args1="$WORK/args1"
if STUB_GO_MODE=socket STUB_GO_RECORD_TMPDIR="$rec_tmp1" STUB_GO_RECORD_ARGS="$rec_args1" \
	TMPDIR=/dev/shm GOTMPDIR=/dev/shm \
	bash "$RUNNER" "$STUB_GO"; then
	got_tmp1="$(<"$rec_tmp1")"
	got_args1="$(<"$rec_args1")"
	if [[ "$got_tmp1" == "$canonical_default_root"/g.* &&
		"$got_args1" == "test -timeout 30m ./..." &&
		! -e "$got_tmp1" ]]; then
		pass 'test-go uses unique disk scratch under ~/agent-work/tmp and cleans up on success'
	else
		fail "test-go default scratch mismatch: tmp=$got_tmp1 args=$got_args1"
	fi
else
	fail 'test-go default scratch run failed'
fi

# 2. Explicit scratch-root override creates distinct directory and cleans up on failure.
override_root="$WORK/custom-scratch/go-tests"
rec_tmp2="$WORK/tmp2"
rec_args2="$WORK/args2"
rc=0
STUB_GO_MODE=fail STUB_GO_RECORD_TMPDIR="$rec_tmp2" STUB_GO_RECORD_ARGS="$rec_args2" \
	CLAWCTL_TEST_SCRATCH_ROOT="$override_root" \
	bash "$RUNNER" "$STUB_GO" ./internal/store || rc=$?
got_tmp2="$(<"$rec_tmp2")"
got_args2="$(<"$rec_args2")"
canonical_override_root="$(cd "$override_root" && pwd -P)"
if [[ "$rc" -eq 23 &&
	"$got_tmp2" == "$canonical_override_root"/g.* &&
	"$got_tmp2" != "${got_tmp1:-}" &&
	"$got_args2" == "test -timeout 30m ./internal/store" &&
	! -e "$got_tmp2" ]]; then
	pass 'test-go propagates failure exit code and removes scratch directory'
else
	fail "test-go failure cleanup mismatch: rc=$rc tmp=$got_tmp2 args=$got_args2"
fi

# 3. Signal interruption cleans up scratch directory.
rec_tmp3="$WORK/tmp3"
rec_args3="$WORK/args3"
rc=0
started=$SECONDS
STUB_GO_MODE=term STUB_GO_CHILD_PID="$WORK/child-pid" STUB_GO_RECORD_TMPDIR="$rec_tmp3" STUB_GO_RECORD_ARGS="$rec_args3" \
	CLAWCTL_TEST_SCRATCH_ROOT="$override_root" \
	bash "$RUNNER" "$STUB_GO" || rc=$?
got_tmp3="$(<"$rec_tmp3")"
if [[ "$rc" -eq 143 && "$((SECONDS - started))" -lt 5 &&
	"$got_tmp3" == "$canonical_override_root"/g.* &&
	! -e "$got_tmp3" ]]; then
	if kill -0 "$(cat "$WORK/child-pid")" 2>/dev/null; then
		fail 'test-go left its test process running'
	else
		pass 'test-go stops the test process and removes scratch on SIGTERM'
	fi
else
	fail "test-go SIGTERM cleanup mismatch: rc=$rc tmp=$got_tmp3"
fi

# 4. Refuses tmpfs and ramfs without creating the target directory or running Go.
fake_bin="$WORK/fake-bin"
mkdir -p -- "$fake_bin"
cat >"$fake_bin/stat" <<'EOF'
#!/usr/bin/env bash
if [[ "${FAKE_PLATFORM:-}" == Darwin ]]; then exit 1; fi
if [[ "${1:-}" == "-f" ]]; then
	printf '%s\n' "${FAKE_FS_TYPE:-tmpfs}"
	exit 0
fi
exec /usr/bin/stat "$@"
EOF
chmod +x "$fake_bin/stat"

for fstype in tmpfs ramfs; do
	uncreated_root="$WORK/refused-$fstype/nested/go-tests"
	rec_tmp_refused="$WORK/tmp-$fstype"
	rc=0
	PATH="$fake_bin:$PATH" FAKE_FS_TYPE="$fstype" \
		STUB_GO_RECORD_TMPDIR="$rec_tmp_refused" STUB_GO_RECORD_ARGS="$WORK/args-$fstype" \
		CLAWCTL_TEST_SCRATCH_ROOT="$uncreated_root" \
		bash "$RUNNER" "$STUB_GO" >/dev/null 2>&1 || rc=$?
	if [[ "$rc" -ne 0 && ! -e "$WORK/refused-$fstype" && ! -e "$rec_tmp_refused" ]]; then
		pass "test-go refuses $fstype ancestor before creating scratch directories"
	else
		fail "test-go did not refuse $fstype cleanly: rc=$rc"
	fi
done

# macOS uses BSD stat and mount output; cover paths with spaces and nested mounts.
cat >"$fake_bin/uname" <<'EOF'
#!/usr/bin/env bash
if [[ "${FAKE_PLATFORM:-}" == Darwin ]]; then printf 'Darwin\n'; else /usr/bin/uname "$@"; fi
EOF
cat >"$fake_bin/mount" <<'EOF'
#!/usr/bin/env bash
printf '/dev/disk1 on / (apfs, local)\n'
printf '/dev/disk2 on %s (%s, local)\n' "$FAKE_MOUNT_POINT" "$FAKE_MOUNT_TYPE"
EOF
chmod +x "$fake_bin/uname" "$fake_bin/mount"
darwin_root="$WORK/macos disk"
mkdir -p "$darwin_root"
for fstype in apfs tmpfs ramfs; do
	rec="$WORK/mac-$fstype"
	dest="$darwin_root/$fstype/scratch"
	rc=0
	PATH="$fake_bin:$PATH" FAKE_PLATFORM=Darwin FAKE_MOUNT_POINT="$darwin_root" FAKE_MOUNT_TYPE="$fstype" \
		STUB_GO_RECORD_TMPDIR="$rec" STUB_GO_RECORD_ARGS="$WORK/mac-args" \
		CLAWCTL_TEST_SCRATCH_ROOT="$dest" bash "$RUNNER" "$STUB_GO" >/dev/null 2>&1 || rc=$?
	if [[ "$fstype" == apfs && "$rc" -eq 0 && -f "$rec" && ! -e "$(cat "$rec")" ]]; then
		pass 'test-go supports BSD tools and mount paths with spaces'
	elif [[ "$fstype" != apfs && "$rc" -ne 0 && ! -e "$dest" && ! -e "$rec" ]]; then
		pass "test-go refuses nested macOS $fstype mounts"
	else
		fail "test-go macOS filesystem detection: $fstype rc=$rc"
	fi
done

# 5. Refuses /dev/shm path without creating anything under /dev/shm.
shm_candidate="/dev/shm/clawctl-refused-$$"
rec_tmp_shm="$WORK/tmp-shm"
rc=0
STUB_GO_RECORD_TMPDIR="$rec_tmp_shm" STUB_GO_RECORD_ARGS="$WORK/args-shm" \
	CLAWCTL_TEST_SCRATCH_ROOT="$shm_candidate" \
	bash "$RUNNER" "$STUB_GO" >/dev/null 2>&1 || rc=$?
if [[ "$rc" -ne 0 && ! -e "$shm_candidate" && ! -e "$rec_tmp_shm" ]]; then
	pass 'test-go refuses /dev/shm scratch root without touching /dev/shm'
else
	fail "test-go did not refuse /dev/shm path cleanly: rc=$rc"
fi

# 6. Makefile test-go target delegates to the disk wrapper.
rec_tmp_make="$WORK/tmp-make"
rec_args_make="$WORK/args-make"
if STUB_GO_RECORD_TMPDIR="$rec_tmp_make" STUB_GO_RECORD_ARGS="$rec_args_make" \
		CLAWCTL_TEST_SCRATCH_ROOT="$override_root" \
		make -s -C "$ROOT" test-go GO="$STUB_GO"; then
	got_tmp_make="$(<"$rec_tmp_make")"
	got_args_make="$(<"$rec_args_make")"
	if [[ "$got_tmp_make" == "$canonical_override_root"/g.* &&
		"$got_args_make" == "test -timeout 30m ./..." &&
		! -e "$got_tmp_make" ]]; then
		pass 'Makefile test-go delegates to ops/test-go.sh with disk scratch and 30m timeout'
	else
		fail "Makefile test-go mismatch: tmp=$got_tmp_make args=$got_args_make"
	fi
else
	fail 'Makefile test-go check failed'
fi

printf 'test-go tests passed: %s, failed: %s\n' "$passed" "$failed"
[[ "$failed" -eq 0 ]]
