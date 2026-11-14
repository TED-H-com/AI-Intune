#!/usr/bin/env bash
# Tests for ops/ci-race-shard.sh. A fake go on PATH records every call and
# plays back a list fixture; the real toolchain is never run.
set -uo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SCRIPT="$ROOT/ops/ci-race-shard.sh"

bash -n "$SCRIPT" || exit 1
shellcheck "$SCRIPT" "$0" || exit 1

WORK=$(mktemp -d) || exit 1
trap 'rm -rf "$WORK"' EXIT

passed=0
failed=0
ok() { passed=$((passed + 1)); printf 'ok  %s\n' "$1"; }
bad() { failed=$((failed + 1)); printf 'FAIL %s\n' "$1" >&2; }

mkdir "$WORK/bin" || exit 1
cat > "$WORK/bin/go" <<'EOF' || exit 1
#!/usr/bin/env bash
set -uo pipefail
printf '%s\n' --call-- "$@" >> "$FAKE_GO_LOG"
for arg in "$@"; do
	if [ "$arg" = -list ]; then
		cat "$FAKE_GO_LIST"
		exit "${FAKE_GO_LIST_RC:-0}"
	fi
done
exit "${FAKE_GO_RUN_RC:-0}"
EOF
chmod 755 "$WORK/bin/go" || exit 1

export PATH="$WORK/bin:$PATH"
export FAKE_GO_LOG="$WORK/go.log"
export FAKE_GO_LIST="$WORK/default-list"
export FAKE_GO_LIST_RC=0
export FAKE_GO_RUN_RC=0
unset RACE_TEST_TIMEOUT

cat > "$FAKE_GO_LIST" <<'EOF'
TestAlpha
TestBeta
BenchmarkGamma
TestDelta
FuzzEpsilon
ExampleZeta
TestEta
ok  	example.com/pkg	0.012s
EOF
cat > "$WORK/expected-names" <<'EOF'
ExampleZeta
FuzzEpsilon
TestAlpha
TestBeta
TestDelta
TestEta
EOF
printf 'TestAlpha\nTestBeta\n' > "$WORK/two-names"
printf 'BenchmarkGamma\nok  \texample.com/pkg\t0.012s\n' > "$WORK/no-names"
cp "$FAKE_GO_LIST" "$WORK/unsafe-list"
printf 'Test.Odd\n' >> "$WORK/unsafe-list"
cp "$FAKE_GO_LIST" "$WORK/output-list"
printf 'Testing 1 2 3\n' >> "$WORK/output-list"
cp "$FAKE_GO_LIST" "$WORK/duplicate-list"
printf 'TestAlpha\n' >> "$WORK/duplicate-list"

run_shard() {
	: > "$FAKE_GO_LOG"
	bash "$SCRIPT" "$@" > "$WORK/stdout" 2> "$WORK/stderr"
	RUN_STATUS=$?
	RUN_STDOUT=$(cat "$WORK/stdout")
	RUN_STDERR=$(cat "$WORK/stderr")
}

extract_call() {
	awk -v wanted="$1" '
		function emit(  i) {
			if (n && ((wanted == "list" && listing) || (wanted == "run" && !listing))) {
				for (i = 1; i <= n; i++) print args[i]
			}
		}
		$0 == "--call--" { emit(); n = 0; listing = 0; next }
		{ args[++n] = $0; if ($0 == "-list") listing = 1 }
		END { emit() }
	' "$FAKE_GO_LOG"
}

run_pattern() {
	extract_call run | awk '$0 == "-run" { if (getline) print; exit }'
}

pattern_names() {
	run_pattern | sed 's/^\^(//; s/)\$$//' | tr '|' '\n'
}

list_only() {
	awk '
		$0 == "--call--" { calls++ }
		$0 == "-list" { listings++ }
		END { exit !(calls == 1 && listings == 1) }
	' "$FAKE_GO_LOG"
}

rejects_args() {
	run_shard "$@"
	[ "$RUN_STATUS" -eq 2 ] && [ ! -s "$FAKE_GO_LOG" ]
}

partition_ok=1
smallest=7
largest=0
: > "$WORK/all-names"
: > "$WORK/all-patterns"
for shard in 1 2 3; do
	run_shard "$shard" 3 ./pkg/a ./pkg/b
	[ "$RUN_STATUS" -eq 0 ] || partition_ok=0
	if [ "$shard" -eq 1 ]; then
		printf '%s\n' "$RUN_STDOUT" > "$WORK/shard-one-stdout"
	fi
	run_pattern >> "$WORK/all-patterns"
	pattern_names > "$WORK/shard-names"
	cat "$WORK/shard-names" >> "$WORK/all-names"
	count=$(awk 'END { print NR }' "$WORK/shard-names")
	[ "$count" -gt 0 ] || partition_ok=0
	[ "$count" -ge "$smallest" ] || smallest=$count
	[ "$count" -le "$largest" ] || largest=$count
done
LC_ALL=C sort "$WORK/all-names" > "$WORK/sorted-names"
total=$(awk 'END { print NR }' "$WORK/all-names")
if [ "$partition_ok" -eq 1 ] && [ "$total" -eq 6 ] &&
	[ $((largest - smallest)) -le 1 ] && cmp -s "$WORK/expected-names" "$WORK/sorted-names"; then
	ok 'partition covers six names once and balances shards'
else
	bad 'partition covers six names once and balances shards'
fi

if ! grep -Eq 'BenchmarkGamma|ok|example[.]com' "$WORK/all-patterns"; then
	ok 'patterns exclude benchmarks and package output'
else
	bad 'patterns exclude benchmarks and package output'
fi

anchors_ok=1
while IFS= read -r pattern; do
	case "$pattern" in
		'^('*')$') ;;
		*) anchors_ok=0 ;;
	esac
done < "$WORK/all-patterns"
if [ "$anchors_ok" -eq 1 ] && [ "$(wc -l < "$WORK/all-patterns")" -eq 3 ]; then
	ok 'patterns are anchored'
else
	bad 'patterns are anchored'
fi

extract_call run > "$WORK/run-args"
extract_call list > "$WORK/list-args"
if awk '
	$0 == "--call--" { calls++ }
	END { exit !(calls == 2) }
' "$FAKE_GO_LOG" && awk '
	$0 == "test" { test_arg = 1 }
	$0 == "-race" { race = 1 }
	$0 == "-count=1" { count = 1 }
	previous == "-timeout" && $0 == "75m" { timeout = 1 }
	$0 == "-run" { run = 1 }
	{ before_last = last; last = $0; previous = $0 }
	END { exit !(test_arg && race && count && timeout && run && before_last == "./pkg/a" && last == "./pkg/b") }
' "$WORK/run-args" && awk '
	$0 == "-race" { race = 1 }
	{ before_last = last; last = $0 }
	END { exit !(race && before_last == "./pkg/a" && last == "./pkg/b") }
' "$WORK/list-args"; then
	ok 'listing and test calls receive required arguments'
else
	bad 'listing and test calls receive required arguments'
fi

RACE_TEST_TIMEOUT=10m run_shard 1 3 ./pkg/a
if [ "$RUN_STATUS" -eq 0 ] && extract_call run | awk '
	previous == "-timeout" && $0 == "10m" { found = 1 }
	{ previous = $0 }
	END { exit !found }
'; then
	ok 'timeout override is passed to go test'
else
	bad 'timeout override is passed to go test'
fi

run_shard 1 1 ./pkg/a
pattern_names | LC_ALL=C sort > "$WORK/one-shard-names"
if [ "$RUN_STATUS" -eq 0 ] && cmp -s "$WORK/expected-names" "$WORK/one-shard-names"; then
	ok 'one shard contains every runnable name'
else
	bad 'one shard contains every runnable name'
fi

if grep -Fxq 'shard 1 of 3: 2 of 6 tests' "$WORK/shard-one-stdout"; then
	ok 'count line reports shard and total'
else
	bad 'count line reports shard and total'
fi

args_ok=1
rejects_args 0 3 ./pkg/a || args_ok=0
rejects_args 4 3 ./pkg/a || args_ok=0
rejects_args x 3 ./pkg/a || args_ok=0
rejects_args 1 x ./pkg/a || args_ok=0
rejects_args 1 0 ./pkg/a || args_ok=0
rejects_args 1 3 || args_ok=0
rejects_args || args_ok=0
if [ "$args_ok" -eq 1 ]; then
	ok 'invalid arguments exit 2 without calling go'
else
	bad 'invalid arguments exit 2 without calling go'
fi

FAKE_GO_LIST="$WORK/two-names" run_shard 3 3 ./pkg/a
if [ "$RUN_STATUS" -eq 1 ] && [[ "$RUN_STDERR" == *'has no tests'* ]] && list_only; then
	ok 'empty shard fails after listing only'
else
	bad 'empty shard fails after listing only'
fi

FAKE_GO_LIST="$WORK/no-names" run_shard 1 1 ./pkg/a
if [ "$RUN_STATUS" -eq 1 ] && [[ "$RUN_STDERR" == *'no tests listed'* ]] && list_only; then
	ok 'list with no runnable names fails before test run'
else
	bad 'list with no runnable names fails before test run'
fi

FAKE_GO_LIST_RC=1 run_shard 1 1 ./pkg/a
if [ "$RUN_STATUS" -ne 0 ] && list_only; then
	ok 'listing failure stops before test run'
else
	bad 'listing failure stops before test run'
fi

FAKE_GO_RUN_RC=3 run_shard 1 1 ./pkg/a
if [ "$RUN_STATUS" -eq 3 ]; then
	ok 'test run exit status is propagated'
else
	bad 'test run exit status is propagated'
fi

FAKE_GO_LIST="$WORK/unsafe-list" run_shard 1 1 ./pkg/a
if [ "$RUN_STATUS" -eq 1 ] && [[ "$RUN_STDERR" == *'Test.Odd'* ]] && list_only; then
	ok 'unsafe name fails after listing only'
else
	bad 'unsafe name fails after listing only'
fi

FAKE_GO_LIST="$WORK/output-list" run_shard 1 1 ./pkg/a
pattern_names | LC_ALL=C sort > "$WORK/output-names"
if [ "$RUN_STATUS" -eq 0 ] && cmp -s "$WORK/expected-names" "$WORK/output-names"; then
	ok 'non-name output is ignored'
else
	bad 'non-name output is ignored'
fi

FAKE_GO_LIST="$WORK/duplicate-list" run_shard 1 1 ./pkg/a
pattern_names | LC_ALL=C sort > "$WORK/duplicate-names"
if [ "$RUN_STATUS" -eq 0 ] && cmp -s "$WORK/expected-names" "$WORK/duplicate-names" &&
	[[ "$RUN_STDOUT" == *'shard 1 of 1: 6 of 6 tests'* ]]; then
	ok 'duplicate names run once and count once'
else
	bad 'duplicate names run once and count once'
fi

printf '\nci-race-shard tests passed: %s failed: %s\n' "$passed" "$failed"
[ "$failed" -eq 0 ]
