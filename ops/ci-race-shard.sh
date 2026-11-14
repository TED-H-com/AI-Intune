#!/usr/bin/env bash
# Runs one shard of the tests of the given packages under the race detector.
#
# usage: ci-race-shard.sh SHARD SHARDS PACKAGE...
#
# The top-level tests, fuzz targets and examples of the packages are sorted by
# name and dealt out in turn, so each of them belongs to exactly one of the
# SHARDS shards. RACE_TEST_TIMEOUT sets the go test timeout (default 75m).
set -euo pipefail

if [ "$#" -lt 3 ]; then
	echo "usage: ci-race-shard.sh SHARD SHARDS PACKAGE..." >&2
	exit 2
fi
shard=$1
shards=$2
shift 2
case "$shard" in '' | *[!0-9]*) shard=0 ;; esac
case "$shards" in '' | *[!0-9]*) shards=0 ;; esac
if [ "$shards" -lt 1 ] || [ "$shard" -lt 1 ] || [ "$shard" -gt "$shards" ]; then
	echo "ci-race-shard.sh: SHARD must be between 1 and SHARDS" >&2
	exit 2
fi

list=$(go test -race -list . "$@")
names=$(printf '%s\n' "$list" | grep -E '^(Test|Fuzz|Example)[^[:space:]]*$' | LC_ALL=C sort -u) || true
if [ -z "$names" ]; then
	echo "ci-race-shard.sh: no tests listed for $*" >&2
	exit 1
fi
# The names go into a -run pattern. A name that is not a plain identifier
# stops the run here: it must not be dropped from every shard.
unsafe=$(printf '%s\n' "$names" | LC_ALL=C grep -v -E '^[A-Za-z0-9_]+$') || true
if [ -n "$unsafe" ]; then
	echo "ci-race-shard.sh: cannot shard these test names:" >&2
	printf '%s\n' "$unsafe" >&2
	exit 1
fi

selected=$(printf '%s\n' "$names" | awk -v n="$shards" -v k="$shard" 'NR % n == k % n')
if [ -z "$selected" ]; then
	echo "ci-race-shard.sh: shard $shard of $shards has no tests" >&2
	exit 1
fi
total=$(printf '%s\n' "$names" | wc -l | tr -d ' ')
count=$(printf '%s\n' "$selected" | wc -l | tr -d ' ')
echo "shard $shard of $shards: $count of $total tests"

pattern="^($(printf '%s\n' "$selected" | paste -sd'|' -))\$"
exec go test -race -count=1 -timeout "${RACE_TEST_TIMEOUT:-75m}" -run "$pattern" "$@"
