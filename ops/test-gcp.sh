#!/usr/bin/env bash
# Offline only. Command sentinels catch accidental cloud/network execution.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
shellcheck "$root"/ops/gcp/*.sh "$0"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/bin"
for tool in gcloud curl docker apt-get tailscale systemctl; do
  # shellcheck disable=SC2016
  printf '#!/usr/bin/env bash\necho unexpected-command >> "$GCP_TEST_SENTINEL"\nexit 97\n' > "$tmp/bin/$tool"
  chmod +x "$tmp/bin/$tool"
done
export GCP_TEST_SENTINEL="$tmp/called"
for flag in default --dry-run; do
  args=()
  [[ $flag == default ]] || args+=("$flag")
  PATH="$tmp/bin:$PATH" bash "$root/ops/gcp/provision.sh" "${args[@]}" > "$tmp/plan"
  grep -Fq 35.235.240.0/20 "$tmp/plan"
  if grep -Fq 0.0.0.0/0 "$tmp/plan"; then exit 1; fi
  grep -Fq e2-standard-2 "$tmp/plan"
  grep -Fq pd-balanced "$tmp/plan"
  TS_AUTHKEY=secret-sentinel CLOUDFLARE_TUNNEL_TOKEN=secret-sentinel PATH="$tmp/bin:$PATH" bash "$root/ops/gcp/host-setup.sh" "${args[@]}" > "$tmp/host"
  if grep -Fq secret-sentinel "$tmp/host"; then exit 1; fi
done
GCP_BILLING_ACCOUNT='<billing-account>' GCP_BUDGET_AMOUNT=60USD PATH="$tmp/bin:$PATH" bash "$root/ops/gcp/provision.sh" --dry-run > "$tmp/budget"
for threshold in 0.5 0.9 1.0; do grep -Fq "percent=$threshold" "$tmp/budget"; done
[[ ! -e $GCP_TEST_SENTINEL ]]
if command -v sqlite3 >/dev/null; then
  sqlite3 "$tmp/old.db" 'CREATE TABLE "odd table" (id); INSERT INTO "odd table" VALUES (1);'
  cp "$tmp/old.db" "$tmp/new.db"
  bash "$root/ops/gcp/compare-rowcounts.sh" "$tmp/old.db" "$tmp/new.db"
  sqlite3 "$tmp/new.db" 'INSERT INTO "odd table" VALUES (2);'
  if bash "$root/ops/gcp/compare-rowcounts.sh" "$tmp/old.db" "$tmp/new.db"; then exit 1; fi
  sqlite3 "$tmp/new.db" 'DELETE FROM "odd table" WHERE id=2; CREATE TABLE extra (id);'
  if bash "$root/ops/gcp/compare-rowcounts.sh" "$tmp/old.db" "$tmp/new.db"; then exit 1; fi
  printf 'corrupt database' > "$tmp/new.db"
  if bash "$root/ops/gcp/compare-rowcounts.sh" "$tmp/old.db" "$tmp/new.db"; then exit 1; fi
else
  echo 'SKIP: sqlite3 fixtures (sqlite3 unavailable)'
fi
echo 'GCP offline tests passed'
