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
  grep -Fq 'apt-get install docker.io docker-buildx ca-certificates curl sqlite3' "$tmp/host"
  grep -Fq 'DOCKER_BUILDKIT=1 docker buildx build --load --file ops/docker/Dockerfile --target hub-fly --tag clawctl-hub:gcp .' "$tmp/host"
done
# Exercise every combination independently; previews must stay offline.
for tailscale in 0 1; do
  for tunnel in 0 1; do
    for litestream in 0 1; do
      GCP_SKIP_TAILSCALE=$tailscale GCP_SKIP_TUNNEL=$tunnel GCP_SKIP_LITESTREAM=$litestream \
        TS_AUTHKEY=secret-sentinel CLOUDFLARE_TUNNEL_TOKEN=secret-sentinel \
        R2_SECRET_ACCESS_KEY=secret-sentinel PATH="$tmp/bin:$PATH" \
        bash "$root/ops/gcp/host-setup.sh" --dry-run > "$tmp/skip"
      if grep -Fq secret-sentinel "$tmp/skip"; then exit 1; fi
      for service in Tailscale 'Cloudflare Tunnel' Litestream; do
        case $service in
          Tailscale) skipped=$tailscale; active='Install Tailscale' ;;
          'Cloudflare Tunnel') skipped=$tunnel; active='Install cloudflared' ;;
          Litestream) skipped=$litestream; active='Require R2 variables' ;;
        esac
        if [[ $skipped == 1 ]]; then
          grep -Fxq "SKIPPED: $service" "$tmp/skip"
          if grep -Fq "$active" "$tmp/skip"; then exit 1; fi
        else
          grep -Fq "$active" "$tmp/skip"
          if grep -Fxq "SKIPPED: $service" "$tmp/skip"; then exit 1; fi
        fi
      done
      grep -Fq 'sqlite3 -readonly' "$tmp/skip"
      grep -Fq 'print /healthz body' "$tmp/skip"
    done
  done
done
GCP_BILLING_ACCOUNT='<billing-account>' GCP_BUDGET_AMOUNT=60USD PATH="$tmp/bin:$PATH" bash "$root/ops/gcp/provision.sh" --dry-run > "$tmp/budget"
for threshold in 0.5 0.9 1.0; do grep -Fq "percent=$threshold" "$tmp/budget"; done
[[ ! -e $GCP_TEST_SENTINEL ]]
# Mock apply mode: missing resources are quiet, repeated runs create nothing,
# and creation errors remain visible and stop provisioning.
cat > "$tmp/bin/gcloud" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$GCP_TEST_STATE/calls"
if [[ $* == *"--format=value(address)"* ]]; then
  echo '192.0.2.1'
  exit 0
fi
for ((i=1; i<=$#; i++)); do
  if [[ ${!i} == describe || ${!i} == create ]]; then
    action=${!i}
    next=$((i + 1))
    name=${!next}
    previous=$((i - 1))
    kind=${!previous}
    resource="$GCP_TEST_STATE/$kind-$name"
    if [[ $action == describe ]]; then
      [[ ! -e $resource ]] || exit 0
      echo 'ERROR resource was not found' >&2
      exit 1
    fi
    if [[ ${GCP_TEST_CREATE_FAIL:-0} == 1 ]]; then
      echo 'creation failed' >&2
      exit 42
    fi
    touch "$resource"
    exit 0
  fi
done
exit 98
MOCK
chmod +x "$tmp/bin/gcloud"
export GCP_TEST_STATE="$tmp/resources"
mkdir "$GCP_TEST_STATE"
for run in first repeat; do
  GCP_PROJECT=test-project GCP_REGION=test-region GCP_ZONE=test-zone PATH="$tmp/bin:$PATH" \
    bash "$root/ops/gcp/provision.sh" --apply > "$tmp/$run.out" 2> "$tmp/$run.err"
  [[ ! -s $tmp/$run.err ]]
done
[[ $(grep -c '^creating ' "$tmp/first.out") == 5 ]]
grep -Fxq 'creating subnets clawctl-hub' "$tmp/first.out"
[[ $(grep -c '^exists: ' "$tmp/repeat.out") == 5 ]]
[[ $(grep -c ' create ' "$GCP_TEST_STATE/calls") == 5 ]]
rm "$GCP_TEST_STATE/networks-clawctl-hub"
if GCP_TEST_CREATE_FAIL=1 GCP_PROJECT=test-project GCP_REGION=test-region GCP_ZONE=test-zone PATH="$tmp/bin:$PATH" \
  bash "$root/ops/gcp/provision.sh" --apply > "$tmp/fail.out" 2> "$tmp/fail.err"; then
  exit 1
else
  [[ $? == 42 ]]
fi
grep -Fxq 'creation failed' "$tmp/fail.err"
[[ $(wc -l < "$tmp/fail.err") == 1 ]]
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
