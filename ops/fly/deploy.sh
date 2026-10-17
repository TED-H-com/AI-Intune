#!/bin/bash
# Deploy the public HTTPS pack without changing the checked-in config.
# Auto: Depot -> classic remote builder (clean up new builders) -> local Docker.
# On restricted-egress hosts (only TCP 443 via an egress gateway), Depot gRPC
# handshake fails with EOF; the classic stream drops and h2c upgrade returns 500.
# Local build only needs registry.fly.io over 443 for the Fly image push.
set -euo pipefail
org=${FLY_ORG:-}
app=${FLY_APP:-}
region=${FLY_REGION:-iad}
url=${FLY_PUBLIC_URL:-}
public_url_given=0
[[ -z "$url" ]] || public_url_given=1
secrets_file=${FLY_SECRETS_FILE:-}
builder=${FLY_BUILDER:-auto}
skip_snapshot=${FLY_SKIP_SNAPSHOT:-0}
snapshot_timeout=${FLY_SNAPSHOT_TIMEOUT:-180}
dry_run=0
destroy=0
fail() { echo "deploy: $*" >&2; exit 1; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --org|--app|--region|--secrets-file|--public-url|--builder)
      [[ $# -ge 2 ]] || fail "missing flag value"
      case "$1" in
        --builder) builder=$2 ;;
        --org) org=$2 ;; --app) app=$2 ;; --region) region=$2 ;; --secrets-file) secrets_file=$2 ;;
        --public-url) url=$2; public_url_given=1 ;;
      esac
      shift 2 ;;
    --skip-snapshot) skip_snapshot=1; shift ;;
    --dry-run) dry_run=1; shift ;;
    --destroy) destroy=1; shift ;;
    *) fail "unknown flag" ;;
  esac
done
[[ "$skip_snapshot" == 0 || "$skip_snapshot" == 1 ]] || fail "FLY_SKIP_SNAPSHOT must be 0 or 1"
[[ "$snapshot_timeout" =~ ^[1-9][0-9]{0,3}$ ]] || fail "FLY_SNAPSHOT_TIMEOUT must be 1..9999 seconds"
if [[ "$destroy" == 0 && "$skip_snapshot" == 1 ]]; then
  echo "WARNING: SNAPSHOT SAFETY GATE DISABLED; deploying without a verified recovery snapshot!" >&2
fi
case "$builder" in auto|depot|remote|local) ;; *) fail "builder must be auto, depot, remote, or local" ;; esac
[[ "$app" =~ ^[a-z0-9-]{1,63}$ ]] || fail "invalid or empty app name"
[[ "$region" =~ ^[a-z0-9]+$ ]] || fail "invalid or empty region"
if [[ "$destroy" == 0 ]]; then
  [[ "$org" =~ ^[a-z0-9-]+$ ]] || fail "invalid or empty org"
fi
if [[ "$public_url_given" == 1 ]]; then
  url=${url%/}
  dns_label='[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
  [[ "$url" =~ ^https://$dns_label(\.$dns_label)*(:[0-9]{1,5})?$ ]] || fail "public URL must be https://<dns-host>[:port] with no path, query, fragment, or userinfo"
else
  url="https://$app.fly.dev"
fi
fly=$(command -v fly || command -v flyctl) || fail "fly or flyctl not found on PATH"
command -v python3 >/dev/null || fail "python3 not found on PATH"
command -v timeout >/dev/null || fail "timeout not found on PATH (GNU coreutils required)"
if [[ -n "$secrets_file" ]]; then
  [[ -f "$secrets_file" ]] || fail "secrets file must be a regular file"
  mode=$(python3 - "$secrets_file" <<'PY'
import os, stat, sys
print(oct(stat.S_IMODE(os.stat(sys.argv[1]).st_mode)))
PY
)
  [[ "$mode" == 0o600 ]] || fail "secrets file must have mode 0600"
  secrets_file=$(python3 - "$secrets_file" <<'PY2'
import os, sys
print(os.path.abspath(sys.argv[1]))
PY2
)
fi
plan() { printf '%q ' "$fly" "$@"; printf '\n'; }

if [[ "$dry_run" == 1 ]]; then
  if [[ "$destroy" == 1 ]]; then
    echo "Plan: require typed app name, destroy its clawctl_data volumes and app (including machines)."
    plan machines list -a "$app" --json
    plan machines destroy '<machine-id>' -a "$app" --force
    plan volumes list -a "$app" --json
    plan volumes destroy '<clawctl_data-volume-id>' -a "$app" --yes
    plan apps destroy "$app" --yes
  else
    echo "Plan: create only missing resources; one 1024mb machine and a 3GB volume. Config copied outside the repo."
    plan apps create "$app" --org "$org"
    plan volumes create clawctl_data --region "$region" --size 3 -a "$app" --yes
    if [[ -n "$secrets_file" ]]; then plan secrets import --stage -a "$app"; echo "Read secrets from the supplied file via stdin."; fi
    if [[ "$skip_snapshot" == 0 ]]; then
      plan volumes snapshots list '<data-volume-id>' -a "$app" --json
      plan volumes snapshots create '<data-volume-id>' -a "$app"
      echo "Poll snapshots list for each clawctl_data volume: new ID, status created, recent timestamp; timeout ${snapshot_timeout}s. Abort unless verified."
    fi
    builder_args=()
    case "$builder" in
      auto|depot) builder_args=(--depot=true) ;;
      remote) builder_args=(--depot=false) ;;
      local) builder_args=(--local-only) ;;
    esac
    plan deploy . --config '<temporary-config>' --dockerfile ops/docker/Dockerfile --build-target hub-fly --build-arg 'CLAWCTL_VERSION=<git-short-HEAD>' --ha=false --yes "${builder_args[@]}"
    if [[ "$builder" == auto ]]; then
      echo "Fallback chain: Depot -> remote -> --local-only if docker info succeeds; each builder gets three transient attempts with 2s/4s backoff."
      echo "Remove only newly created fly-builder-* apps before local fallback. Non-transient errors fail fast."
    else
      echo "Builder: $builder; no fallback. Remote mode removes only newly created fly-builder-* apps."
    fi
    plan scale count 1 -a "$app" --yes
    echo "Wait for $url/healthz; check /setup before reading a first-run code."
  fi
  exit 0
fi
[[ -n "${FLY_API_TOKEN:-}" ]] || "$fly" auth whoami >/dev/null 2>&1 || fail "Fly authentication required"
work=$(mktemp -d)
chmod 700 "$work"
trap 'rm -rf "$work"' EXIT
# Read Fly JSON without relying on table formatting.
json_items() {
  python3 - "$1" "$2" <<'PY'
import json, sys
items = json.load(open(sys.argv[1]))
if not isinstance(items, list):
    raise ValueError('expected Fly JSON array')
for item in items:
    name = item.get('Name', item.get('name', ''))
    if sys.argv[2] == 'apps':
        print(name)
    elif sys.argv[2] == 'machines':
        print(item.get('ID', item.get('id', '')))
    elif name == 'clawctl_data':
        print(item.get('ID', item.get('id', '')))
PY
}
if [[ "$destroy" == 1 ]]; then
  printf 'Type the app name to destroy %s: ' "$app" >&2
  confirmation=''
  IFS= read -r confirmation || [[ -n "$confirmation" ]] || fail "confirmation required"
  [[ "$confirmation" == "$app" ]] || fail "confirmation did not match; nothing deleted"
  "$fly" machines list -a "$app" --json > "$work/machines"
  json_items "$work/machines" machines > "$work/machine-ids"
  while IFS= read -r id; do
    [[ -n "$id" ]] || fail "invalid machine inventory"
    "$fly" machines destroy "$id" -a "$app" --force >/dev/null 2>&1 || fail "machine destroy failed"
  done < "$work/machine-ids"
  "$fly" volumes list -a "$app" --json > "$work/volumes"
  json_items "$work/volumes" volumes > "$work/ids"
  while IFS= read -r id; do
    [[ -n "$id" ]] || fail "invalid volume inventory"
    destroyed=0
    for _ in 1 2 3 4 5 6; do
      if "$fly" volumes destroy "$id" -a "$app" --yes >/dev/null 2>&1; then
        destroyed=1
        break
      fi
      sleep 2
    done
    [[ "$destroyed" == 1 ]] || fail "volume destroy failed"
  done < "$work/ids"
  "$fly" apps destroy "$app" --yes >/dev/null 2>&1 || fail "app destroy failed"
  echo "Destroyed $app and its clawctl_data volumes."
  exit 0
fi
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
command -v curl >/dev/null || fail "curl not found on PATH"
sed -e "s/^app = .*/app = \"$app\"/" -e "s/^primary_region = .*/primary_region = \"$region\"/" ops/fly/fly.toml > "$work/fly.toml"
"$fly" apps list --json > "$work/apps"
json_items "$work/apps" apps > "$work/names"
if ! grep -Fxq "$app" "$work/names"; then
  "$fly" apps create "$app" --org "$org" >/dev/null 2>&1 || fail "app creation failed"
fi
"$fly" volumes list -a "$app" --json > "$work/volumes"
json_items "$work/volumes" volumes > "$work/ids"
if [[ ! -s "$work/ids" ]]; then
  "$fly" volumes create clawctl_data --region "$region" --size 3 -a "$app" --yes >/dev/null 2>&1 || fail "volume creation failed"
fi
# Re-inventory after creating a volume; never deploy with an empty inventory.
"$fly" volumes list -a "$app" --json > "$work/volumes"
json_items "$work/volumes" volumes > "$work/ids"
[[ -s "$work/ids" ]] || fail "no data volumes found after provisioning"
if [[ "$skip_snapshot" == 0 ]]; then
  while IFS= read -r id; do
    [[ "$id" =~ ^vol_[a-zA-Z0-9_-]+$ ]] || fail "invalid data volume ID"
    timeout 15 "$fly" volumes snapshots list "$id" -a "$app" --json > "$work/snap-before" 2> "$work/snapshot-log" || fail "cannot inventory snapshots"
    started=$(date +%s)
    timeout 15 "$fly" volumes snapshots create "$id" -a "$app" > "$work/snapshot-log" 2>&1 || fail "snapshot creation failed"
    deadline=$((SECONDS + snapshot_timeout))
    while :; do
      if timeout 15 "$fly" volumes snapshots list "$id" -a "$app" --json > "$work/snap-after" 2> "$work/snapshot-log"; then
        snapshot=$(python3 - "$work/snap-before" "$work/snap-after" "$started" <<'PY_SNAPSHOT'
import datetime, json, re, sys, time
try:
    before, after = (json.load(open(p)) for p in sys.argv[1:3])
    assert isinstance(before, list) and isinstance(after, list)
    old = {s['id'] for s in before}
    for s in after:
        sid = s['id']
        created = datetime.datetime.fromisoformat(s['created_at'].replace('Z', '+00:00')).timestamp()
        now = time.time()
        if (sid not in old and re.fullmatch(r'vs_[a-zA-Z0-9_-]+', sid)
                and s['status'] == 'created' and int(sys.argv[3]) <= created <= now
                and now - created <= 300):
            print(sid)
            break
except (ValueError, KeyError, TypeError, AssertionError):
    pass
PY_SNAPSHOT
)
        if [[ -n "$snapshot" ]]; then
          echo "Verified snapshot $snapshot for volume $id (created after request; age <=300s)."
          break
        fi
      fi
      (( SECONDS < deadline )) || fail "snapshot verification timed out for volume $id; deployment blocked"
      sleep 2
    done
  done < "$work/ids"
fi
if [[ -n "$secrets_file" ]]; then
  "$fly" secrets import --stage -a "$app" < "$secrets_file" > "$work/import" 2>&1 || fail "secrets import failed"
fi
args=(deploy . --config "$work/fly.toml" --dockerfile ops/docker/Dockerfile --build-target hub-fly --build-arg "CLAWCTL_VERSION=$(git rev-parse --short HEAD)" --build-arg "CLAWCTL_COMMIT=$(git rev-parse HEAD)" --build-arg "CLAWCTL_BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)" --ha=false --yes)
# Return failure on exhaustion or a permanent error; callers preserve cleanup.
transient() {
  grep -Eiq 'unexpected EOF|(^|[^a-z])EOF([^a-z]|$)|context deadline|handshake|list[ -]workers|h2c|failed to dial gRPC|failed to get status|Unavailable|remote builder.*(500|502|503)|HTTP[^0-9]*(500|502|503)' "$1"
}
attempt_builder() {
  local stage=$1 attempt
  shift
  for attempt in 1 2 3; do
    if "$fly" "${args[@]}" "$@" > "$work/build-log" 2>&1; then return 0; fi
    # Raw builder output can contain build secrets; report only the classification.
    if ! transient "$work/build-log"; then
      build_permanent=1
      return 1
    fi
    echo "$stage transient failure (attempt $attempt/3)." >&2
    if [[ "$attempt" != 3 ]]; then sleep "$((attempt * 2))"; fi
  done
  return 1
}
remote_deploy() {
  "$fly" apps list --json > "$work/before" || fail "cannot inventory classic builders before deployment"
  json_items "$work/before" apps > "$work/before-names"
  build_failed=0
  attempt_builder remote --depot=false || build_failed=1
  "$fly" apps list --json > "$work/after" || fail "cannot inventory classic builders; check for leftover fly-builder apps"
  json_items "$work/after" apps > "$work/after-names"
  cleanup_failed=0
  while IFS= read -r name; do
    if [[ "$name" == fly-builder-* ]] && ! grep -Fxq "$name" "$work/before-names"; then
      if ! "$fly" apps destroy "$name" --yes >/dev/null 2>&1; then
        echo "Warning: builder teardown failed for $name" >&2
        cleanup_failed=1
      fi
    fi
  done < "$work/after-names"
  [[ "$cleanup_failed" == 0 ]] || fail "builder teardown incomplete"
  [[ "$build_permanent" == 0 ]] || fail "remote build failed (non-transient)"
  [[ "$build_failed" == 0 ]]
}
build_permanent=0
case "$builder" in
  local) attempt_builder local --local-only || fail "local build deploy failed" ;;
  remote) remote_deploy || fail "remote builder deploy failed" ;;
  auto|depot)
    if ! attempt_builder Depot --depot=true; then
      [[ "$build_permanent" == 0 ]] || fail "Depot build failed (non-transient)"
      [[ "$builder" == auto ]] || fail "Depot retries exhausted"
      echo "Depot retries exhausted; falling back to remote."
      if ! remote_deploy; then
        if ! command -v docker >/dev/null || ! docker info > "$work/docker" 2>&1; then
          fail "local Docker unavailable; start Docker and use --builder local (--local-only)"
        fi
        echo "Remote retries exhausted; falling back to --local-only."
        attempt_builder local --depot=false --local-only || fail "local build deploy failed"
      fi
    fi ;;
esac
"$fly" scale count 1 -a "$app" --yes >/dev/null 2>&1 || fail "scale failed"
deadline=$((SECONDS + 180))
while :; do
  status=$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 10 "$url/healthz") || status=000
  [[ "$status" == 200 ]] && break
  (( SECONDS < deadline )) || fail "health check timed out"
  sleep 3
done
echo "$url"
status=$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 10 "$url/setup") || fail "setup check failed"
case "$status" in
  200)
    "$fly" logs -a "$app" --no-tail > "$work/logs" 2>&1 || fail "cannot read setup logs"
    code=$(sed -n 's|.*first-run setup: open https://[^[:space:]]*/setup and enter setup code \([^[:space:]]*\).*|\1|p' "$work/logs" | tail -n 1)
    if [[ -n "$code" ]]; then printf 'Setup code: %s\n' "$code"; else echo "No generated setup code found; use your configured code."; fi ;;
  404) echo "Setup is already closed; use /login." ;;
  421)
    if [[ "$public_url_given" == 1 ]]; then
      fail "setup HTTP 421: --public-url / FLY_PUBLIC_URL must match the configured CLAWCTL_PUBLIC_URL"
    fi
    echo "fly.dev refuses operator routes (HTTP 421): CLAWCTL_PUBLIC_URL is a custom domain. Check https://<your-domain>/setup or rerun the checks with --public-url."
    exit 0 ;;
  *) fail "unexpected setup HTTP status" ;;
esac
echo "Next: open $url/setup or use ops/fly/setup-admin.sh for first-run setup."
echo "R2 is optional. Choose a custom domain before enrolling machines. Do not allocate a dedicated IPv4."
