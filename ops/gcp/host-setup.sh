#!/usr/bin/env bash
# Run from a reviewed checkout on Ubuntu 24.04. Never enable tracing.
set +x
set -euo pipefail
case ${1:---dry-run} in
  --dry-run)
    cat <<'PLAN'
apt-get install docker.io ca-certificates curl sqlite3
Install Tailscale from its Ubuntu noble apt repository; enable tailscaled
Join Tailscale using a private auth-key file (only when not already joined)
docker build --file ops/docker/Dockerfile --target hub-fly --tag clawctl-hub:gcp .
Write root-only container and tunnel env files (values suppressed)
docker run --restart unless-stopped --publish 127.0.0.1:8787:8787 --health-cmd 'sqlite3 /var/lib/clawctl/clawctl.sqlite "SELECT 1"' ...
Install cloudflared from its apt repository; run outbound tunnel as a restartable container
Reuse built-in Litestream 0.5 and ops/fly/litestream.yml for R2 replication
PLAN
    exit 0 ;;
  --apply) ;;
  *) echo 'Usage: host-setup.sh [--dry-run|--apply]' >&2; exit 2 ;;
esac
[[ $# -le 1 && $(id -u) == 0 ]] || { echo 'Run as root with --apply' >&2; exit 1; }
umask 077
# Optional trusted root-owned shell file, outside the checkout; never source in preview.
if [[ -n ${GCP_SECRETS_FILE:-} ]]; then
  [[ $(stat -c '%u:%a' "$GCP_SECRETS_FILE") == 0:600 ]] || { echo 'Secrets file must be root-owned mode 0600' >&2; exit 1; }
  set -a
  # shellcheck disable=SC1090
  . "$GCP_SECRETS_FILE"
  set +a
fi
: "${CLAWCTL_PUBLIC_URL:?Set HTTPS origin}" "${CLOUDFLARE_TUNNEL_TOKEN:?Set tunnel token}"
: "${R2_BUCKET:?Set bucket}" "${R2_ENDPOINT:?Set endpoint}" "${R2_ACCESS_KEY_ID:?Set access key}" "${R2_SECRET_ACCESS_KEY:?Set secret key}"
root=$(cd "$(dirname "$0")/../.." && pwd)
state=${GCP_STATE_DIR:-/var/lib/clawctl}
config=${GCP_CONFIG_DIR:-/etc/clawctl-gcp}
install -d -m 700 "$config"
exec 9>"$config/setup.lock"
flock -n 9
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y docker.io ca-certificates curl sqlite3
systemctl enable --now docker
curl -fsSL https://pkgs.tailscale.com/stable/ubuntu/noble.noarmor.gpg -o /usr/share/keyrings/tailscale-archive-keyring.gpg
curl -fsSL https://pkgs.tailscale.com/stable/ubuntu/noble.tailscale-keyring.list -o /etc/apt/sources.list.d/tailscale.list
curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg -o /usr/share/keyrings/cloudflare-main.gpg
printf '%s\n' 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main' > /etc/apt/sources.list.d/cloudflared.list
apt-get update
apt-get install -y tailscale cloudflared
systemctl enable --now tailscaled
if ! tailscale ip -4 >/dev/null 2>&1; then
  keyfile=${TS_AUTHKEY_FILE:-$config/ts-authkey}
  if [[ -n ${TS_AUTHKEY:-} ]]; then printf '%s' "$TS_AUTHKEY" > "$keyfile"; chmod 600 "$keyfile"; fi
  [[ -s $keyfile ]] || { echo 'Set TS_AUTHKEY or TS_AUTHKEY_FILE' >&2; exit 1; }
  tailscale up --auth-key="file:$keyfile" >/dev/null 2>&1 || { echo 'Tailscale join failed' >&2; exit 1; }
fi
install -d -m 700 "$state"
# The image initializer manages database ownership; do not recursively chown.
write_env() {
  local name value
  for name in "$@"; do
    value=${!name:-}
    [[ $value != *$'\n'* && $value != *$'\r'* ]] || { echo 'Multiline environment value refused' >&2; return 1; }
    printf '%s=%s\n' "$name" "$value"
  done
}
export CLAWCTL_AUTH_MODE=local
export CLAWCTL_PORT=8787
export CLAWCTL_TRUSTED_PROXIES=''
export CLAWCTL_CLIENT_IP_HEADER=X-Forwarded-For
export LITESTREAM_REQUIRED=1
write_env CLAWCTL_AUTH_MODE CLAWCTL_PORT CLAWCTL_PUBLIC_URL CLAWCTL_TRUSTED_PROXIES CLAWCTL_CLIENT_IP_HEADER LITESTREAM_REQUIRED R2_BUCKET R2_ENDPOINT R2_ACCESS_KEY_ID R2_SECRET_ACCESS_KEY > "$config/hub.env"
export TUNNEL_TOKEN=$CLOUDFLARE_TUNNEL_TOKEN
write_env TUNNEL_TOKEN > "$config/tunnel.env"
image=${GCP_HUB_IMAGE:-clawctl-hub:gcp}
docker build --file "$root/ops/docker/Dockerfile" --target hub-fly --build-arg "CLAWCTL_VERSION=$(git -C "$root" rev-parse --short HEAD)" --tag "$image" "$root"
# Reconcile containers on repeated setup; preserve the data bind mount.
docker rm -f clawctl-hub >/dev/null 2>&1 || true
docker run -d --name clawctl-hub --restart unless-stopped --stop-timeout 60 --env-file "$config/hub.env" --publish 127.0.0.1:8787:8787 --mount "type=bind,src=$state,dst=/var/lib/clawctl" --health-cmd 'sqlite3 /var/lib/clawctl/clawctl.sqlite "SELECT 1"' --health-interval 30s --health-start-period 60s "$image" >/dev/null
docker rm -f clawctl-tunnel >/dev/null 2>&1 || true
# Host network lets cloudflared reach the loopback-only Hub listener.
docker run -d --name clawctl-tunnel --restart unless-stopped --network host --env-file "$config/tunnel.env" "${GCP_TUNNEL_IMAGE:-cloudflare/cloudflared:latest}" tunnel --no-autoupdate run >/dev/null
curl --fail --silent --show-error --retry 12 --retry-connrefused --retry-delay 5 http://127.0.0.1:8787/healthz >/dev/null
echo 'Host configured; verify tunnel health, login, and R2 restore before cutover.'
