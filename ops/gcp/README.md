# GCE Hub deployment

See [DEPLOY-GCP](../../docs/DEPLOY-GCP.md). Fly remains the cheaper default;
GCE is useful with free credits. Ubuntu 24.04, Docker, host Tailscale,
outbound Cloudflare Tunnel, and the existing hub-fly Litestream/R2 image.

Both setup scripts default to an offline command preview. Use `--apply` only
with reviewed environment settings. No public HTTP/HTTPS or SSH firewall rules
are created; SSH is restricted to IAP. Never commit credentials.

Run `bash ops/test-gcp.sh` for offline validation. Compare stopped snapshots
with `bash ops/gcp/compare-rowcounts.sh OLD.sqlite NEW.sqlite`.
