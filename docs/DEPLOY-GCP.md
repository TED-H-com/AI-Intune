# Deploy the Hub on GCP (GCE VM)

GCP is for people with free credits; [Fly](DEPLOY-FLY.md) stays the cheaper
default. Budget approximately **$60/month** for e2-standard-2 plus a 50 GB
pd-balanced disk. This is approximate, varies by region, and excludes extra
network traffic, backups, and separately billed external IPv4. Check current
[GCP VM pricing](https://cloud.google.com/products/compute/pricing/general-purpose),
[disk pricing](https://cloud.google.com/compute/disks-image-pricing), and the
pricing calculator before applying. This size is not the free-tier e2-micro.

## Provision

Install/authenticate gcloud on your workstation, enable Compute Engine and IAP
APIs, and obtain project Compute administration, firewall administration, IAP
TCP forwarding and OS Login permissions (OS Admin Login for sudo). Billing
budgets need separate billing-account permissions and the Budget API enabled.
All commands below use placeholders; replace them locally.

```bash
export GCP_PROJECT='<your-project>'
export GCP_REGION='<your-region>'
export GCP_ZONE='<your-zone>'
export GCP_VM_NAME=clawctl-hub
bash ops/gcp/provision.sh --dry-run
# Review first, then explicitly create resources:
bash ops/gcp/provision.sh --apply
```

No arguments also means offline preview: not even describe commands execute.
Apply describes before creating resources. Defaults: e2-standard-2, 50 GB
pd-balanced, Ubuntu 24.04 LTS amd64, retained boot disk, reserved static IPv4,
and a dedicated custom VPC/subnet. Override with `GCP_MACHINE_TYPE`,
`GCP_DISK_SIZE`, `GCP_DISK_TYPE`, `GCP_IMAGE_FAMILY`, `GCP_IMAGE_PROJECT`,
`GCP_NETWORK`, `GCP_SUBNET`, `GCP_SUBNET_RANGE`, `GCP_ADDRESS_NAME`,
`GCP_FIREWALL_NAME`, and `GCP_NETWORK_TAG`.

Only IAP's `35.235.240.0/20` may reach tcp:22. No public 22/80/443
rules are created. Use a new dedicated network; describe-before-create does
not reconcile drift or audit existing rules. Review effective organization,
hierarchical and VPC firewall policies before reusing any network. No VM
service account or cloud API scopes are attached.

```bash
gcloud compute ssh "$GCP_VM_NAME" --project="$GCP_PROJECT" \
  --zone="$GCP_ZONE" --tunnel-through-iap
```

## Host setup, Tailscale, and ingress

Copy a reviewed checkout onto the VM, with Git metadata. Install Git if needed.
Run from that checkout. Preview requires no root, secrets, or network:

```bash
bash ops/gcp/host-setup.sh --dry-run
sudo install -m 600 /dev/null /root/clawctl-gcp.env
# Edit that file locally with a terminal editor; do not paste secrets in commands.
sudo env GCP_SECRETS_FILE=/root/clawctl-gcp.env bash ops/gcp/host-setup.sh --apply
```

The root-owned mode-0600 file is trusted shell configuration. Set these values
using shell quoting as necessary; never commit it or enable shell tracing:

```bash
CLAWCTL_PUBLIC_URL=https://hub.example.com
TS_AUTHKEY='<your-auth-key>'
CLOUDFLARE_TUNNEL_TOKEN='<your-tunnel-token>'
R2_BUCKET='<your-bucket>'
R2_ENDPOINT='https://<your-account-id>.r2.cloudflarestorage.com'
R2_ACCESS_KEY_ID='<your-access-key>'
R2_SECRET_ACCESS_KEY='<your-secret-key>'
```

Alternatively supply exported environment variables through an appropriate
root environment, or use `TS_AUTHKEY_FILE` pointing to a private key-only file.
Tailscale is installed on the host; the key is passed by file, with join output
suppressed. Existing joined state is preserved. Configure tailnet ACLs for
administrative SSH; IAP remains a recovery path. This deployment uses local
Hub login with MFA over the tunnel; host Tailscale membership does not provide
Hub operator authentication. See [operator authentication](OPERATOR-AUTH.md).

Create a named Cloudflare Tunnel in the dashboard and set its public hostname
to `hub.example.com`, with HTTP service `http://127.0.0.1:8787`.
The tunnel runs outbound; keep public ingress ports closed. Protect the
Cloudflare account and tunnel token. Setup installs Docker, Tailscale and
cloudflared using their apt repositories, builds `ops/docker/Dockerfile`
target `hub-fly`, and runs restartable Hub and tunnel containers. The Hub
publishes only on host loopback; cloudflared uses the host network. Container
health checks query SQLite in read-only mode (the image has no curl or wget).
Setup waits up to 180 seconds for Docker health to become healthy, then prints
the loopback `/healthz` response body. Docker restart
policy restarts exited processes, not unhealthy processes: monitor both health
and tunnel connectivity externally. Proxy header trust is disabled by default;
review the repository's proxy guidance before enabling it.

`GCP_STATE_DIR` defaults to `/var/lib/clawctl`, `GCP_CONFIG_DIR` to
`/etc/clawctl-gcp`, and `GCP_HUB_IMAGE` to `clawctl-hub:gcp`. Repeated apply
rebuilds/replaces containers, causing a short interruption, while preserving
the database mount and Tailscale state. Schedule upgrades accordingly.
Container env files are root-only; Docker administrators can read secrets.
Do not dump container environments or startup logs containing setup codes.

For validation or staged setups, set any of these flags to `1` in the
environment or the private secrets file:

- `GCP_SKIP_TAILSCALE=1`: skip host Tailscale installation and joining.
- `GCP_SKIP_TUNNEL=1`: skip the tunnel token requirement, cloudflared
  installation and tunnel startup; remove any stale `clawctl-tunnel`
  container and `tunnel.env`.
- `GCP_SKIP_LITESTREAM=1`: skip R2 requirements and replication; rewrite
  `hub.env` without `LITESTREAM_REQUIRED` or R2 variables.

Each skipped service prints a `SKIPPED:` line. Preview reads flags from the
environment only; it does not source the secrets file. For example:

```bash
GCP_SKIP_TAILSCALE=1 GCP_SKIP_TUNNEL=1 GCP_SKIP_LITESTREAM=1 \
  bash ops/gcp/host-setup.sh --dry-run
```

Hub still uses `CLAWCTL_AUTH_MODE=local` and requires `CLAWCTL_PUBLIC_URL`
as an HTTPS origin on apply. The container receives no Tailscale auth key.
With replication skipped, the existing image entrypoint starts Hub directly.
The loopback listener remains available for validation when the tunnel is
skipped. Reapply without the skip flags and with the required credentials to
enable those services. Skipping host Tailscale leaves existing membership
unchanged.

## Litestream to R2 and budgets

The image already includes Litestream 0.5.17 and
[the shared configuration](../ops/fly/litestream.yml). R2 replication is required
by default. Use bucket-scoped read/write keys. The default replica prefix is
`clawctl/litestream/clawctl.sqlite`, with 10-second sync, daily snapshots, and
seven-day retention. Existing databases are never overwritten at startup;
a missing database is restored if a replica exists. Do not start a fresh VM
against a production replica until the migration gates below pass. Use a
separate bucket for a trial deployment. Run the shared
[restore drill](runbooks/RESTORE-DRILL.md) periodically; replication alone is
not evidence of recoverability.

Optional monthly alerts (default billing-account recipients):

```bash
export GCP_BILLING_ACCOUNT='<your-billing-account>'
export GCP_BUDGET_AMOUNT=60USD
bash ops/gcp/provision.sh --dry-run
bash ops/gcp/provision.sh --apply
```

The script lists budgets and creates a project-scoped budget only when its
`GCP_BUDGET_NAME` display name (default `clawctl-hub`) is absent. Thresholds
are 50%, 90%, and 100%. Existing budgets are left unchanged; review recipients,
project scope, credit treatment and amount in Billing. Alerts are not spending
caps. See [gcloud budget creation](https://docs.cloud.google.com/sdk/gcloud/reference/billing/budgets/create).

## Migration from Fly

1. Announce a maintenance window. Preserve the Fly machine, volume, image
   version, secrets and original tunnel/DNS configuration for rollback. Inventory
   DB, artifacts, bootstrap bundles, public origin and integration state. Keep
   the same image version on both sides to avoid schema changes during cutover.
2. Stop writes, workers, timers and external producers on Fly. Never run two
   pollers for the same integration token. Let the existing Litestream process
   flush its final WAL on graceful shutdown; verify completion and replica
   freshness. Do not simply kill it or assume a timed wait proves a final sync.
   Capture a consistent old SQLite snapshot using SQLite backup after writes
   stop; never copy a live main DB without its WAL.
3. Keep the GCE Hub and tunnel stopped. Build the image separately without
   running host-setup apply. Use Litestream from that image with the shared R2
   configuration and credentials to restore into a separate staging directory,
   never directly over a live DB. Follow the off-host restore drill for exact
   restore commands and environment initialization. Keep the restored copy
   read-only (mode 0400); preserve it as verification evidence. It must not be
   opened by a running Hub. Transfer the stopped old snapshot securely too.
4. Run `sqlite3 -readonly OLD.sqlite 'PRAGMA integrity_check;'` and the same
   command on `NEW.sqlite`, requiring `ok`. Then run:

   ```bash
   bash ops/gcp/compare-rowcounts.sh OLD.sqlite NEW.sqlite
   ```

   Both integrity checks and every table count must match, including the table
   set. Counts do not prove content equality: also compare snapshot hashes or
   logical content where appropriate, artifacts, and route behavior. Retain the
   evidence. Copy the verified new snapshot into the stopped GCE data directory
   as `clawctl.sqlite`, uid/gid 65532, directory mode 0700 and DB mode 0600.
   Restore required artifacts/bundles separately; do not copy Tailscale identity.
5. Configure the same public origin, then apply host setup only after these
   gates pass. Keep producers frozen until health and restored state are checked.
   Cut over the public hostname's DNS/tunnel route to GCE. Verify HTTPS
   `/healthz`, `/version`, login/MFA, enrollment and a controlled endpoint action,
   expected routes, artifact downloads and R2 restore. Unfreeze producers only
   after verification; ensure Fly remains stopped.
6. Rollback: stop GCE writes and workers first, restore the old tunnel/DNS route,
   and restart the retained Fly machine. If GCE accepted writes, reconcile/export
   them before restarting Fly; the old volume is now stale. Never run both
   writers. Keep GCE's disk and evidence for investigation.

Reported validation on a GCE VM restored a schema of **121 tables**, with row
counts matched and login taking **0.2–0.4 seconds**. These are supplied historical
observations, not benchmarks or live validation performed by these scripts.

Offline checks: `bash ops/test-gcp.sh` and
`shellcheck ops/gcp/*.sh ops/test-gcp.sh`. No real cloud provisioning is part
of those tests.
