#!/usr/bin/env bash
# Preview by default; never consult gcloud in preview mode.
set -euo pipefail
apply=0
case ${1:---dry-run} in
  --dry-run) ;;
  --apply) apply=1 ;;
  *) echo 'Usage: provision.sh [--dry-run|--apply]' >&2; exit 2 ;;
esac
[[ $# -le 1 ]] || exit 2
project=${GCP_PROJECT:-<your-project>}
region=${GCP_REGION:-<your-region>}
zone=${GCP_ZONE:-<your-zone>}
vm=${GCP_VM_NAME:-clawctl-hub}
network=${GCP_NETWORK:-clawctl-hub}
subnet=${GCP_SUBNET:-clawctl-hub}
address=${GCP_ADDRESS_NAME:-clawctl-hub}
firewall=${GCP_FIREWALL_NAME:-clawctl-iap-ssh}
tag=${GCP_NETWORK_TAG:-clawctl-hub}
print() { printf '%q ' "$@"; printf '\n'; }
ensure() {
  # Describe failure is followed by create; permission/API failures stop creation
  # without changing or deleting existing resources.
  local split=0 kind name i
  local -a probe=() create=()
  for arg in "$@"; do
    if [[ $arg == :: ]]; then split=1
    elif (( split )); then create+=("$arg")
    else probe+=("$arg"); fi
  done
  if (( apply )); then
    for i in "${!probe[@]}"; do
      if [[ ${probe[i]} == describe ]]; then
        kind=${probe[i-1]}
        name=${probe[i+1]}
        break
      fi
    done
    if gcloud "${probe[@]}" --project="$project" >/dev/null 2>/dev/null; then
      printf 'exists: %s\n' "$name"
    else
      printf 'creating %s %s\n' "$kind" "$name"
      gcloud "${create[@]}" --project="$project" --quiet
    fi
  else
    print gcloud "${probe[@]}" --project="$project"
    printf '# If absent: '
    print gcloud "${create[@]}" --project="$project" --quiet
  fi
}
if (( apply )); then
  [[ $project != *'<'* && $region != *'<'* && $zone != *'<'* ]] || { echo 'Set GCP_PROJECT, GCP_REGION, GCP_ZONE' >&2; exit 1; }
fi
# Dedicated custom VPC avoids inherited default-network public SSH rules.
ensure compute networks describe "$network" :: compute networks create "$network" --subnet-mode=custom
ensure compute networks subnets describe "$subnet" --region="$region" :: compute networks subnets create "$subnet" --network="$network" --region="$region" --range="${GCP_SUBNET_RANGE:-10.42.0.0/24}"
ensure compute addresses describe "$address" --region="$region" :: compute addresses create "$address" --region="$region"
ensure compute firewall-rules describe "$firewall" :: compute firewall-rules create "$firewall" --network="$network" --direction=INGRESS --action=ALLOW --rules=tcp:22 --source-ranges=35.235.240.0/20 --target-tags="$tag"
ip='<reserved-address>'
if (( apply )); then ip=$(gcloud compute addresses describe "$address" --region="$region" --project="$project" --format='value(address)'); fi
ensure compute instances describe "$vm" --zone="$zone" :: compute instances create "$vm" --zone="$zone" --machine-type="${GCP_MACHINE_TYPE:-e2-standard-2}" --boot-disk-size="${GCP_DISK_SIZE:-50GB}" --boot-disk-type="${GCP_DISK_TYPE:-pd-balanced}" --no-boot-disk-auto-delete --image-family="${GCP_IMAGE_FAMILY:-ubuntu-2404-lts-amd64}" --image-project="${GCP_IMAGE_PROJECT:-ubuntu-os-cloud}" --network="$network" --subnet="$subnet" --address="$ip" --tags="$tag" --metadata=enable-oslogin=TRUE,block-project-ssh-keys=TRUE --no-service-account --no-scopes
if [[ -n ${GCP_BILLING_ACCOUNT:-} || -n ${GCP_BUDGET_AMOUNT:-} ]]; then
  : "${GCP_BILLING_ACCOUNT:?Set both billing account and amount}" "${GCP_BUDGET_AMOUNT:?Set both billing account and amount}"
  budget=${GCP_BUDGET_NAME:-clawctl-hub}
  cmd=(gcloud billing budgets create --billing-account="$GCP_BILLING_ACCOUNT" --display-name="$budget" --budget-amount="$GCP_BUDGET_AMOUNT" --filter-projects="projects/$project" --calendar-period=month --threshold-rule=percent=0.5 --threshold-rule=percent=0.9 --threshold-rule=percent=1.0)
  if (( apply )); then
    existing=$(gcloud billing budgets list --billing-account="$GCP_BILLING_ACCOUNT" --format='value(displayName)')
    if ! grep -Fxq -- "$budget" <<< "$existing"; then "${cmd[@]}"; fi
  else
    print gcloud billing budgets list --billing-account="$GCP_BILLING_ACCOUNT"
    printf '# If display name absent: '; print "${cmd[@]}"
  fi
fi
