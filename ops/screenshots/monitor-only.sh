#!/usr/bin/env bash
# Local SSR fixtures only; no Hub login or network requests.
set -euo pipefail
repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
output_dir="${1:-$repo_dir/docs/screenshots/monitor-only}"
mkdir -p "$output_dir"
output_dir="$(cd -- "$output_dir" && pwd)"
cd "$repo_dir"
CLAWCTL_PROFILE_SCREENSHOT_DIR="$output_dir" go test ./internal/web -run '^TestMonitorOnlyProfileSSRPreviewConfirmAndHiddenActions$' -count=1
browser_path="${CLAWCTL_SCREENSHOT_BROWSER:-}"
if [[ -z "$browser_path" ]]; then
  for candidate in chromium google-chrome chromium-browser; do
    if command -v "$candidate" >/dev/null 2>&1; then
      browser_path="$(command -v "$candidate")"
      break
    fi
  done
fi
if [[ -z "$browser_path" ]]; then
  printf 'No browser found; fixture HTML saved to %s\n' "$output_dir"
  exit 0
fi
browser_profile="$(mktemp -d "${TMPDIR:-/tmp}/monitor-only-browser.XXXXXX")"
trap 'rm -rf -- "$browser_profile"' EXIT
for width in 390 768 1440; do
  for fixture in "$output_dir"/*.html; do
    fragment=''
    if [[ "$fixture" == */monitor-only-machine.html ]]; then fragment='' ; fi
    "$browser_path" --headless --no-sandbox --disable-gpu --disable-dev-shm-usage \
      --no-first-run --no-default-browser-check --hide-scrollbars \
      --user-data-dir="$browser_profile" --window-size="$width,1100" \
      --force-device-scale-factor=1 --screenshot="${fixture%.html}-$width.png" \
      "file://$fixture$fragment" >/dev/null 2>&1
  done
done
