#!/usr/bin/env bash
# Generate server-rendered, generic disk administration fixtures and screenshots.
set -euo pipefail
repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
output_dir="${1:-$repo_dir/docs/screenshots/phase2/p2-01}"
mkdir -p "$output_dir"
output_dir="$(cd -- "$output_dir" && pwd)"
cd "$repo_dir"
GOCACHE="${GOCACHE:-/tmp/gocache}" CLAWCTL_SCREENSHOT_DIR="$output_dir" go test ./internal/web -run '^TestDiskOpsScreenshotFixtures$' -count=1
browser_path=''
for candidate in google-chrome chromium chromium-browser google-chrome-stable; do
  if command -v "$candidate" >/dev/null 2>&1; then
    browser_path="$(command -v "$candidate")"
    break
  fi
done
if [[ -z "$browser_path" ]]; then
  printf 'Headless browser unavailable; fixture HTML saved to %s\n' "$output_dir"
  exit 0
fi
browser_profile="$(mktemp -d /tmp/p201-browser.XXXXXX)"
trap 'rm -rf -- "$browser_profile"' EXIT
for fixture in "$output_dir"/*.html; do
  png_path="${fixture%.html}.png"
  if ! "$browser_path" --headless --no-sandbox --disable-gpu --disable-dev-shm-usage \
      --disable-crashpad-for-testing --disable-crash-reporter --disable-breakpad --no-zygote --single-process \
      --user-data-dir="$browser_profile" --hide-scrollbars --no-first-run \
      --no-default-browser-check --window-size=1440,2200 --force-device-scale-factor=1 \
      --screenshot="$png_path" "file://$fixture" > /tmp/p201-screenshot-browser.log 2>&1; then
    printf 'Headless browser could not run; fixture HTML saved to %s\n' "$output_dir"
    exit 0
  fi
  printf 'Screenshot saved: %s\n' "$png_path"
done
