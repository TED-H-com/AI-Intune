#!/usr/bin/env bash
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CLAWCTL_SCREENSHOT_VIEWPORT=1280,2200 CLAWCTL_SCREENSHOT_TEST=TestDeepDiskScreenshotFixtures bash "$script_dir/phase2-disk.sh" "${1:-$script_dir/../../docs/screenshots/phase2/p2-03}"
