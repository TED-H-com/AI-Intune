#!/usr/bin/env bash
set -euo pipefail
BASE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
python3 "$BASE/test_applier.py"
exec python3 "$BASE/test_disks.py"
