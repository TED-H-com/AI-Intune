#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
INSTALLER="$SCRIPT_DIR/install-agent-macos.sh"
"$BASH" -n "$INSTALLER"
"$BASH" -n "${BASH_SOURCE[0]}"
if grep -Eq 'chmod[[:space:]]+[0-7]+[[:space:]]+--' "$INSTALLER"; then
  echo 'chmod options must precede the mode on macOS' >&2
  exit 1
fi

# Sourcing must not parse arguments, run preflight, or install anything.
# shellcheck source=ops/install-agent-macos.sh
source "$INSTALLER"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/clawctl-macos-test.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

# Keep the production BSD stat calls intact; translate only in Linux tests.
if [[ "$(uname -s)" == Linux ]]; then
  stat() {
    case "$2" in
      '%u') command stat -c '%u' "$3" ;;
      '%Lp') command stat -c '%a' "$3" ;;
      *) return 1 ;;
    esac
  }
fi

assert_mode() {
  [[ "$(stat -f '%Lp' "$2")" == "${1#0}" ]] || fail "Unexpected permissions: $2"
}

ensure_home_ancestor "$TMP/ancestor"
ensure_home_ancestor "$TMP/ancestor"
ensure_directory "$TMP/ancestor/private dir" 0700
assert_mode 0700 "$TMP/ancestor/private dir"
ensure_directory "$TMP/ancestor/private dir" 0755
assert_mode 0755 "$TMP/ancestor/private dir"
ensure_directory "$TMP/ancestor/private dir" 0700
assert_mode 0700 "$TMP/ancestor/private dir"
printf 'test\n' >"$TMP/test file"
for mode in 0600 0644 0700; do
  set_permissions "$mode" "$TMP/test file"
  assert_mode "$mode" "$TMP/test file"
done
ln -s "$TMP/ancestor/private dir" "$TMP/link"
if (ensure_directory "$TMP/link" 0755) 2>/dev/null; then
  fail 'Directory helper accepted a symlink'
fi
assert_mode 0700 "$TMP/ancestor/private dir"

# Exercise URL preflight without credentials or installation side effects.
[[ "$(CLAWCTL_INSTALL_AGENT_CHECK_HUB=1 "$BASH" "$INSTALLER" --hub http://100.64.0.1:8080/)" == http://100.64.0.1:8080 ]]
[[ "$(CLAWCTL_INSTALL_AGENT_CHECK_HUB=1 "$BASH" "$INSTALLER" --hub https://EXAMPLE.COM)" == https://example.com ]]
if CLAWCTL_INSTALL_AGENT_CHECK_HUB=1 "$BASH" "$INSTALLER" --hub http://127.0.0.1:8080 >/dev/null 2>&1; then
  fail 'Preflight accepted a non-Tailscale HTTP address'
fi

# Match the macOS installer checks in publish-agent-bundles.sh.
[[ "$(head -c 2 "$INSTALLER")" == '#!' ]]
for entry in Darwin launchctl clawctl-agent.plist --hub com.clawctl.agent; do
  grep -Fq -- "$entry" "$INSTALLER"
done
printf 'macOS installer tests passed\n'
