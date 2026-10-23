#!/usr/bin/env bash
# Check an extracted image's agent-bootstrap/<version> directory.
set -euo pipefail

fail() { echo "agent-bootstrap image check: $*" >&2; exit 1; }
[[ $# == 1 && -d $1 ]] || fail "usage: $0 <agent-bootstrap/version directory>"
dir=$(cd -- "$1" && pwd -P)
version=${dir##*/}
[[ $version =~ ^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$ ]] || fail 'invalid version directory name'
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

# Require exactly the six canonical checksum lines, including their order.
for os in linux windows darwin; do
  for arch in amd64 arm64; do
    name="clawctl-agent-bootstrap-$os-$arch.tar.gz"
    [[ -f $dir/$name && ! -L $dir/$name ]] || fail "missing archive: $name"
    (cd -- "$dir" && sha256sum "$name") >> "$work/SHA256SUMS"
  done
done
cmp "$work/SHA256SUMS" "$dir/SHA256SUMS" || fail 'SHA256SUMS does not match all six archives'
(cd -- "$dir" && sha256sum -c SHA256SUMS)

printf '%s\n' VERSION clawctl-agent clawctl-agent.plist install-agent-macos.sh > "$work/entries"
printf '%s\n' "$version" > "$work/VERSION"
for arch in amd64 arm64; do
  archive="$dir/clawctl-agent-bootstrap-darwin-$arch.tar.gz"
  tar -tzf "$archive" > "$work/actual-entries"
  cmp "$work/entries" "$work/actual-entries" || fail "unexpected Darwin $arch archive entries"
  tar -xOzf "$archive" VERSION > "$work/actual-version"
  cmp "$work/VERSION" "$work/actual-version" || fail "Darwin $arch VERSION mismatch"
  tar -xOzf "$archive" clawctl-agent > "$work/agent"
  # Little-endian MH_MAGIC_64, CPU_TYPE_X86_64 / CPU_TYPE_ARM64.
  header=$(od -An -tx1 -N8 "$work/agent" | tr -d ' \n')
  case "$arch:$header" in
    amd64:cffaedfe07000001|arm64:cffaedfe0c000001) ;;
    *) fail "Darwin $arch agent has invalid Mach-O magic or architecture" ;;
  esac
  if command -v file >/dev/null 2>&1; then
    file "$work/agent"
  fi
  tar -xOzf "$archive" install-agent-macos.sh > "$work/installer"
  if grep -Eq 'chmod[[:space:]]+[0-7]+[[:space:]]+--' "$work/installer"; then
    fail "Darwin $arch installer contains chmod mode --"
  fi
done
printf 'Verified all six agent bootstrap archives for %s\n' "$version"
