#!/usr/bin/env bash
set -euo pipefail

repo_root=${1:?repository root is required}
test_version=9.8.7
case $(uname -m) in
  x86_64|amd64) test_arch=amd64 ;;
  aarch64|arm64) test_arch=arm64 ;;
  *) echo "unsupported test architecture: $(uname -m)" >&2; exit 1 ;;
esac
test_tmp=$(mktemp -d)
trap 'rm -rf -- "$test_tmp"' EXIT

release_dir="$test_tmp/releases/download/v$test_version"
archive_dir="why_${test_version}_linux_${test_arch}"
install_dir="$test_tmp/install"
mkdir -p "$release_dir" "$test_tmp/stage/$archive_dir"

CGO_ENABLED=0 GOOS=linux GOARCH="$test_arch" go build \
  -buildvcs=false \
  -ldflags "-X main.version=$test_version" \
  -o "$test_tmp/stage/$archive_dir/why" \
  "$repo_root/cmd/why"

tar -C "$test_tmp/stage" -czf "$release_dir/${archive_dir}.tar.gz" "$archive_dir"
(
  cd "$release_dir"
  sha256sum "${archive_dir}.tar.gz" > SHA256SUMS
)

WHY_VERSION="$test_version" \
WHY_RELEASE_BASE="file://$test_tmp/releases" \
WHY_INSTALL_DIR="$install_dir" \
  bash "$repo_root/site/install.sh"

test "$($install_dir/why --version)" = "why $test_version"

output=$(
  WHY_VERSION="$test_version" \
  WHY_RELEASE_BASE="file://$test_tmp/releases" \
  WHY_INSTALL_DIR="$install_dir" \
    bash "$repo_root/site/install.sh"
)
grep -q "already installed" <<<"$output"
