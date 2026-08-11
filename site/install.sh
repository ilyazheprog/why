#!/usr/bin/env bash
set -euo pipefail

repository=${WHY_GITHUB_REPOSITORY:-ilyazheprog/why}
release_base=${WHY_RELEASE_BASE:-https://github.com/${repository}/releases}
install_dir=${WHY_INSTALL_DIR:-${HOME}/.local/bin}
requested_version=${WHY_VERSION:-}

for dependency in curl tar sha256sum grep install mkdir mktemp mv uname; do
  if ! command -v "$dependency" >/dev/null 2>&1; then
    echo "why installer: required command not found: $dependency" >&2
    exit 1
  fi
done

if [[ $(uname -s) != Linux ]]; then
  echo "why installer: only Linux is currently supported" >&2
  exit 1
fi

case $(uname -m) in
  x86_64|amd64) architecture=amd64 ;;
  aarch64|arm64) architecture=arm64 ;;
  *)
    echo "why installer: unsupported architecture: $(uname -m)" >&2
    exit 1
    ;;
esac

if [[ -n "$requested_version" ]]; then
  version=${requested_version#v}
else
  if ! latest_url=$(curl -fsSL -o /dev/null -w '%{url_effective}' "${release_base}/latest"); then
    echo "why installer: no public release is available yet" >&2
    exit 1
  fi
  tag=${latest_url##*/}
  if [[ $tag != v* ]]; then
    echo "why installer: could not determine the latest release" >&2
    exit 1
  fi
  version=${tag#v}
fi

if [[ ! $version =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  echo "why installer: invalid version: $version" >&2
  exit 1
fi

target=${install_dir}/why
if [[ -x $target ]] && [[ $($target --version 2>/dev/null || true) == "why $version" ]]; then
  echo "why $version is already installed at $target"
  exit 0
fi

archive_name="why_${version}_linux_${architecture}.tar.gz"
download_base="${release_base}/download/v${version}"
install_tmp=$(mktemp -d)
target_tmp=

cleanup() {
  rm -rf -- "$install_tmp"
  if [[ -n "$target_tmp" ]]; then rm -f -- "$target_tmp"; fi
}
trap cleanup EXIT

echo "Downloading why $version for linux/$architecture..."
curl -fsSL --retry 3 -o "$install_tmp/$archive_name" "$download_base/$archive_name"
curl -fsSL --retry 3 -o "$install_tmp/SHA256SUMS" "$download_base/SHA256SUMS"

if ! grep "  ${archive_name}$" "$install_tmp/SHA256SUMS" > "$install_tmp/CHECKSUM"; then
  echo "why installer: release checksum does not contain $archive_name" >&2
  exit 1
fi
(cd "$install_tmp" && sha256sum -c CHECKSUM)

tar -xzf "$install_tmp/$archive_name" -C "$install_tmp"
source_binary="$install_tmp/why_${version}_linux_${architecture}/why"
if [[ ! -f $source_binary ]]; then
  echo "why installer: release archive does not contain the expected binary" >&2
  exit 1
fi

mkdir -p "$install_dir"
target_tmp=$(mktemp "${install_dir}/.why.XXXXXX")
install -m 0755 "$source_binary" "$target_tmp"
mv -f "$target_tmp" "$target"
target_tmp=

echo "Installed why $version to $target"
case :${PATH}: in
  *:"$install_dir":*) ;;
  *) echo "Add $install_dir to PATH to run 'why' from any directory." ;;
esac
