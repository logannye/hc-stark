#!/usr/bin/env bash
set -euo pipefail

umask 077

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(cd -- "$script_dir/../.." && pwd -P)
cd "$repo_root"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "disk-full crash evidence requires Linux" >&2
  exit 2
fi
if [[ -z "${HC_RELEASE_SHA:-}" ]]; then
  echo "HC_RELEASE_SHA must name the exact source commit" >&2
  exit 2
fi
if [[ $# -ne 2 ]]; then
  echo "usage: $0 OUTPUT_JSON LOG_DIRECTORY" >&2
  exit 2
fi

output=$1
log_dir=$2
image=$(mktemp --tmpdir tinyzkp-disk-full.XXXXXXXX.img)
mount_dir=$(mktemp -d --tmpdir tinyzkp-disk-full.XXXXXXXX)

cleanup() {
  sudo umount "$mount_dir" 2>/dev/null || true
  rm -f "$image"
  rmdir "$mount_dir" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

truncate -s 134217728 "$image"
mkfs.ext4 -q -F "$image"
sudo mount -o loop,nosuid,nodev,noexec "$image" "$mount_dir"
sudo chown "$(id -u):$(id -g)" "$mount_dir"
chmod 0700 "$mount_dir"

python3 scripts/release/run_crash_matrix.py \
  --output "$output" \
  --log-dir "$log_dir" \
  --disk-full-scratch "$mount_dir"
