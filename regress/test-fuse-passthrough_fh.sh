#!/usr/bin/env bash

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
regress_py=${REGRESS_PY:-"$script_dir/regress_gfarm2fs.py"}
fuse_pkg=${FUSE_PKG:-fuse3}
fuse_branch=${FUSE_BRANCH:-fuse-3.3.0}  # Available on almalinux8
fuse_url_base=${FUSE_URL_BASE:-https://raw.githubusercontent.com/libfuse/libfuse}
redownload=0
test_args=("--fuse")
while [[ $# -gt 0 ]]; do
    case "$1" in
        --re-download) redownload=1 ;;
        *) test_args+=("$1") ;;
    esac
    shift
done
work_dir=$(mktemp -d /tmp/gfarm2fs-test-passthrough_fh.XXXXXX)
mount_dir="$work_dir/mount"
test_dir="$work_dir/test"
mkdir "$mount_dir" "$test_dir"
passthrough="$work_dir/passthrough_fh"
source_file="$script_dir/passthrough_fh.c"
helper_file="$script_dir/passthrough_helpers.h"
mounted=0

cleanup() {
    local status=$?
    if [[ $mounted -eq 1 ]]; then
        if command -v fusermount3 >/dev/null 2>&1; then
            fusermount3 -u "$mount_dir" || umount "$mount_dir" || true
        else
            fusermount -u "$mount_dir" || umount "$mount_dir" || true
        fi
    fi
    rmdir "$mount_dir" || true
    rmdir "$test_dir" || true
    rm -f "$passthrough"
    rmdir "$work_dir" || true
    exit "$status"
}
trap cleanup EXIT INT TERM

if [[ $redownload -eq 1 || ! -f "$source_file" ]]; then
    echo "Downloading passthrough_fh.c from libfuse branch $fuse_branch"
    curl -fsSL "$fuse_url_base/$fuse_branch/example/passthrough_fh.c" \
        -o "$source_file"
fi

if grep -q 'passthrough_helpers.h' "$source_file" && \
   [[ $redownload -eq 1 || ! -f "$helper_file" ]]; then
    echo "Downloading passthrough_helpers.h from libfuse branch $fuse_branch"
    curl -fsSL "$fuse_url_base/$fuse_branch/example/passthrough_helpers.h" \
         -o "$helper_file"
fi

cmd() {
    echo [$*]
    $*
}

command -v pkg-config >/dev/null
cmd pkg-config --exists "$fuse_pkg"
cmd "${CC:-cc}" -Wall -Wextra -DHAVE_FALLOCATE -DHAVE_POSIX_FALLOCATE \
    -DHAVE_FSTATAT -DHAVE_SETXATTR -DHAVE_UTIMENSAT -DHAVE_FDATASYNC \
    -DHAVE_COPY_FILE_RANGE -Wno-unused-parameter \
    "$source_file" \
    $(pkg-config --cflags --libs "$fuse_pkg") -o "$passthrough"

cmd "$passthrough" "$mount_dir" &
passthrough_pid=$!
mounted=1
for _ in $(seq 1 50); do
    mountpoint -q "$mount_dir" && break
    kill -0 "$passthrough_pid" 2>/dev/null || exit 1
    sleep 0.1
done
mountpoint "$mount_dir"

cmd python3 "$regress_py" "$mount_dir$test_dir" "${test_args[@]}"
