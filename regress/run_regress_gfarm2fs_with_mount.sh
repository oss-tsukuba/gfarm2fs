#!/usr/bin/env bash

set -euo pipefail

regress_args=${REGRESS_ARGS:-"--gfarm2fs --gfarmized --xattr"}

usage() {
    cat <<EOF
Usage:
  run_regress_gfarm2fs_with_mount.sh [--gfarm2fs-options '...'] [--] [regress_gfarm2fs.py args...]

Environment:
  REGRESS_PY             regress_gfarm2fs.py path (default: same directory as this script)
  REGRESS_ARGS           arguments passed to regress_gfarm2fs.py (default: ${regress_args})
  GFARM2FS_CMD           gfarm2fs command to run (default: gfarm2fs)
  GFARM2FS_OPTIONS       additional gfarm2fs mount options
  GFARM2FS_TESTDIR       test directory on Gfarm (default: /tmp)
EOF
}

script_name=$(basename "$0")
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

cmd_gfarm2fs=${GFARM2FS_CMD:-gfarm2fs}
regress_py=${REGRESS_PY:-"$script_dir/regress_gfarm2fs.py"}
gfarm2fs_options=${GFARM2FS_OPTIONS:-}
GFARM2FS_TESTDIR=${GFARM2FS_TESTDIR:-/tmp}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --gfarm2fs-options)
            shift
            [[ $# -gt 0 ]] || {
                usage >&2
                exit 2
            }
            gfarm2fs_options=${gfarm2fs_options:+$gfarm2fs_options }$1
            ;;
        --help | -h)
            usage
            exit 0
            ;;
        --)
            shift
            break
            ;;
        *)
            break
            ;;
    esac
    shift
done

mntdir=$(mktemp -d /tmp/gfarm2fs-test.XXXXXX)
mounted=0

info() {
    echo "[$script_name]" "$@"
}

cleanup() {
    local status=$?
    if [[ $mounted -eq 1 ]] && [[ -d "$mntdir" ]]; then
        info "Unmount $mntdir"
        if command -v fusermount3 >/dev/null 2>&1; then
            fusermount3 -u "$mntdir" || umount "$mntdir" || true
        else
            fusermount -u "$mntdir" || umount "$mntdir" || true
        fi
    fi
    if [[ -d "$mntdir" ]]; then
        rmdir "$mntdir" || true
    fi
    mounted=0
    exit "$status"
}
trap cleanup EXIT INT TERM

if [[ -n "${gfarm2fs_options}" ]]; then
    # shellcheck disable=SC2086
    # GFARM2FS_OPTIONS is intentionally a shell-style option string.
    info $cmd_gfarm2fs $gfarm2fs_options "$mntdir"
    # shellcheck disable=SC2086
    $cmd_gfarm2fs $gfarm2fs_options "$mntdir"
else
    info "$cmd_gfarm2fs" "$mntdir"
    $cmd_gfarm2fs "$mntdir"
fi
info "Mount $mntdir"
mounted=1

testdir="${mntdir}${GFARM2FS_TESTDIR}"
test_args=("$regress_py" "$testdir")
if [[ -n "${regress_args}" ]]; then
    # shellcheck disable=SC2206
    test_args+=($regress_args)
fi
if [[ $# -gt 0 ]]; then
    test_args+=("$@")
fi

if [ ! -d "$testdir" ]; then
    if [ "$GFARM2FS_TESTDIR" = "/tmp" ]; then
	# gfarmadm group is required
	mkdir -p -m 1777 "$testdir"
    fi
fi

info Run python3 "${test_args[@]}"
python3 "${test_args[@]}"
