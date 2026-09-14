#!/usr/bin/env bash

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
regress_py=${REGRESS_PY:-"$script_dir/regress_gfarm2fs.py"}
test_dir=$(mktemp -d /tmp/gfarm2fs-test-localfs.XXXXXX)

cleanup() {
    local status=$?
    rmdir "$test_dir" 2>/dev/null || true
    exit "$status"
}
trap cleanup EXIT INT TERM

python3 "$regress_py" "$test_dir" "$@"
