#!/usr/bin/env bash

set -uo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
regress_script=${REGRESS_SCRIPT:-"$script_dir/regress.sh"}
report_file=$(mktemp "${TMPDIR:-/tmp}/gfarm2fs-matrix-report.XXXXXX")
trap 'rm -f "${report_file}"' EXIT
export REPORT_FILE="${report_file}"
current_pid=""

interrupt() {
    local signal=$1
    if [[ -n "${current_pid}" ]]; then
        kill -"${signal}" "${current_pid}" 2>/dev/null || true
        wait "${current_pid}" 2>/dev/null || true
    fi
    exit 130
}

trap 'interrupt INT' INT
trap 'interrupt TERM' TERM

usage() {
    cat <<EOF
Usage:
  $(basename "$0") [--] [regress.sh arguments...]

Run the regression suite in five modes:
  default, --memcheck, --helgrind, --asan, --tsan

Arguments after '--' are passed to regress.sh on every run.
EOF
}

run_args=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --help | -h)
            usage
            exit 0
            ;;
        --)
            shift
            run_args=("$@")
            break
            ;;
        *)
            echo "$(basename "$0"): arguments must follow '--': $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

failed=()
read -r -a modes <<< "${REGRESS_MODES:-default --memcheck --helgrind --asan --tsan}"

run_mode() {
    local mode=$1
    shift

    if [[ -n "${mode}" ]]; then
        "$regress_script" "$mode" "$@" &
    else
        "$regress_script" "$@" &
    fi
    current_pid=$!
    local status=0
    wait "${current_pid}" || status=$?
    current_pid=""
    return "${status}"
}

for mode in "${modes[@]}"; do
    echo "================================================================"
    echo "regress-matrix: $mode"
    echo "================================================================"

    if [[ "$mode" == default ]]; then
        if run_mode "" -- "${run_args[@]}"; then
            :
        else
            failed+=("$mode")
        fi
    elif run_mode "$mode" -- "${run_args[@]}"; then
        :
    else
        failed+=("$mode")
    fi
done

set +x
TOOLS_WARN=0
if [[ -s "${report_file}" ]]; then
    echo "[ERROR] regress-matrix: Warning report files:" >&2
    sort -u "${report_file}" | while IFS=$'\t' read -r mode file; do
        printf '    *** File name (%s): %s\n' "${mode}" "${file}" >&2
    done
    TOOLS_WARN=1
else
    echo "[INFO]: regress-matrix: No tool warnings detected"
fi

if [[ ${#failed[@]} -gt 0 ]]; then
    printf '[ERROR] regress-matrix: failed modes:' >&2
    printf ' %s' "${failed[@]}" >&2
    printf '\n' >&2
    exit 1
fi

if [ ${TOOLS_WARN} -eq 1 ]; then
    exit 2
fi

echo "[ OK ]: regress-matrix: All modes passed"
