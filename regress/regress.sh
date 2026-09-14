#!/usr/bin/env bash

set -euo pipefail

interrupt() {
    exit 130
}

trap interrupt INT TERM

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
run_script=${RUN_SCRIPT:-"${script_dir}/run_regress_gfarm2fs_with_mount.sh"}
build_script=${BUILD_SCRIPT:-"${script_dir}/build_gfarm2fs_for_test.sh"}
build_script_name=$(basename "${build_script}")
valgrind_suppressions=${VALGRIND_SUPPRESSIONS:-"${script_dir}/valgrind.supp"}
original_args=("$@")

REGRESS_ARGS=${REGRESS_ARGS:-"--gfarm2fs --gfarmized --xattr"}
export REGRESS_ARGS

usage() {
    cat <<EOF
Usage:
  regress.sh [${build_script_name} args...] [--] [run_regress_gfarm2fs_with_mount.sh args...]

Options for tool selection (at most one):
  --tsan        Enable ThreadSanitizer (requires build with -fsanitize=thread)
  --asan        Enable AddressSanitizer + LeakSanitizer (requires build with -fsanitize=address,undefined)
  --memcheck    Run under valgrind --tool=memcheck
  --helgrind    Run under valgrind --tool=helgrind

Options for log file:
  --logfile <path>   Log file prefix (a unique suffix is added per run; default: /var/tmp/gfarm2fs.log.<tool>)

Environment:
  BUILD_SCRIPT     build_gfarm2fs_for_test.sh path (default: same directory as this script)
  RUN_SCRIPT       run_regress_gfarm2fs_with_mount.sh path (default: same directory as this script)
  GFARM2FS_CMD     gfarm2fs command to run (default: built test binary; overridable below)
  REGRESS_ARGS     arguments passed to regress_gfarm2fs.py (default: ${REGRESS_ARGS})
  VALGRIND_SUPPRESSIONS  suppression file (default: regress/valgrind.supp)
  REPORT_FILE      file to which warning log paths are appended (optional)

Notes:
  - valgrind (--memcheck, --helgrind) and sanitizers (--tsan, --asan) cannot be combined.
  - Each tool option is mutually exclusive with the others.
EOF
}

build_args=()
run_args=()
seen_sep=0

# Tool selection (--tsan | --asan | --memcheck | --helgrind, at most one)
TOOL=""
LOGFILE=""

while [[ $# -gt 0 ]]; do
    if [[ $seen_sep -eq 1 ]]; then
        run_args+=("$1")
        shift
        continue
    fi

    case "$1" in
        --help | -h)
            usage
            exit 0
            ;;
        --tsan | --asan | --memcheck | --helgrind)
            if [[ -n "$TOOL" ]]; then
                echo "regress.sh: cannot combine tool options '$1' and '$TOOL'" >&2
                exit 2
            fi
            TOOL="$1"
            # Sanitizers need the corresponding flag passed to build_gfarm2fs_for_test.sh.
            case "$1" in
                --tsan) build_args+=("tsan") ;;
                --asan) build_args+=("asan") ;;
                --memcheck | --helgrind) : ;; # valgrind needs no instrumented build ;;
            esac
            shift
            continue
            ;;
        --logfile)
            shift
            [[ $# -gt 0 ]] || {
                echo "regress.sh: --logfile requires an argument" >&2
                exit 2
            }
            LOGFILE="$1"
            shift
            continue
            ;;
        --)
            seen_sep=1
            shift
            continue
            ;;
    esac

    build_args+=("$1")
    shift
done

if [[ -n "$LOGFILE" && -z "$TOOL" ]]; then
    echo "regress.sh: --logfile requires a tool option" >&2
    exit 2
fi

# Parallel tests are useful for race detectors, but add noise and overhead to
# the other modes.
PARALLEL_DEFAULT=3
case "$TOOL" in
    --tsan | --helgrind)
        if [[ -n "${REGRESS_ARGS+x}" ]]; then
            case " ${REGRESS_ARGS} " in
                *" --parallel="*) ;;
                *) REGRESS_ARGS="${REGRESS_ARGS} --parallel=${PARALLEL_DEFAULT}" ;;
            esac
        fi
        export REGRESS_ARGS
        ;;
esac

# Resolve default log file path for the selected tool.
default_logfile() {
    case "$TOOL" in
        --tsan) echo "/var/tmp/gfarm2fs.log.tsan" ;;
        --asan) echo "/var/tmp/gfarm2fs.log.asan" ;;
        --memcheck) echo "/var/tmp/gfarm2fs.log.memcheck" ;;
        --helgrind) echo "/var/tmp/gfarm2fs.log.helgrind" ;;
    esac
}

if [[ -n "$TOOL" && -z "$LOGFILE" ]]; then
    LOGFILE=$(default_logfile)
fi

# Use a unique prefix so stale logs from an earlier run are never reported.
RUN_LOGFILE=""
if [[ -n "$LOGFILE" ]]; then
    this_pid=$$
    run_id=$(date +%Y%m%d-%H%M%S).${this_pid}
    RUN_LOGFILE="${LOGFILE}.${run_id}"
fi

if [ -n "${GFARM2FS_CMD:-}" ]; then
    gfarm2fs_cmd="$GFARM2FS_CMD"
else
    build_dir="$("$build_script" "${build_args[@]}")"
    gfarm2fs_cmd="$build_dir/gfarm2fs"
fi
gfarm2fs_cmd_orig="${gfarm2fs_cmd}"

if [[ ! -x "$gfarm2fs_cmd" ]]; then
    echo "regress.sh: gfarm2fs command not found or not executable: $gfarm2fs_cmd" >&2
    exit 1
fi

if [[ -n "${TOOL}" ]]; then
    case "${TOOL}" in
        --tsan)
            export TSAN_OPTIONS="halt_on_error=false,log_exe_name=true,log_path=${RUN_LOGFILE},suppressions=${script_dir}/tsan.supp"
            ;;
        --asan)
            # Keep ASAN, LSAN, and UBSAN output separate while retaining the
            # per-run prefix.
            #export ASAN_OPTIONS="halt_on_error=false,log_exe_name=true,log_path=${RUN_LOGFILE}"
            export ASAN_OPTIONS="halt_on_error=false,detect_leaks=1,fast_unwind_on_malloc=0,log_exe_name=true,log_path=${RUN_LOGFILE}"
            export LSAN_OPTIONS="halt_on_error=false,log_exe_name=true,log_path=${RUN_LOGFILE}.lsan,suppressions=${script_dir}/lsan.supp"
            export UBSAN_OPTIONS="halt_on_error=false,log_exe_name=true,log_path=${RUN_LOGFILE}.ubsan"
            ;;
        --memcheck | --helgrind)
            if ! command -v valgrind >/dev/null 2>&1; then
                echo "regress.sh: valgrind is required for $TOOL but not found in PATH" >&2
                exit 1
            fi
            valgrind_gfarm2fs() {
                # shellcheck disable=SC2086
                echo >&2 "Run:" valgrind --tool="${_VALGRIND_TOOL}" \
                    --log-file="${_VALGRIND_LOG}" \
                    ${_VALGRIND_OPTIONS} \
                    "${_VALGRIND_CMD}" "$@"
                # shellcheck disable=SC2086
                valgrind --tool="${_VALGRIND_TOOL}" \
                    --log-file="${_VALGRIND_LOG}" \
                    ${_VALGRIND_OPTIONS} \
                    "${_VALGRIND_CMD}" "$@"
            }
            valgrind_gfarm2fs_supp() {
                # shellcheck disable=SC2086
                echo >&2 "Run:" valgrind --tool="${_VALGRIND_TOOL}" \
                    --log-file="${_VALGRIND_LOG}" \
                    --suppressions="${_VALGRIND_SUPPRESSIONS}" \
                    ${_VALGRIND_OPTIONS} \
                    "${_VALGRIND_CMD}" "$@"
                # shellcheck disable=SC2086
                valgrind --tool="${_VALGRIND_TOOL}" \
                    --log-file="${_VALGRIND_LOG}" \
                    --suppressions="${_VALGRIND_SUPPRESSIONS}" \
                    ${_VALGRIND_OPTIONS} \
                    "${_VALGRIND_CMD}" "$@"
            }

            valopt="--num-callers=50 --gen-suppressions=all"
            if [ "${TOOL}" = "--memcheck" ]; then
                valopt="${valopt} --leak-check=full"
                valopt="${valopt} --show-reachable=no"
                valopt="${valopt} --show-possibly-lost=no"
                valopt="${valopt} --errors-for-leak-kinds=definite,indirect"
            elif [ "${TOOL}" = "--helgrind" ]; then
                :;
            else
                :;
            fi
            _VALGRIND_CMD="${gfarm2fs_cmd}"
            _VALGRIND_OPTIONS="${valopt}"
            _VALGRIND_LOG="${RUN_LOGFILE}"
            _VALGRIND_TOOL="${TOOL#--}" # ex.: --memcheck -> memcheck
            _VALGRIND_SUPPRESSIONS="${valgrind_suppressions}"
            export _VALGRIND_OPTIONS _VALGRIND_CMD _VALGRIND_LOG \
                _VALGRIND_TOOL _VALGRIND_SUPPRESSIONS
            if [ -f "${valgrind_suppressions}" ]; then
                export -f valgrind_gfarm2fs_supp
                gfarm2fs_cmd="valgrind_gfarm2fs_supp"
            else
                echo >&2 "[WARNING] ${valgrind_suppressions} is not found. IGNORED"
                export -f valgrind_gfarm2fs
                gfarm2fs_cmd="valgrind_gfarm2fs"
            fi
            ;;
    esac
fi

case "${TOOL}" in
    --tsan | --asan)
	ldd "${gfarm2fs_cmd_orig}"

	if [[ "${TOOL}" = "--tsan" ]]; then
	    # Expected for CC=clang: "T __tsan_init"
	    nm "${gfarm2fs_cmd_orig}" | grep __tsan_init
	fi
	if [[ "${TOOL}" = "--asan" ]]; then
	    # Expected for CC=clang: "T __asan_init"
	    nm "${gfarm2fs_cmd_orig}" | grep __asan_init
	fi
	;;
esac

"${gfarm2fs_cmd_orig}" --version

export GFARM2FS_CMD="${gfarm2fs_cmd}"

result=
if "${run_script}" "${run_args[@]}"; then
    result="OK"
else
    result="NG"
fi

wait_for_valgrind_processes() {
    case "${TOOL}" in
        --memcheck | --helgrind) ;;
        *) return 0 ;;
    esac

    local i line running
    local RETRY=100
    local SLEEP_TIME=0.1
    for ((i = 0; i < RETRY; i++)); do
        running=0
        while IFS= read -r line; do
            if [[ "${line}" == *valgrind* ]] &&
                [[ "${line}" == *"--log-file=${RUN_LOGFILE}"* ]]; then
                running=1
                break
            fi
        done < <(ps -eo pid=,args=)

        if ((running == 0)); then
            return 0
        fi
        sleep "${SLEEP_TIME}"
    done

    echo "[INFO] Valgrind process still exists after $((RETRY / 10)) seconds" >&2
}

# The FUSE process can finish writing sanitizer logs shortly after unmount.
# Give it a bounded grace period before collecting the current run's files.
wait_for_sanitizer_logs() {
    case "${TOOL}" in
        --asan | --tsan) ;;
        *) return 0 ;;
    esac

    local i f signature previous_signature="<unobserved>"
    local files=()
    local RETRY=100
    local SLEEP_TIME=0.1
    local stable=0
    local REQUIRED_STABLE=5
    local max_wait
    max_wait=$(awk -v retry="${RETRY}" -v sleep="${SLEEP_TIME}" \
        'BEGIN { printf "%.1f", retry * sleep }')
    for ((i = 0; i < RETRY; i++)); do
        shopt -s nullglob
        files=("${RUN_LOGFILE}"*)
        shopt -u nullglob

        signature=""
        for f in "${files[@]}"; do
            [[ -f "${f}" ]] || continue
            signature+="$(stat -c '%n:%s' "${f}")"$'\n'
        done

        if [[ "${signature}" == "${previous_signature}" ]]; then
            ((stable++)) || :
            if ((stable >= REQUIRED_STABLE)); then
                return 0
            fi
        else
            stable=0
            previous_signature="${signature}"
        fi

        sleep "${SLEEP_TIME}"
    done

    echo "[INFO] sanitizer logs did not stabilize within ${max_wait} seconds" >&2
}

wait_for_valgrind_processes
wait_for_sanitizer_logs

log_has_warning() {
    local file=$1

    case "${TOOL}" in
        --memcheck | --helgrind)
            # A zero Valgrind summary means that no unsuppressed errors occurred.
            grep -Eq 'ERROR SUMMARY: [1-9][0-9]* errors' "${file}"
            ;;
        --asan)
            grep -Eq \
                'ERROR: (AddressSanitizer|LeakSanitizer)|SUMMARY: AddressSanitizer|runtime error:' \
                "${file}"
            ;;
        --tsan)
            grep -Eq 'WARNING: ThreadSanitizer|ERROR: ThreadSanitizer|data race' "${file}"
            ;;
        *)
            return 1
            ;;
    esac
}

set +x
if [ -n "${LOGFILE}" ]; then
    echo "Logfile prefix of ${TOOL}: ${RUN_LOGFILE}"
    found_log=0
    shopt -s nullglob
    log_files=("${RUN_LOGFILE}"*)
    shopt -u nullglob
    for f in "${log_files[@]}"; do
        # Valgrind may create core files such as
        # gfarm2fs.log.memcheck.20260730-123600.114094.core.116397.
        # They are not text logs and should not be dumped or reported here.
        if [[ "${f}" =~ \.core\.[0-9]+$ ]]; then
            continue
        fi
        if [ -f "${f}" ]; then
            found_log=1
            echo "----- ${f} -----"
            cat "${f}"
            echo "----- End of ${f} -----"
            if [[ -n "${REPORT_FILE:-}" ]] && log_has_warning "${f}"; then
                printf '[WARNING] %s: %s\n' "${TOOL}" "${f}" >&2
                printf '%s\t%s\n' "${TOOL}" "${f}" >>"${REPORT_FILE}"
            fi
        fi
    done
    if [ "$found_log" -eq 0 ]; then
        echo "[INFO]: No ${TOOL} errors detected (no log files generated)."
    fi
fi

printf '(%s) %s' "${result}" "$(basename "$0")"
printf ' %q' "${original_args[@]}"
printf '\n'

if [ $result = "OK" ]; then
    exit 0
else
    exit 1
fi
