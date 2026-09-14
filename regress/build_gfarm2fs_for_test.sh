#!/bin/sh
set -eu
set -x

script_name=$(basename "$0")
script_dir=$(cd "$(dirname "$0")" && pwd)
repo_root=$(cd "$script_dir/.." && pwd)

ARCH_GUESS=${ARCH_GUESS:-"$repo_root/../gftool/config-gfarm/gfarm.arch.guess"}
if [ ! -f "$ARCH_GUESS" ]; then
    ARCH_GUESS="gfarm.arch.guess"
fi

BUILD_BASE_DIR=${BUILD_BASE_DIR:-"$script_dir/build"}
BUILD_KIND=
DO_CLEAN=0  # 1: cleanup only
BUILD_ONLY=${BUILD_ONLY:-1}
MAKE_JOBS=${MAKE_JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)}
CONFIGURE_ARGS=${CONFIGURE_ARGS:-"--with-gfarm=/usr/local"}

usage() {
    cat <<EOF
Usage:
  ${script_name} [asan|tsan] [clean]

Environment:
  BUILD_BASE_DIR  base directory for test builds (default: regress/build)
  BUILD_DIR       build directory override
  CONFIGURE_ARGS  configure arguments override (default: --with-gfarm=/usr/local)
  BUILD_ONLY   kept for compatibility; build only when non-empty (default: 1)
  MAKE_JOBS    number of parallel jobs for make (default: online CPUs)
EOF
}

#optflags=-Werror
optflags=
while [ $# -gt 0 ]; do
    case "$1" in
        asan)
            BUILD_KIND=-asan
            optflags='-g -Og -Wall -fsanitize=address,undefined -fsanitize-recover=all -fno-omit-frame-pointer -fno-common'
            ;;
        tsan)
            BUILD_KIND=-tsan
            optflags='-g -Og -Wall -fsanitize=thread -fsanitize-recover=all -fno-omit-frame-pointer -fno-common'
            ;;
        clean)
            DO_CLEAN=1
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
    shift
done

if [ -z "${BUILD_DIR:-}" ]; then
    BUILD_DIR="$BUILD_BASE_DIR/$("$ARCH_GUESS")$BUILD_KIND"
fi

# distclean
rm -rf "$BUILD_DIR"
if [ "$DO_CLEAN" -eq 1 ]; then
    exit 0
fi

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

if [ ! -f config.status ]; then
    if CFLAGS="${CFLAGS:-}${CFLAGS:+ }${optflags}" \
       LDFLAGS="${LDFLAGS:-}${LDFLAGS:+ }${optflags}" \
          "$repo_root/configure" $CONFIGURE_ARGS >&2; then
        :
    else
        echo "----- config.log -----" >&2
        cat config.log >&2
        exit 1
    fi
fi

make -j "$MAKE_JOBS" > /dev/null

printf '%s\n' "$BUILD_DIR"
