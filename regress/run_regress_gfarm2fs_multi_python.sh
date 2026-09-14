#!/bin/bash
set -eu -o pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

REGRESS_ARGS=("$@")
DEBUG=${DEBUG:-}

# Run regress_gfarm2fs.py under two Python versions using pyenv.
# The script installs pyenv under ~/.local/pyenv if needed, then runs
# regress_gfarm2fs.py with Python 3.6 and 3.14.

TARGET_VERSIONS="
3.6.15
3.14.5
"

TESTDIR="${HOME}/regress-gfarm2fs-pyenv"
REGRESS_PY="${REGRESS_PY:-$script_dir/regress_gfarm2fs.py}"

print_func_name() {
    echo "*** $1 ***"
}

confirm_package_install() {
    local package_manager=$1
    shift

    echo "The following packages will be installed with sudo ${package_manager}:"
    printf '  - %s\n' "$@"
    if ! read -r -p "Install these packages? [y/N] " answer; then
        echo "Package installation cancelled (no response)."
        return 1
    fi
    case "${answer}" in
        [yY] | [yY][eE][sS])
            return 0
            ;;
        *)
            echo "Package installation cancelled."
            return 1
            ;;
    esac
}

install_packages_for_debian() {
    local packages=(
        build-essential
        zlib1g-dev libbz2-dev libffi-dev libreadline-dev
        liblzma-dev libncurses-dev libsqlite3-dev libssl-dev
        tk-dev xz-utils
    )

    print_func_name "install_packages_for_debian"
    confirm_package_install "apt install -y" "${packages[@]}"
    sudo apt install -y "${packages[@]}"
}

install_packages_for_rhel() {
    local packages=(
        libffi-devel gcc gcc-c++ zlib zlib-devel
        readline-devel bzip2-devel ncurses-devel
        sqlite-devel xz-devel tk-devel
    )

    print_func_name "install_packages_for_rhel"
    confirm_package_install "dnf install -y" "${packages[@]}"
    sudo dnf install -y "${packages[@]}"
}

install_packages() {
    # shellcheck disable=SC1091
    . /etc/os-release
    for id in ${ID_LIKE:-${ID}}; do
        case "$id" in
            debian)
                install_packages_for_debian
                return 0
                ;;
            rhel | fedora)
                install_packages_for_rhel
                return 0
                ;;
        esac
    done
}

install_pyenv() {
    print_func_name "install_pyenv"
    if [ -e ~/.local/pyenv ]; then
        echo "pyenv is already installed."
        return 0
    fi

    mkdir -p ~/.local ~/env
    git clone https://github.com/pyenv/pyenv.git ~/.local/pyenv
    cat <<EOF >~/env/pyenv.sh
export PYENV_ROOT="${HOME}/.local/pyenv"
export PATH="\${PYENV_ROOT}/bin:${PATH}"
eval "\$(pyenv init -)"
EOF
}

prepare_envs() {
    print_func_name "prepare_envs"
    mkdir -p "${TESTDIR}"
    ABS_PATH=$(pwd)

    for ver in ${TARGET_VERSIONS}; do
        if [[ "${ver}" =~ ^# ]]; then
            continue
        fi

        cd "${ABS_PATH}"
        mkdir -p "${TESTDIR}/${ver}"
        cd "${TESTDIR}/${ver}"
        pyenv install --skip-existing "${ver}"
    done
}

run_python_test() {
    if [ -n "${DEBUG}" ]; then
        python3 "${REGRESS_PY}" "${REGRESS_ARGS[@]}"
    else
        python3 "${REGRESS_PY}" "${REGRESS_ARGS[@]}" >/dev/null 2>&1
    fi
}

run_tests() {
    print_func_name "run_tests"
    for ver in ${TARGET_VERSIONS}; do
        if [[ "${ver}" =~ ^# ]]; then
            continue
        fi

        cd "${TESTDIR}/${ver}"
        pyenv local "${ver}"

        VER_REAL=$(python3 --version)
        echo -n "Running regress_gfarm2fs.py on ${VER_REAL} ... "
        start=$(($(date +%s%N) / 1000000))
        # echo "Run: python3" "${REGRESS_PY}" "${REGRESS_ARGS[@]}"
        if run_python_test; then
            end=$(($(date +%s%N) / 1000000))
            diff=$((end - start))
            diff_sec=$(printf "%d.%03d" $((diff / 1000)) $((diff % 1000)))
            echo "PASS (${diff_sec} sec.)"
        else
            echo "FAIL"
            return 1
        fi
    done
}

print_uninstall_guide() {
    print_func_name "print_uninstall_guide"
    cat <<EOF
Please delete the following directories:
  - ${HOME}/.local/pyenv
  - ${HOME}/env/pyenv.sh
  - ${TESTDIR}
EOF
}

install_packages
install_pyenv
# shellcheck source=/dev/null
. ~/env/pyenv.sh
prepare_envs
run_tests
print_uninstall_guide
