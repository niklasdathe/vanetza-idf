#!/usr/bin/env bash
set -euo pipefail

# Build/cache the exact TITAN + ETSI TS.ITS inputs used by the GitHub Actions
# regression campaign. The caller is responsible for installing OS packages.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=versions.env
source "${SCRIPT_DIR}/versions.env"

CACHE_ROOT="${1:-${HOME}/.cache/vanetza-ttcn}"
TITAN_ROOT="${CACHE_ROOT}/titan-${TITAN_REF}"
ETSI_ROOT="${CACHE_ROOT}/TS.ITS-${ETSI_TS_ITS_COMMIT}"
mkdir -p "${CACHE_ROOT}"

build_titan() {
    if [[ -x "${TITAN_ROOT}/Install/bin/ttcn3_start" ]]; then
        echo "TITAN ${TITAN_REF}: cache hit"
        return
    fi

    echo "Building TITAN ${TITAN_REF}"
    rm -rf "${TITAN_ROOT}"
    git clone --depth 1 --branch "${TITAN_REF}" \
        https://gitlab.eclipse.org/eclipse/titan/titan.core.git "${TITAN_ROOT}"

    cat > "${TITAN_ROOT}/Makefile.personal" <<EOF
TTCN3_DIR := ${TITAN_ROOT}/Install
EOF

    (
        cd "${TITAN_ROOT}"
        export TTCN3_DIR="${TITAN_ROOT}/Install"
        make -j2
        make install
    )

    test -x "${TITAN_ROOT}/Install/bin/ttcn3_start"
}

checkout_etsi() {
    if [[ -d "${ETSI_ROOT}/.git" ]] && \
       [[ "$(git -C "${ETSI_ROOT}" rev-parse HEAD)" == "${ETSI_TS_ITS_COMMIT}" ]]; then
        echo "ETSI TS.ITS ${ETSI_TS_ITS_COMMIT}: cache hit"
        return
    fi

    echo "Checking out ETSI TS.ITS ${ETSI_TS_ITS_COMMIT}"
    rm -rf "${ETSI_ROOT}"
    git init "${ETSI_ROOT}"
    git -C "${ETSI_ROOT}" remote add origin https://forge.etsi.org/gitlab/ITS/TS.ITS.git
    git -C "${ETSI_ROOT}" fetch --depth 1 origin "${ETSI_TS_ITS_COMMIT}"
    git -C "${ETSI_ROOT}" checkout --detach FETCH_HEAD
    git -C "${ETSI_ROOT}" submodule update --init --recursive --depth 1
}

build_etsi_suites() {
    export TTCN3_DIR="${TITAN_ROOT}/Install"
    export PATH="${TTCN3_DIR}/bin:${PATH}"
    export LD_LIBRARY_PATH="${TTCN3_DIR}/lib:${LD_LIBRARY_PATH:-}"
    export GEN_DIR="${ETSI_ROOT}"

    # The ETSI root Makefile produces build/<ATS> and its ASN.1 static library.
    # Build only the suites for which this repository has a real SUT adapter.
    for ats in AtsBTP AtsGeoNetworking AtsSecurity; do
        local sentinel
        case "${ats}" in
            AtsBTP) sentinel="${ETSI_ROOT}/build/AtsBTP/ItsBtp_TestCases.o" ;;
            AtsGeoNetworking) sentinel="${ETSI_ROOT}/build/AtsGeoNetworking/ItsGeoNetworking_TestCases.o" ;;
            AtsSecurity) sentinel="${ETSI_ROOT}/build/AtsSecurity/ItsSecurity_TestCases.o" ;;
        esac
        if [[ -f "${sentinel}" ]]; then
            echo "${ats}: cache hit"
            continue
        fi
        echo "Building official ETSI ${ats}"
        (
            cd "${ETSI_ROOT}"
            ATS="${ats}" make -j2
        )
        test -f "${sentinel}"
    done
}

write_manifest() {
    export TTCN3_DIR="${TITAN_ROOT}/Install"
    export PATH="${TTCN3_DIR}/bin:${PATH}"
    {
        echo "titan_ref=${TITAN_REF}"
        echo "etsi_ts_its_commit=$(git -C "${ETSI_ROOT}" rev-parse HEAD)"
        echo "etsi_submodules:"
        git -C "${ETSI_ROOT}" submodule status --recursive
        echo "titan_version:"
        "${TTCN3_DIR}/bin/compiler" -v || true
    } > "${CACHE_ROOT}/toolchain-manifest.txt" 2>&1
}

build_titan
checkout_etsi
build_etsi_suites
write_manifest

cat <<EOF
TTCN3_DIR=${TITAN_ROOT}/Install
ETSI_TS_ITS_DIR=${ETSI_ROOT}
TOOLCHAIN_MANIFEST=${CACHE_ROOT}/toolchain-manifest.txt
EOF
