#!/bin/sh
# Downloads the NIST ACVP ML-DSA sigVer vectors if needed and checks them
# against the Rust backend.
#
# Usage:
#   ./scripts/acvp-rust.sh
#   CARGO=~/.cargo/bin/cargo ./scripts/acvp-rust.sh
set -eu

CARGO=${CARGO:-cargo}
DIR=${ACVP_DIR:-testdata/acvp}
FILE=${DIR}/sigver.json
URL="https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json"

export CARGO_INCREMENTAL=0

mkdir -p "${DIR}"
if [ ! -f "${FILE}" ]; then
	echo "+ downloading ${URL}"
	curl -sSfL -o "${FILE}" "${URL}"
fi

"${CARGO}" run --release -q -p karsa -- acvp "${FILE}"
