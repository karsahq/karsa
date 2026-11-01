#!/bin/sh
# Downloads the NIST ACVP sigVer vectors if needed and checks them against the
# Rust backends: ML-DSA-65 (FIPS 204) and SLH-DSA-SHA2-128s (FIPS 205).
#
# Usage:
#   ./scripts/acvp-rust.sh
#   CARGO=~/.cargo/bin/cargo ./scripts/acvp-rust.sh
set -eu

CARGO=${CARGO:-cargo}
DIR=${ACVP_DIR:-testdata/acvp}
BASE="https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files"

export CARGO_INCREMENTAL=0

mkdir -p "${DIR}"

fetch() {
	if [ ! -f "$2" ]; then
		echo "+ downloading $3"
		curl -sSfL -o "$2" "$3"
	fi
}

ML_DSA="${DIR}/sigver.json"
SLH_DSA="${DIR}/slh-sigver.json"

fetch ml-dsa "${ML_DSA}" "${BASE}/ML-DSA-sigVer-FIPS204/internalProjection.json"
fetch slh-dsa "${SLH_DSA}" "${BASE}/SLH-DSA-sigVer-FIPS205/internalProjection.json"

"${CARGO}" run --release -q -p karsa -- acvp "${ML_DSA}"
echo
"${CARGO}" run --release -q -p karsa -- acvp "${SLH_DSA}"
