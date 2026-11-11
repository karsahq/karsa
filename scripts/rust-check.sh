#!/bin/sh
# Validation gate for the Rust workspace.
#
# Usage:
#   ./scripts/rust-check.sh
#   CARGO=~/.cargo/bin/cargo ./scripts/rust-check.sh   # cargo not on PATH
set -eu

CARGO=${CARGO:-cargo}

# sccache cannot reuse incremental artifacts, so keep incremental off.
export CARGO_INCREMENTAL=0

# The mesh tests start four real processes and the finality harness has
# wall-clock windows. On a four-core machine, running those tests in parallel
# makes scheduler gaps look like consensus stalls, so the gate serializes them.
export RUST_TEST_THREADS=1

echo "+ ${CARGO} fmt --all --check"
"${CARGO}" fmt --all --check

echo "+ ${CARGO} clippy --all-targets --all-features -- -D warnings"
"${CARGO}" clippy --all-targets --all-features -- -D warnings

echo "+ ${CARGO} test"
"${CARGO}" test

echo "+ ${CARGO} test --all-features"
"${CARGO}" test --all-features

echo "all gates passed"
