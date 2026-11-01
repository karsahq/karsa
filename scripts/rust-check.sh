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

echo "+ ${CARGO} fmt --all --check"
"${CARGO}" fmt --all --check

echo "+ ${CARGO} clippy --all-targets --all-features -- -D warnings"
"${CARGO}" clippy --all-targets --all-features -- -D warnings

echo "+ ${CARGO} test"
"${CARGO}" test

echo "+ ${CARGO} test --all-features"
"${CARGO}" test --all-features

echo "all gates passed"
