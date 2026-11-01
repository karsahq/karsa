#!/bin/sh
# Builds the Karsa CLI, starts the demo node, sends signed transactions over
# keep-alive TCP connections, and reports accepted transactions per second.
#
# Usage: ./scripts/loadtest-rust.sh [count] [concurrency]
set -eu

CARGO=${CARGO:-cargo}
COUNT=${1:-20000}
CONCURRENCY=${2:-16}
export CARGO_INCREMENTAL=0

BIN=target/release/karsa
LOG=/tmp/karsa_rust_node.log

echo "+ building the karsa CLI"
"${CARGO}" build --release -q -p karsa

echo "+ starting node on 127.0.0.1:8099"
"${BIN}" node >"${LOG}" 2>&1 &
NODE_PID=$!
sleep 1

"${BIN}" loadtest "${COUNT}" "${CONCURRENCY}"

kill "${NODE_PID}" 2>/dev/null || true
wait "${NODE_PID}" 2>/dev/null || true
