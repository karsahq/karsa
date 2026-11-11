#!/bin/sh
# Sends one transfer per validator account in parallel until the duration ends.
#
# Usage:
#   ./scripts/transfer-load.sh [seconds]
#
# Environment:
#   DEVNET=/tmp/karsa-devnet   home the live mesh was started from
#   BIN=target/release/karsa
#   RPC_PORT=7610              validator i answers on rpc_port + i
#   VALIDATORS=4
#   WAIT_SECONDS=8             per-transaction finality timeout
#
# Every loop is sequential per sender: it waits for the previous transaction to
# reach finality before reading the next sequence. That keeps a sender's
# sequence gap-free while still keeping all four mempools busy. The output of
# each sender goes to $DEVNET/load-$i.log; the last line of each log names the
# count and whether the last transaction finalized.
set -u

DURATION=${1:-30}
DEVNET=${DEVNET:-/tmp/karsa-devnet}
BIN=${BIN:-target/release/karsa}
RPC_PORT=${RPC_PORT:-7610}
VALIDATORS=${VALIDATORS:-4}
WAIT_SECONDS=${WAIT_SECONDS:-8}

if [ ! -x "$BIN" ]; then
    echo "no binary at $BIN" >&2
    exit 1
fi

run_sender() {
    index=$1
    to=$(( (index + 1) % VALIDATORS ))
    log="$DEVNET/load-$index.log"
    : > "$log"
    deadline=$(( $(date +%s) + DURATION ))
    sent=0
    finalized=0
    failed=0
    while [ "$(date +%s)" -lt "$deadline" ]; do
        sent=$((sent + 1))
        if "$BIN" send --home "$DEVNET" --rpc "127.0.0.1:$((RPC_PORT + index))" \
            --from "$index" --to "$to" --amount 1 --wait \
            --wait-seconds "$WAIT_SECONDS" >> "$log" 2>&1; then
            finalized=$((finalized + 1))
        else
            failed=$((failed + 1))
        fi
    done
    echo "sender $index: sent $sent, finalized $finalized, failed $failed" >> "$log"
    echo "sender $index: sent $sent, finalized $finalized, failed $failed"
}

i=0
while [ "$i" -lt "$VALIDATORS" ]; do
    run_sender "$i" &
    i=$((i + 1))
done
wait
