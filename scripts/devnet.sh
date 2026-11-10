#!/bin/sh
# Brings up a four-validator devnet, one process per validator, from a real home.
#
# Usage:
#   ./scripts/devnet.sh [lifetime-seconds]
#
# Environment:
#   DEVNET=/tmp/karsa-devnet   home directory and parent of the stores
#   PORT_BASE=7600             consensus base; node i uses port_base + i
#   RPC_PORT=7610              HTTP base; node i uses rpc_port + i
#   SNAPSHOT_PORT=7620         snapshot base; node i uses snapshot_port + i
#   BIN=target/release/karsa
#   RESET=1                    wipe the devnet directory first
#
# The genesis is the four-validator example `karsa genesis --init` writes; its
# keys are the demo keys and are public knowledge. peers.json is written for the
# operator and for commands that read it — the live mesh itself still derives its
# endpoints from PORT_BASE, because that flag is what the transport takes today.
#
# Requires jq to read the validator addresses out of genesis.json.
#
# This is a devnet, not a deployment: every process runs on loopback under one
# user, and the chain id comes from the generated genesis rather than the demo
# hash, which is enough to exercise joins, restarts, and snapshot resync.
set -eu

LIFETIME=${1:-3600}
DEVNET=${DEVNET:-/tmp/karsa-devnet}
PORT_BASE=${PORT_BASE:-7600}
RPC_PORT=${RPC_PORT:-7610}
SNAPSHOT_PORT=${SNAPSHOT_PORT:-7620}
CHECKPOINT_EVERY=${CHECKPOINT_EVERY:-1024}
BIN=${BIN:-target/release/karsa}
VALIDATORS=4

if [ "${RESET:-0}" = 1 ]; then
    rm -rf "$DEVNET"
fi
mkdir -p "$DEVNET"

if [ ! -f "$DEVNET/genesis.json" ]; then
    "$BIN" genesis --home "$DEVNET" --init > /dev/null
fi

i=0
for address in $(jq -r '.validators[].address' "$DEVNET/genesis.json"); do
    "$BIN" peers --home "$DEVNET" --add "$address@127.0.0.1:$((PORT_BASE + i))" > /dev/null
    i=$((i + 1))
done

pids=""
stop() {
    if [ -n "$pids" ]; then
        kill $pids 2>/dev/null || true
    fi
    wait
}
trap stop INT TERM

i=0
while [ "$i" -lt "$VALIDATORS" ]; do
    "$BIN" live \
        --validators "$VALIDATORS" \
        --node-index "$i" \
        --port-base "$PORT_BASE" \
        --rpc-port "$RPC_PORT" \
        --snapshot-port "$SNAPSHOT_PORT" \
        --execute \
        --txs 0 \
        --timeout-seconds "$LIFETIME" \
        --checkpoint-every "$CHECKPOINT_EVERY" \
        --home "$DEVNET" \
        --store "$DEVNET/data" \
        > "$DEVNET/val-$i.log" 2>&1 &
    pids="$pids $!"
    i=$((i + 1))
done

echo "== devnet: $VALIDATORS validators, lifetime ${LIFETIME}s =="
echo "  home      $DEVNET"
echo "  p2p       $PORT_BASE..$((PORT_BASE + VALIDATORS - 1))"
echo "  rpc       http://127.0.0.1:$RPC_PORT..$((RPC_PORT + VALIDATORS - 1))"
echo "  snapshot  $SNAPSHOT_PORT..$((SNAPSHOT_PORT + VALIDATORS - 1))"
echo "  checkpoint every $CHECKPOINT_EVERY certified heights (0 disables)"
echo "  send      $BIN send --home $DEVNET --rpc 127.0.0.1:$RPC_PORT --from 0 --to 1 --amount 1 --wait"
echo "  logs      $DEVNET/val-*.log"

wait
