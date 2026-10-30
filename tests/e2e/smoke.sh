#!/usr/bin/env bash
#
# End-to-end smoke test: boot a single-node Karsa chain and verify that the app
# works as a real process, not just as genesis JSON.
#
# Checks:
#   - karsad builds, init produces a valid genesis, gentx + collect succeed
#   - the node produces blocks
#   - the EVM JSON-RPC answers
#   - the Karsa precompiles (AMM, factory, minter) are active on chain
#   - the nativetoken query service is reachable
#   - a real zero-fee bank transfer is included in a block
#
# Usage: tests/e2e/smoke.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HOME_DIR="${KARSA_E2E_HOME:-/tmp/karsa-e2e-smoke}"
BIN="${KARSA_E2E_BIN:-/tmp/karsad}"
CHAIN_ID="${KARSA_E2E_CHAIN_ID:-karsa_262144-1}"
KEYRING="test"
VAL="val"
LOG="$HOME_DIR/node.log"
RPC_URL="http://127.0.0.1:8545"

NODE_PID=""
cleanup() {
  if [[ -n "$NODE_PID" ]] && kill -0 "$NODE_PID" 2>/dev/null; then
    kill "$NODE_PID" 2>/dev/null || true
    wait "$NODE_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

step() { printf '\n== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

step "build"
( cd "$ROOT" && go build -o "$BIN" ./cmd/karsad )

step "init and validator"
rm -rf "$HOME_DIR"
"$BIN" init e2e --chain-id "$CHAIN_ID" --home "$HOME_DIR" >/dev/null

"$BIN" keys add "$VAL" --keyring-backend "$KEYRING" --home "$HOME_DIR" >/dev/null 2>&1
VAL_ADDR="$("$BIN" keys show "$VAL" -a --keyring-backend "$KEYRING" --home "$HOME_DIR")"
[[ -n "$VAL_ADDR" ]] || fail "validator address is empty"

"$BIN" genesis add-genesis-account "$VAL_ADDR" 100000000000000000000000000akra \
  --keyring-backend "$KEYRING" --home "$HOME_DIR" >/dev/null
"$BIN" genesis gentx "$VAL" 1000000000000000000000akra \
  --chain-id "$CHAIN_ID" --keyring-backend "$KEYRING" --home "$HOME_DIR" >/dev/null
"$BIN" genesis collect-gentxs --home "$HOME_DIR" >/dev/null
"$BIN" genesis validate --home "$HOME_DIR" >/dev/null
printf 'genesis valid\n'

# The EVM mempool requires CometBFT's app-side mempool; the stock config uses flood.
CONFIG_TOML="$HOME_DIR/config/config.toml"
sed -i.bak 's/^type = "flood"/type = "app"/' "$CONFIG_TOML"
grep -q '^type = "app"' "$CONFIG_TOML" || fail "could not enable the app-side mempool"

step "start node"
"$BIN" start --home "$HOME_DIR" \
  --chain-id "$CHAIN_ID" \
  --minimum-gas-prices=0akra \
  --evm.min-tip=0 \
  --json-rpc.enable=true \
  --json-rpc.api eth,txpool,personal,net,debug,web3 \
  >"$LOG" 2>&1 &
NODE_PID=$!

step "wait for the EVM JSON-RPC"
height=""
for _ in $(seq 1 60); do
  if ! kill -0 "$NODE_PID" 2>/dev/null; then
    tail -30 "$LOG" >&2
    fail "node exited during startup"
  fi
  out="$(curl -s -m 2 -X POST -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' \
    "$RPC_URL" || true)"
  if [[ "$out" == *'"result"'* ]]; then
    height="$out"
    break
  fi
  sleep 2
done
[[ -n "$height" ]] || { tail -30 "$LOG" >&2; fail "no JSON-RPC response"; }
printf 'eth_blockNumber: %s\n' "$height"

step "wait for a block"
bn="0x0"
for _ in $(seq 1 30); do
  bn="$(curl -s -m 2 -X POST -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' \
    "$RPC_URL" | sed -E 's/.*"result":"(0x[0-9a-fA-F]+)".*/\1/')"
  if [[ -n "$bn" && "$bn" != "0x0" ]]; then
    printf 'block number: %s\n' "$bn"
    break
  fi
  sleep 2
done
[[ "$bn" != "0x0" ]] || { tail -30 "$LOG" >&2; fail "no block produced"; }

step "check precompiles on chain"
evm_params="$("$BIN" q evm params --home "$HOME_DIR" -o json)"
for addr in 0900 0901 0902; do
  echo "$evm_params" | grep -qi "000000000000000000000000000000000000${addr}" \
    || fail "precompile ${addr} is not active"
done
printf 'precompiles 0900, 0901, 0902 active\n'

step "check nativetoken query"
"$BIN" q nativetoken params --home "$HOME_DIR" -o json >/dev/null
printf 'nativetoken params readable\n'

# A default fee-market base fee rejects ordinary txs at DeliverTx even though
# the broadcast returns code 0 from CheckTx. Send a real tx and wait for it to
# be indexed, then verify the balance actually moved.
step "send a zero-fee bank transaction"
RECIP="recipient"
"$BIN" keys add "$RECIP" --keyring-backend "$KEYRING" --home "$HOME_DIR" >/dev/null 2>&1
RECIP_ADDR="$("$BIN" keys show "$RECIP" -a --keyring-backend "$KEYRING" --home "$HOME_DIR")"
[[ -n "$RECIP_ADDR" ]] || fail "recipient address is empty"

send_out="$("$BIN" tx bank send "$VAL" "$RECIP_ADDR" 1000akra \
  --from "$VAL" --keyring-backend "$KEYRING" --home "$HOME_DIR" \
  --chain-id "$CHAIN_ID" \
  --gas auto --gas-adjustment 1.3 --gas-prices 0akra \
  --broadcast-mode sync -y -o json)"
TXHASH="$(printf '%s' "$send_out" | sed -nE 's/.*"txhash":"([^"]+)".*/\1/p')"
[[ -n "$TXHASH" ]] || fail "bank send returned no txhash: $send_out"

TX_JSON=""
for _ in $(seq 1 30); do
  if TX_JSON="$("$BIN" q tx "$TXHASH" --node tcp://127.0.0.1:26657 --home "$HOME_DIR" -o json 2>/dev/null)"; then
    break
  fi
  TX_JSON=""
  sleep 1
done
[[ -n "$TX_JSON" ]] || fail "bank send was not indexed: $TXHASH"
printf '%s' "$TX_JSON" | grep -q '"code":0' || fail "bank send failed: $TX_JSON"
printf 'bank send included at %s\n' "$(printf '%s' "$TX_JSON" | sed -nE 's/.*"height":"([0-9]+)".*/\1/p')"

balance="$("$BIN" q bank balances "$RECIP_ADDR" --node tcp://127.0.0.1:26657 --home "$HOME_DIR" -o json)"
printf '%s' "$balance" | grep -q '"amount": "1000"' || fail "recipient balance did not change: $balance"
printf 'recipient received 1000akra\n'

printf '\nSMOKE TEST PASSED\n'
