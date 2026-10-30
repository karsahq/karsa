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
#   - an AMM pool can be created and swapped through the CLI
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

# wait_for_tx prints the indexed tx JSON, or fails after 30 seconds. A sync
# broadcast only proves CheckTx passed; DeliverTx is what actually moves state.
wait_for_tx() {
  local hash="$1" out=""
  for _ in $(seq 1 30); do
    if out="$("$BIN" q tx "$hash" --node tcp://127.0.0.1:26657 --home "$HOME_DIR" -o json 2>/dev/null)"; then
      printf '%s' "$out"
      return 0
    fi
    sleep 1
  done
  return 1
}

step "build"
( cd "$ROOT" && go build -o "$BIN" ./cmd/karsad )

step "init and validator"
rm -rf "$HOME_DIR"
"$BIN" init e2e --chain-id "$CHAIN_ID" --home "$HOME_DIR" >/dev/null

"$BIN" keys add "$VAL" --keyring-backend "$KEYRING" --home "$HOME_DIR" >/dev/null 2>&1
VAL_ADDR="$("$BIN" keys show "$VAL" -a --keyring-backend "$KEYRING" --home "$HOME_DIR")"
[[ -n "$VAL_ADDR" ]] || fail "validator address is empty"

"$BIN" genesis add-genesis-account "$VAL_ADDR" \
  100000000000000000000000000akra,1000000000000000000000uusdc \
  --keyring-backend "$KEYRING" --home "$HOME_DIR" >/dev/null
"$BIN" genesis gentx "$VAL" 1000000000000000000000akra \
  --chain-id "$CHAIN_ID" --keyring-backend "$KEYRING" --home "$HOME_DIR" >/dev/null
"$BIN" genesis collect-gentxs --home "$HOME_DIR" >/dev/null

# Register a second, bank-backed asset for the AMM test. This is e2e-only: a
# module-owned token pair turns the denom into a dynamic ERC20 precompile, so
# the CLI can create a real KRA/uusdc pool without deploying a contract.
python3 - "$HOME_DIR/config/genesis.json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path) as f:
    genesis = json.load(f)

erc20 = genesis["app_state"]["erc20"]
pair = {
    "erc20_address": "0x1000000000000000000000000000000000000001",
    "denom": "uusdc",
    "enabled": True,
    "contract_owner": "OWNER_MODULE",
}
erc20["token_pairs"].append(pair)
erc20["dynamic_precompiles"].append(pair["erc20_address"])

# The ERC20 precompile reads name/symbol/decimals from bank metadata. Without
# it those calls revert, so Blockscout cannot display the token even though the
# precompile exists.
genesis["app_state"]["bank"]["denom_metadata"].append({
    "description": "USD Coin test asset",
    "denom_units": [
        {"denom": "uusdc", "exponent": 0, "aliases": []},
        {"denom": "usdc", "exponent": 6, "aliases": []},
    ],
    "base": "uusdc",
    "display": "usdc",
    "name": "USD Coin",
    "symbol": "USDC",
    "uri": "",
    "uri_hash": "",
})

# EVM transactions are checked against the block gas limit at admission. The
# Cosmos default of -1 (unlimited) is read as zero by the EVM mempool, so an
# ordinary EVM transfer is rejected as exceeding the block gas limit. Mirror
# the production consensus values from local_node.sh / docs/tokenomics.md.
genesis["consensus"]["params"]["block"]["max_bytes"] = "3000000"
genesis["consensus"]["params"]["block"]["max_gas"] = "100000000"

with open(path, "w") as f:
    json.dump(genesis, f, separators=(",", ":"))
PY

"$BIN" genesis validate --home "$HOME_DIR" >/dev/null
printf 'genesis valid\n'

# The EVM mempool requires CometBFT's app-side mempool; the stock config uses flood.
CONFIG_TOML="$HOME_DIR/config/config.toml"
sed -i.bak 's/^type = "flood"/type = "app"/' "$CONFIG_TOML"
grep -q '^type = "app"' "$CONFIG_TOML" || fail "could not enable the app-side mempool"

step "start node"
"$BIN" start --home "$HOME_DIR" \
  --chain-id "$CHAIN_ID" \
  --keyring-backend "$KEYRING" \
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

TX_JSON="$(wait_for_tx "$TXHASH")" || fail "bank send was not indexed: $TXHASH"
printf '%s' "$TX_JSON" | grep -q '"code":0' || fail "bank send failed: $TX_JSON"
printf 'bank send included at %s\n' "$(printf '%s' "$TX_JSON" | sed -nE 's/.*"height":"([0-9]+)".*/\1/p')"

balance="$("$BIN" q bank balances "$RECIP_ADDR" --node tcp://127.0.0.1:26657 --home "$HOME_DIR" -o json)"
printf '%s' "$balance" | grep -q '"amount": "1000"' || fail "recipient balance did not change: $balance"
printf 'recipient received 1000akra\n'

step "create an AMM pool"
KRA_ASSET="0xd9171c1192d82ecd4f71dec2ee0264769af9531e"
USDC_ASSET="0x1000000000000000000000000000000000000001"
create_out="$("$BIN" tx amm create-pool \
  --asset-a "$KRA_ASSET" --asset-b "$USDC_ASSET" \
  --fee-bps 30 \
  --amount-a 1000000000000000000000 --amount-b 1000000000000000000000 \
  --from "$VAL" --keyring-backend "$KEYRING" --home "$HOME_DIR" \
  --chain-id "$CHAIN_ID" --gas auto --gas-adjustment 1.3 --gas-prices 0akra \
  --broadcast-mode sync -y -o json)"
TXHASH="$(printf '%s' "$create_out" | sed -nE 's/.*"txhash":"([^"]+)".*/\1/p')"
[[ -n "$TXHASH" ]] || fail "create-pool returned no txhash: $create_out"
TX_JSON="$(wait_for_tx "$TXHASH")" || fail "create-pool was not indexed: $TXHASH"
printf '%s' "$TX_JSON" | grep -q '"code":0' || fail "create-pool failed: $TX_JSON"
printf 'pool created\n'

POOL_JSON="$("$BIN" q amm pool --pool-id 1 --node tcp://127.0.0.1:26657 --home "$HOME_DIR" -o json)"
printf '%s' "$POOL_JSON" | grep -q '"id": "1"' || fail "pool 1 not found: $POOL_JSON"
RESERVES_BEFORE="$(printf '%s' "$POOL_JSON" | python3 -c 'import json,sys; p=json.load(sys.stdin)["pool"]; assert not p.get("status") or p["status"] == "POOL_STATUS_ACTIVE"; print(p["reserve_a"], p["reserve_b"])')"
printf 'pool 1 active, reserves: %s\n' "$RESERVES_BEFORE"

step "swap in the AMM pool"
swap_out="$("$BIN" tx amm swap-exact-in \
  --path "$KRA_ASSET,$USDC_ASSET" \
  --amount-in 1000000000000000000 --min-out 1 \
  --from "$VAL" --keyring-backend "$KEYRING" --home "$HOME_DIR" \
  --chain-id "$CHAIN_ID" --gas auto --gas-adjustment 1.3 --gas-prices 0akra \
  --broadcast-mode sync -y -o json)"
TXHASH="$(printf '%s' "$swap_out" | sed -nE 's/.*"txhash":"([^"]+)".*/\1/p')"
[[ -n "$TXHASH" ]] || fail "swap-exact-in returned no txhash: $swap_out"
TX_JSON="$(wait_for_tx "$TXHASH")" || fail "swap-exact-in was not indexed: $TXHASH"
printf '%s' "$TX_JSON" | grep -q '"code":0' || fail "swap-exact-in failed: $TX_JSON"

POOL_JSON="$("$BIN" q amm pool --pool-id 1 --node tcp://127.0.0.1:26657 --home "$HOME_DIR" -o json)"
RESERVES_AFTER="$(printf '%s' "$POOL_JSON" | python3 -c 'import json,sys; p=json.load(sys.stdin)["pool"]; print(p["reserve_a"], p["reserve_b"])')"
[[ "$RESERVES_AFTER" != "$RESERVES_BEFORE" ]] || fail "swap did not move the reserves"
printf 'swap moved reserves: %s -> %s\n' "$RESERVES_BEFORE" "$RESERVES_AFTER"

# Blockscout discovers ERC20 tokens through eth_getCode and eth_call, and
# follows balances through Transfer logs. Exercise that exact surface against
# the dynamic precompile so an explorer regression is caught here.
step "check the explorer RPC surface"
rpc() {
  local timeout="${2:-5}"
  curl -s -m "$timeout" -X POST -H 'Content-Type: application/json' -d "$1" "$RPC_URL"
}
VAL_EVM="$("$BIN" debug addr "$VAL_ADDR" --home "$HOME_DIR" | sed -nE 's/.*Address hex: (0x[0-9a-fA-F]+).*/\1/p')"
RECIP_EVM="$("$BIN" debug addr "$RECIP_ADDR" --home "$HOME_DIR" | sed -nE 's/.*Address hex: (0x[0-9a-fA-F]+).*/\1/p')"
[[ -n "$VAL_EVM" && -n "$RECIP_EVM" ]] || fail "could not derive EVM addresses"

code_json="$(rpc "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getCode\",\"params\":[\"$USDC_ASSET\",\"latest\"]}")"
printf '%s' "$code_json" | grep -q '"result":"0x[0-9a-fA-F]' || fail "precompile has no code: $code_json"

call_json() {
  rpc "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_call\",\"params\":[{\"to\":\"$USDC_ASSET\",\"data\":\"$1\"},\"latest\"]}"
}
for selector in 0x06fdde03 0x95d89b41 0x313ce567 0x18160ddd; do
  out="$(call_json "$selector")"
  printf '%s' "$out" | grep -q '"result":"0x' || fail "ERC20 metadata call $selector failed: $out"
done
decimals_hex="$(call_json 0x313ce567 | sed -nE 's/.*"result":"0x0*([0-9a-fA-F]+)".*/\1/p')"
[[ "$decimals_hex" == "6" ]] || fail "decimals is not 6: $decimals_hex"
printf 'precompile exposes ERC20 metadata (decimals=%s)\n' "$decimals_hex"

balance_before="$(call_json "0x70a08231000000000000000000000000${RECIP_EVM:2}")"
printf '%s' "$balance_before" | grep -q '"result":"0x' || fail "balanceOf failed: $balance_before"

block_before="$(rpc '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' | sed -nE 's/.*"result":"(0x[0-9a-fA-F]+)".*/\1/p')"
transfer_data="0xa9059cbb000000000000000000000000${RECIP_EVM:2}00000000000000000000000000000000000000000000000000000000000003e8"
send_json="$(rpc "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_sendTransaction\",\"params\":[{\"from\":\"$VAL_EVM\",\"to\":\"$USDC_ASSET\",\"gas\":\"0x100000\",\"gasPrice\":\"0x0\",\"data\":\"$transfer_data\"}]}")"
EVM_HASH="$(printf '%s' "$send_json" | sed -nE 's/.*"result":"(0x[0-9a-fA-F]+)".*/\1/p')"
[[ -n "$EVM_HASH" ]] || fail "eth_sendTransaction failed: $send_json"
printf 'EVM tx submitted: %s\n' "$EVM_HASH"

# eth_getTransactionReceipt retries internally for ~50s when the tx is not yet
# indexed. Wait for the tx to be included first; otherwise every short client
# timeout leaves a retry loop running server-side and the test appears stuck.
for _ in $(seq 1 20); do
  block_now="$(rpc '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' | sed -nE 's/.*"result":"(0x[0-9a-fA-F]+)".*/\1/p')"
  if [[ -n "$block_now" && -n "$block_before" ]] && (( block_now >= block_before + 2 )); then break; fi
  sleep 1
done
receipt_json="$(rpc "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getTransactionReceipt\",\"params\":[\"$EVM_HASH\"]}" 60)"
printf '%s' "$receipt_json" | grep -q '"status":"0x1"' || fail "EVM transfer receipt missing or failed: $receipt_json"
printf 'EVM receipt confirmed\n'

logs_json="$(rpc "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getLogs\",\"params\":[{\"address\":\"$USDC_ASSET\",\"fromBlock\":\"0x0\",\"toBlock\":\"latest\",\"topics\":[\"0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef\"]}]}")"
printf '%s' "$logs_json" | grep -q '"result":\[{.*ddf252ad' || fail "Transfer log missing: $logs_json"
printf 'Transfer log indexed\n'

balance_after="$(call_json "0x70a08231000000000000000000000000${RECIP_EVM:2}")"
[[ "$balance_after" != "$balance_before" ]] || fail "ERC20 balance did not change"
printf 'explorer RPC surface: code, metadata, receipt, Transfer log, balance OK\n'

printf '\nSMOKE TEST PASSED\n'
