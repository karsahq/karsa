#!/usr/bin/env bash
# Measures end-to-end transaction throughput against a local Karsa node: it
# derives accounts from a seed, funds them at genesis, signs EVM transfers
# offline, broadcasts them, and reports the blocks used and the achieved TPS.
# Timings depend on the host, so treat the numbers as a local reference.
#
# Usage: TPS_ACCOUNTS=32 TPS_PER_ACCOUNT=500 tests/e2e/tps.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${KARSA_E2E_BIN:-/tmp/karsad-tps}"
HOME_DIR="${KARSA_TPS_HOME:-/tmp/karsa-tps}"
LOADGEN="$ROOT/tests/e2e/loadgen.go"
KEYRING=test
ACCOUNTS="${TPS_ACCOUNTS:-32}"
PER_ACCOUNT="${TPS_PER_ACCOUNT:-200}"
RPC=26691
P2P=26690
GRPC=9101
JSONRPC=18591
PID=""

cleanup() {
  [[ -n "$PID" ]] && kill "$PID" 2>/dev/null || true
  [[ -n "$PID" ]] && wait "$PID" 2>/dev/null || true
}
trap cleanup EXIT

( cd "$ROOT" && go build -o "$BIN" ./cmd/karsad )
rm -rf "$HOME_DIR"
"$BIN" init tps --chain-id karsa_262144-1 --home "$HOME_DIR" >/dev/null 2>&1
"$BIN" keys add val --keyring-backend "$KEYRING" --algo eth_secp256k1 --home "$HOME_DIR" >/dev/null 2>&1
VAL_ADDR="$("$BIN" keys show val -a --keyring-backend "$KEYRING" --home "$HOME_DIR")"
"$BIN" genesis add-genesis-account "$VAL_ADDR" 100000000000000000000000000akra \
  --keyring-backend "$KEYRING" --home "$HOME_DIR" >/dev/null

( cd "$ROOT" && go run "$LOADGEN" -mode info -accounts "$ACCOUNTS" > /tmp/tps-accounts.json )
python3 - /tmp/tps-accounts.json > /tmp/tps-addresses.txt <<'PY'
import json
import sys

for entry in json.load(open(sys.argv[1])):
    print(entry["bech32"])
PY
while read -r addr; do
  "$BIN" genesis add-genesis-account "$addr" 1000000000000000000000akra \
    --keyring-backend "$KEYRING" --home "$HOME_DIR" >/dev/null
done < /tmp/tps-addresses.txt

"$BIN" genesis gentx val 1000000000000000000000akra --gas-prices 20000000000akra \
  --chain-id karsa_262144-1 --keyring-backend "$KEYRING" --home "$HOME_DIR" >/dev/null
"$BIN" genesis collect-gentxs --home "$HOME_DIR" >/dev/null

# The EVM mempool is app-side. Widen its queues so a burst measures block
# production instead of the default 16 executable and 1024 queued slots.
sed -i.bak 's/^type = "flood"/type = "app"/' "$HOME_DIR/config/config.toml"
sed -i.bak 's/^timeout_commit = "5s"/timeout_commit = "3s"/' "$HOME_DIR/config/config.toml"
grep -q '^timeout_commit = "3s"' "$HOME_DIR/config/config.toml" || { echo "commit timeout not set"; exit 1; }
sed -i 's/^account-slots = 16$/account-slots = 512/; s/^global-slots = 5120$/global-slots = 40960/; s/^account-queue = 64$/account-queue = 512/; s/^global-queue = 1024$/global-queue = 40960/; s/^included-nonce-cache-size = 4096$/included-nonce-cache-size = 40960/' "$HOME_DIR/config/app.toml"

python3 - "$HOME_DIR/config/genesis.json" <<'PY'
import json
import sys

genesis = json.load(open(sys.argv[1]))
print("block limits:", genesis["consensus"]["params"]["block"])
print("blocks_per_year:", genesis["app_state"]["mint"]["params"]["blocks_per_year"])
PY

"$BIN" start --home "$HOME_DIR" --chain-id karsa_262144-1 --keyring-backend "$KEYRING" \
  --minimum-gas-prices=20000000000akra --evm.min-tip=20000000000 --json-rpc.enable=true \
  --json-rpc.address "127.0.0.1:$JSONRPC" --json-rpc.ws-address "127.0.0.1:$((JSONRPC + 1))" \
  --json-rpc.api eth,txpool,personal,net,debug,web3 \
  --rpc.laddr "tcp://127.0.0.1:$RPC" --p2p.laddr "tcp://127.0.0.1:$P2P" \
  --grpc.address "127.0.0.1:$GRPC" >"$HOME_DIR/node.log" 2>&1 &
PID=$!

for _ in $(seq 1 90); do
  out="$(curl -s -m 2 "http://127.0.0.1:$RPC/status" || true)"
  if [[ "$out" == *'"latest_block_height"'* && "$out" != *'"latest_block_height":"0"'* ]]; then break; fi
  sleep 1
done
echo "node ready with 3s blocks"

cd "$ROOT"
go run "$LOADGEN" -mode run -accounts "$ACCOUNTS" -per-account "$PER_ACCOUNT" \
  -rpc "http://127.0.0.1:$JSONRPC" -chain-id 262144 -gas-price 100000000000

sleep 4
python3 - "$RPC" <<'PY'
import json
import sys
import urllib.request

rpc = "http://127.0.0.1:" + sys.argv[1]
head = int(json.load(urllib.request.urlopen(rpc + "/status"))["result"]["sync_info"]["latest_block_height"])
counts = []
for height in range(max(1, head - 30), head + 1):
    block = json.load(urllib.request.urlopen(f"{rpc}/block?height={height}"))["result"]["block"]
    counts.append(len(block["data"]["txs"] or []))
print("txs per block:", counts)
print("max per block:", max(counts))
PY
