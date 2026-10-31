# Karsa — Kernel for Assets, Runtime, Settlement & Apps

**KARSA** stands for **K**ernel for **A**ssets, **R**untime, **S**ettlement & **A**pps.

Karsa is a Cosmos EVM chain for on-chain assets, an AMM, native
ERC20-compatible tokens, and IBC v2. It is built on Cosmos SDK and
[`cosmos/evm`](https://github.com/cosmos/evm). The repository started from the
Cosmos EVM example chain, but the chain now has its own genesis, modules, and
production-oriented defaults.

Karsa is **IBC v2 only**. Channel-based ICS20 v1 transfers are deliberately not
registered.

## Documentation

- [`docs/ibc.md`](docs/ibc.md) — IBC v2 wiring and relayer
- [`docs/amm-design.md`](docs/amm-design.md) — AMM design
- [`docs/native-token.md`](docs/native-token.md) — native ERC20 tokens
- [`docs/precompiles.md`](docs/precompiles.md) — static and dynamic precompiles
- [`docs/tokenomics.md`](docs/tokenomics.md) — supply, inflation, and fees
- [`karsahq/ibc-ferry`](https://github.com/karsahq/ibc-ferry) — Go IBC v2 relayer

## Config

By default, the chain has the following configuration:

| Option              | Value                  |
|---------------------|------------------------|
| Binary              | `karsad`               |
| Chain ID            | `karsa_262144-1`       |
| Custom Opcodes      | -                      |
| Default Token Pairs | 1 for the native token |
| Denomination        | `akra` (display `kra`, symbol `KRA`) |
| EVM permissioning   | permissionless         |
| Static Precompiles  | SDK defaults + AMM + native token factory/minter |

## Running The Chain

To run a local Karsa node, execute the local node script:

```bash
./local_node.sh [FLAGS]
```

Available flags are:

- `-y`: Overwrite previous database
- `-n`: Do **not** overwrite previous database
- `--no-install`: Skip building the binary
- `--remote-debugging`: Build a binary suitable for remote debugging
- `--additional-users N`: Create N extra funded dev accounts
- `--mnemonic-file PATH`: Write generated mnemonics to a YAML file
- `--mnemonics-input PATH`: Use dev mnemonics from a YAML file

## Build and Test

```bash
gofmt -l .
go build ./...
go test ./
go test -tags=test ./config/... ./x/amm/... ./x/nativetoken/... ./tests/ibc
tests/e2e/smoke.sh
```

## Connect to Wallet

For a local node, add a custom network in MetaMask:

1. Import the local dev mnemonic if you need a funded account:
   `gesture inject test cycle original hollow east ridge hen combine junk child
   bacon zero hope comfort vacuum milk pitch cage oppose unhappy lunar seat`
2. Add a network with RPC URL `http://localhost:8545`.
3. Use chain ID `262144`, symbol `KRA`, and 18 decimals.

The local node script prints the full set of accounts and mnemonics it funds.

## Modules

Karsa runs the following modules:

### Cosmos SDK

- `auth`
- `authz`
- `bank`
- `consensus`
- `distribution`
- `evidence`
- `feegrant`
- `genutil`
- `gov`
- `mint`
- `slashing`
- `staking`
- `upgrade`
- `vesting`

### IBC

- `ibc` (core clients)
- `07-tendermint`
- `transfer` (IBC v2 only)

### Cosmos EVM

- `vm` (EVM)
- `feemarket`
- `erc20`

### Karsa

- `amm` — constant-product and stableswap pools
- `nativetoken` — ERC20-compatible bank tokens without a deployed contract

The v1 IBC port router is empty. It is kept that way on purpose so a
channel-based handshake fails instead of silently falling back to v1.
