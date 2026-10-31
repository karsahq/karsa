# Karsa Precompiles

Karsa has two kinds of precompiles with different lifecycles.

| | **Static** | **Dynamic** |
|---|---|---|
| Count | fixed, currently 13 | one per asset |
| Address | protocol constant (`0x…0100`–`0x…09ff`) | derived from denom/address |
| Registered | genesis or `evm.params.active_static_precompiles` | at runtime via `x/erc20.EnableDynamicPrecompile` |
| Changed by | governance (`MsgUpdateParams` to `x/vm`) | the module that owns the asset |
| Examples | Bank, AMM, Staking | LP token, IBC voucher, native token `n:0x…` |

## 1. Active static precompiles

Default genesis takes `evmtypes.AvailableStaticPrecompiles` and adds three Karsa
precompiles: AMM, token factory, and token minter (`genesis.go`).

| Address | Name | Type | Function |
|---|---|---|---|
| `0x…0100` | P256 | stateless | secp256r1 signature verification |
| `0x…0400` | Bech32 | stateless | hex ↔ bech32 address conversion |
| `0x…0800` | Staking | module | staking operations |
| `0x…0801` | Distribution | module | rewards and distribution |
| `0x…0802` | ICS20 | module | IBC transfer |
| `0x…0803` | Vesting | module | vesting accounts |
| `0x…0804` | Bank | module | balances, supply, send |
| `0x…0805` | Gov | module | governance |
| `0x…0806` | Slashing | module | slashing |
| `0x…0807` | ICS02 | module | IBC client |
| `0x…0900` | AMM | Karsa | swap, quote, getPool, liquidity |
| **`0x…0901`** | **Token Factory** | **Karsa** | `createToken` — create a native token from a contract |
| **`0x…0902`** | **Token Minter** | **Karsa** | `mint`/`burn` on behalf of the token controller |

## 2. Single source of truth

The static list is built by `NewEVMGenesisState` (`genesis.go`) and used by
`App.DefaultGenesis` (`app.go`). `karsad init` uses the same `BasicModuleManager`
through `genutilcli.InitCmd` (`cmd/karsad/cmd/root.go`), so a new chain starts
with every active precompile.

> Previously `karsad init` used `BasicModuleManager.DefaultGenesis`, which only
> contained per-module defaults and **did not** include the precompile list. A
> newly initialised chain therefore had no working precompiles, and
> `local_node.sh` hid the problem by patching genesis through `jq`. That patch
> has been removed.

The only place to maintain is `NewEVMGenesisState`: adding a precompile means
adding it there, and `genesis_test.go` locks the three Karsa addresses.

## 3. Fixed Karsa addresses

| Item | Address |
|---|---|
| Native coin KRA | not a contract — network currency, 18 decimals |
| ERC20 view of `akra` | `0xd9171c1192d82ecd4f71dec2ee0264769af9531e` |
| AMM | `0x…0900` |
| Token factory | `0x…0901` |
| Token minter | `0x…0902` |
| User native token | derived from `(creator, sequence)`; denom `n:0x…` |
| IBC asset | derived from the trace hash |

`0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE` is the EIP-7528 marker for a
native asset in token lists, **not** a contract: there is no code there. Do not
register it as a precompile; Karsa does not need it because the `akra` precompile
reads directly from the bank ledger, with no WETH-style wrap step.

### The `akra` address

`NewErc20GenesisState` registers the native pair at a deterministic address:

```
address = sha256("karsa/erc20/akra")[12:]
        = 0xd9171c1192d82ecd4f71dec2ee0264769af9531e
```

The constant lives in `config.NativeERC20Address`; `config/config_test.go` locks
it to the derivation above. This address is part of genesis: changing it changes
the ERC20 identity of the native asset and breaks wallets, pools, and explorers
that already stored it. Do not copy an address from another chain (Karsa
previously used Evmos's WEVMOS address).

## 4. Gas cost: none

Static precompiles **do not add gas per EVM call**. `stateDB.Prepare` adds all of
them to the access list without charging gas.

This was measured, and the opposite hypothesis was disproved: an earlier estimate
of 13 precompiles × 2,400 gas = 31,200 gas per call never appeared in the
measurements. Do not optimise in that direction again.

Consequently, choosing 13 or 20 precompiles does not change performance. It only
changes the attack surface, because every precompile is code callable from the
EVM.

## 5. Planned precompiles

None. The next candidate is `permit` (EIP-2612) on the ERC20 token precompile, if
it can be implemented safely.

See `docs/native-token.md` for the ownership model and token creation flow.

## 6. Checklist for adding a static precompile

- [ ] Choose an address in the `0x…09xx` range, outside the used addresses
- [ ] Add it to `genesis.go` (`NewEVMGenesisState`)
- [ ] Register its implementation in `app.go` / the `precompiles` module
- [ ] Update `genesis_test.go` so the new address is locked
- [ ] Make sure the address is in `config/permissions.go` (blocked addresses) so
      it cannot accidentally receive funds
- [ ] Add a Solidity interface + NatSpec, following `IAmm.sol`
- [ ] Emit EVM logs for state-changing operations, not only Cosmos events
- [ ] Test calls from an EOA, from a contract, reentrancy, and blocked addresses
- [ ] Verify `karsad q evm params` shows the new address

## 7. Dynamic precompiles

Registered through `x/erc20`:

```go
erc20Keeper.SetToken(ctx, erc20types.NewTokenPair(address, denom, erc20types.OWNER_MODULE))
erc20Keeper.EnableDynamicPrecompile(ctx, address)
```

Assets that use this path:

| Asset | Address |
|---|---|
| Non-EVM native denom that is paired | derived from the denom |
| IBC voucher | derived from the trace hash |
| LP token | `LPAssetAddress("amm/pool/{id}")` |
| Native token | `sha256("karsa/native/" + creator + "/" + sequence)[12:]` |

Registration also creates an EVM account with the ERC20 code hash, so the
address passes `isContract()` checks in third-party integrations.
