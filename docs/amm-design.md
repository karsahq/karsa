# Karsa AMM — Design

Status: **in progress** — `x/amm` implements constant-product pools, integrator
fees, LP shares with an ERC20 precompile, and direct custody for external ERC20
contracts. Pending: AMM precompile and TWAP. Fee abstraction (paying gas in a
token) is **descoped**.

## 1. Goals

1. A first-class automated market maker on Karsa, built as a **Cosmos SDK module** (`x/amm`).
2. Pools between **ERC20-represented assets only**. Raw bank denoms (`akra`, `ibc/…`, `factory/…`) are never used as pool keys.
3. Full AMM product: arbitrary asset pairs, LP shares, and multi-hop routing (Uniswap v2 style paths).
4. Primary consumer: **fee abstraction** — a user holding only a supported token can send a transaction without holding `akra`. Scope depends on the asset class (§10): bank-canonical assets (`akra`, IBC vouchers) can be handled in the ante handler; ERC20 contracts require an ERC-4337 paymaster.

## 2. Key decisions

| # | Decision | Rationale |
|---|---|---|
| D1 | AMM is a Cosmos module, **no Solidity contracts** | Must be callable from the ante handler (fee abstraction) deterministically, without EVM gas or reentrancy |
| D2 | Pool assets are identified by **ERC20 address**, not by bank denom | Matches product requirement; makes the pool interface identical for native, IBC, and coin-registered assets |
| D3 | Pool reserves are the **token itself**: bank denom for `OWNER_MODULE` pairs, contract balance held by the module for `OWNER_EXTERNAL` pairs (§2.2) | One source of truth per asset; no escrow, no `erc20:0x…` denom created by the AMM |
| D4 | LP shares are bank denoms (`amm/pool/{id}`) | Lets LP tokens participate in fee abstraction and (phase 2) be exposed as ERC20 precompiles |
| D5 | Routing: caller supplies the path; on-chain path search is bounded | Uniswap v2 semantics; predictable gas, no unbounded search |

### Why pools are keyed by ERC20 address

An ERC20 address on Karsa can be one of:

| Kind | `ContractOwner` | Balances live in | Poolable |
|---|---|---|---|
| Native denom (`akra`) | `OWNER_MODULE` | bank (precompile at the native address) | ✅ no conversion |
| IBC voucher auto-pair | `OWNER_MODULE` | bank (address derived from trace hash) | ✅ no conversion |
| Coin-registered pair | `OWNER_MODULE` | bank | ✅ no conversion |
| User-deployed ERC20 | `OWNER_EXTERNAL` | contract storage (held by the module) | ✅ permissionless, capability-checked |

Pool reserves are **bank denoms** in all cases. For `OWNER_MODULE` pairs the bank balance and the
EVM view are the same number. For `OWNER_EXTERNAL` pairs the reserve is the `erc20:0x…` denom,
backed 1:1 by tokens escrowed at the x/erc20 module address.

### What "bank-backed" means (and the three token classes)

The Cosmos bank module is the canonical ledger for coins: `balances[account][denom]`.
Three distinct things are easy to confuse:

| Term | Meaning | Applies to |
|---|---|---|
| **precompile-backed** | the ERC20 address is served by chain code that reads the bank ledger | `OWNER_MODULE` pairs (native, IBC) |
| **escrow-backed** | the bank denom `erc20:0x…` is a claim on tokens escrowed at the x/erc20 module address | `OWNER_EXTERNAL` pairs after conversion |
| **contract-only** | balances live only in contract storage | `OWNER_EXTERNAL` pairs before conversion |

A converted ERC20 does **not** become a precompile. Its contract stays at `0xAAA` and keeps its own
storage; conversion only creates the bank-side mirror `erc20:0xAAA` and escrows the tokens.
Therefore the EVM explorer keeps showing only the contract balance, while the bank side is visible
only from Cosmos tooling (see `docs/token-representations.md`).

A user-deployed ERC20 contract is **not** bank-canonical: `x/erc20` can bridge it by creating a
denom `erc20:0x…`, but only for the amount that has been explicitly converted.

Consequence: a Cosmos module can only move bank balances. Pooling a user-deployed ERC20 would
require executing `transferFrom` inside the EVM (not possible from an ante handler) or forcing
users to convert before providing liquidity.

**Decision: no token factory.** Karsa has exactly three token classes:

| Class | Issued by | Bank denom | EVM address |
|---|---|---|---|
| Native | chain genesis | `akra` | precompile (native address) |
| IBC | incoming ICS20 transfer | `ibc/<HASH>` | auto precompile |
| ERC20 | user-deployed contract | `erc20:0x…` only after conversion | the contract itself |

So user-issued tokens are always ERC20 contracts. Their bank form exists only through `x/erc20`
conversion (escrow), which makes dual representation inherent for them: the contract balance and
the `erc20:0x…` bank balance are two halves of the same holding (see `docs/token-representations.md`).

Consequences:

- There is no "bank-backed from birth" path for new tokens; conversion is the only one.
- ERC20 contracts become poolable through direct-custody pools (§2.2).
- Fee abstraction in the ante handler only works for bank-canonical assets (`akra`, IBC).
  ERC20 contracts require an ERC-4337 paymaster (§10.2).

### 2.2 Direct-custody pools (external ERC20)

Pools hold the **token itself**, not a bank representation. Reserves are the module's balance in the
token contract:

```
reserveA = tokenA.balanceOf(ammModuleAddress)
```

How the module moves funds depends on where the token lives:

| Asset class | Movement | Cost |
|---|---|---|
| `akra`, IBC (precompiles, `OWNER_MODULE`) | `bank.SendCoins` | bank only, no EVM |
| ERC20 contracts (`OWNER_EXTERNAL`) | `token.transfer` executed by the module | 2 EVM calls per swap, constant regardless of hops |

Why the AMM does **not** convert to `erc20:0x…`:

- it creates a second ledger (contract balance + bank balance) that the EVM explorer cannot see;
- it requires escrow, an escrow invariant, and handling of pair deletion;
- it does not enable fee abstraction for ERC20 holders: the ante handler still cannot touch contract
  balances;
- it is strictly more expensive: 2 EVM calls **plus** mint/burn/escrow bookkeeping.

Direct custody keeps one source of truth (`balanceOf`). The `erc20:0x…` denom is only created when a
user (or the ICS20 precompile) explicitly converts for an IBC transfer; the AMM never creates it.

Requirements:

- **Capability checks, not a whitelist.** Pools are permissionless. A token is accepted only if the
  first real transfer behaves like a standard ERC20: the module measures `balanceOf` before/after and
  rejects the deposit when the delta differs from the requested amount (this rejects fee-on-transfer
  and rebasing tokens).
- **Measure balance deltas** (`balanceOf` before/after). Never assume the received amount equals the
  requested amount.
- **Reentrancy guard** covering the whole message: a hostile token can call back into the module
  while reserves are mid-update.
- **Gas cap**: EVM calls are bounded by `server/config.DefaultGasCap` (25M).
- **Authorization**: the module executes `transfer` with `from` equal to the message signer, and only
  for the exact signed amount. Never accept an arbitrary `from` from calldata.
- **Fee abstraction is not solved here**: gas is charged before execution, so an `OWNER_EXTERNAL`
  token still cannot pay for its own transaction. That requires an ERC-4337 paymaster.

## 3. Asset model

```go
type AssetID = common.Address // 20 bytes, the token pair's ERC20 address
```

Resolution at the API boundary:

```
AssetID --(x/erc20 GetTokenPairID)--> TokenPair{Denom, Enabled, ContractOwner}
        --(bank)--> reserve balance
```

Rejection rules (return an error, never silently skip):

- pair not found / `Enabled == false`
- asset A == asset B (self-pair)
- pool already exists for the (unordered) pair
- the input is a denom string instead of a 20-byte address (e.g. `ibc/…`, `akra`,
  `erc20:0x…`) — the API boundary only accepts ERC20 addresses; denoms are an
  internal detail resolved via `x/erc20`
- `OWNER_EXTERNAL` pair whose token fails the capability check on first deposit

Special case: the asset whose resolved denom equals `evmtypes.GetEVMCoinDenom()` is the native asset. Its reserves are plain bank `akra`.

## 4. State

```go
type Pool struct {
    ID           uint64
    AssetA       common.Address // sorted: bytes.Compare(AssetA, AssetB) < 0
    AssetB       common.Address
    DenomA       string         // resolved at creation, immutable
    DenomB       string
    ReserveA     sdkmath.Int
    ReserveB     sdkmath.Int
    TotalShares  sdkmath.Int
    LPAssetID    common.Address // phase 2
    FeeBps       uint32         // e.g. 30 = 0.30%
    PoolType     PoolType       // constant_product | stableswap (phase 3)
}
```

Keys:

- `pool/{id}`
- `pool_by_assets/{assetA}/{assetB}` → id
- `pools_by_asset/{asset}` → list of ids (routing candidate set)

Params (`MsgUpdateParams`, governance only):

| Param | Default | Notes |
|---|---|---|
| `max_hops` | 2 | hard cap for routing |
| `default_fee_bps` | 30 | 0.30% |
| `protocol_fee_bps` | 0 | off in phase 1 |
| `min_initial_liquidity` | 1000 | anti-spam, also locks a minimum share |
| `max_price_impact_bps` | 1000 | guard on `quote`/`swap` |

## 5. Messages

| Message | Who | Notes |
|---|---|---|
| `MsgCreatePool{asset_a, asset_b, fee_bps, amount_a, amount_b}` | anyone (or `authority` only, configurable) | validates both assets per §3 |
| `MsgAddLiquidity{pool_id, max_a, max_b, min_shares}` | LP | proportional deposit |
| `MsgRemoveLiquidity{pool_id, shares, min_a, min_b}` | LP | proportional withdrawal |
| `MsgSwapExactIn{sender, path[], amount_in, min_out, receiver, deadline, integrator, integrator_fee_bps}` | user | `path` is a list of `AssetID`; `len(path) >= 2`; integrator fields are optional (§13) |
| `MsgSwapExactOut{...}` | user | phase 3 |
| `MsgUpdateParams{authority, params}` | governance | |

All messages reject `deadline` in the past and `min_out == 0`.

## 6. Queries

| Query | Returns |
|---|---|
| `Pool{id}` / `Pools{pagination}` | pool state |
| `PoolByAssets{a,b}` | pool id + state |
| `Quote{path, amount_in, integrator, integrator_fee_bps}` | `amount_out`, `pool_fee`, `integrator_fee`, per-hop impact |
| `PoolsByAsset{asset}` | candidate pools for routing |
| `Twap{pool_id, window}` | time-weighted price (phase 2) |

`Quote` is pure (no state writes) and is the function the ante handler uses for fee abstraction.

## 7. Math (phase 1: constant product)

With `feeFactor = 10_000 - feeBps`:

```
amountOut = (amountInAfterFee * reserveOut) / (reserveIn * 10_000 + amountInAfterFee)
amountInAfterFee = amountIn * feeFactor
```

Fee ordering when an integrator is set (§13):

```
integratorFee   = amountIn * integratorFeeBps / 10_000
amountInForPool = amountIn - integratorFee
// the pool fee is then applied to amountInForPool
```

Rules:

- All arithmetic with `sdkmath.Int`; no floats.
- Round **down** for user output and **up** for required input (favours the pool).
- Enforce `k_after >= k_before`.
- Lock `min_initial_liquidity` shares forever on first deposit (inflation-attack guard).

## 8. Routing

- Caller-provided path, Uniswap v2 style: `[MOMO, USDT, akra]`.
- Hard cap `len(path) - 1 <= max_hops` (default 2).
- Each hop looks up `pool_by_assets`; missing pool ⇒ error (no silent fallback).
- Path validation: no duplicate assets, all assets poolable, deadline respected.
- Optional (phase 3): bounded on-chain route search over `pools_by_asset`, max 3 hops, gas-capped.

## 9. LP shares

- Phase 1: LP position is a bank denom `amm/pool/{id}`; holders can move it as a normal coin.
- Phase 2: expose the LP denom as an ERC20 precompile so EVM contracts can hold LP.

  Implementation note: `x/erc20.CreateNewTokenPair` only derives addresses for `ibc/…`
  denoms (`utils.GetIBCDenomAddress`). For `amm/pool/{id}` we need our own deterministic
  derivation — `sha256(denom)` truncated to 20 bytes — plus
  `RegisterERC20CodeHash` + `EnableDynamicPrecompile`.

## 10. Fee abstraction integration (descoped)

> **Status: not in scope.** Paying gas with a non-native token was descoped: it requires trading a
> token into `akra` before execution, which adds price-manipulation and MEV surface for a benefit
> that is mostly onboarding. Kept here as a reference if it is ever revived; gas can instead be
> sponsored by integrators through an ERC-4337 paymaster (§10.2).

Fee abstraction has two different scopes, because the ante handler can only move **bank**
balances:

| Asset class | Mechanism | Why |
|---|---|---|
| `akra`, IBC vouchers (precompiles) | ante decorator | balances already live in bank; no conversion needed |
| ERC20 contracts | ERC-4337 paymaster | gas is charged before execution, so the ante handler cannot pull contract balances |

### 10.1 Bank-canonical assets (`akra`, IBC): ante path

```
1. tx arrives
2. ante: does sender cover gas in akra?
   - yes → normal path
   - no  → continue
3. required fee = gasLimit × effectiveGasPrice  (akra)
4. quote token→akra over `path` (max 2 hops) using TWAP, not spot
5. move the token into the pool, credit akra to the sender, pay gas, run tx
```

Authorization: the AMM module **must not** debit funds without consent. For precompile-backed
tokens the balance is a bank balance, so the ante handler must only move it when the signed
message authorizes it. Do **not** add a blanket "module may debit any balance" path.

### 10.2 ERC20 contracts: ERC-4337 paymaster

```
1. user signs a UserOperation
2. bundler (holds akra) submits it and pays gas
3. EntryPoint calls the paymaster
4. paymaster charges the user in the ERC20 (transferFrom / permit)
5. paymaster swaps the ERC20 for akra through a liquidity source
   (contract DEX, or a direct-custody AMM pool)
```

This is a separate project and is out of scope for phases 1–4. It is the only correct way to let
an ERC20 contract pay for its own transaction, because gas is settled before the EVM runs.

Open design points (ante path):

| Point | Options |
|---|---|
| CheckTx vs DeliverTx price drift | TWAP + 10–20% buffer; reject beyond `max_price_impact_bps` |
| Gas refunds | charge on `gasLimit`, or settle actual usage in a post-handler |
| Which tokens (if revived) | whitelist only |
| Solvency | floor per pool; cap per-block fee swaps |

## 11. Security checklist

- [ ] Invariant tests: reserves non-negative, `k` monotonic, shares == sum of LP balances
- [ ] First-depositor inflation attack (locked minimum liquidity)
- [ ] Rounding always favours the pool
- [ ] TWAP manipulation (window length, minimum liquidity, deviation cap)
- [ ] Sandwich/JIT liquidity: `min_out` mandatory, consider private orderflow for fee swaps
- [ ] Reentrancy: not possible at module level, but audit precompile entrypoints
- [ ] Pause: per-pool and global
- [ ] Pool creation spam: `min_initial_liquidity`
- [ ] Asset pair mutations: token pairs can be disabled later — pools must re-validate on use
- [ ] Deterministic addresses: assert no collision between LP asset addresses and existing pairs
- [ ] Integrator fee cap enforced, emitted in events, and returned by `Quote`
- [ ] Decimal normalisation in every price/quote surface (18 vs 6 decimals)
- [ ] Price display gated by a minimum-liquidity threshold

## 12. Phasing

| Phase | Scope |
|---|---|
| 1 | Module skeleton, constant product, create/add/remove/swap, `Quote`, integrator fee, 1–2 hop path, LP as bank denom, precompile for `swap`/`quote` |
| 2 | Direct-custody pools for external ERC20 contracts (EVM transfers, balance-delta checks, reentrancy guard) |
| 3 | TWAP for fees/pricing (fee abstraction is descoped) |
| 4 | Stableswap pools, `SwapExactOut`, bounded route search, LP as ERC20 |
| 5 | ERC-4337 paymaster for ERC20 contracts (separate project) |

## 13. Integrator fee & external routers

Third parties (a trading UI, a router contract, an aggregator) may route swaps through the module and
charge their own fee **on top of** the pool fee. This is an *integrator fee*, not a referral
revenue-share: the platform is paid by its own users and LP revenue is untouched.

```
user pays 0.5%
  ├─ 0.3%  → pool reserve (LPs)
  └─ 0.2%  → integrator
```

| Rule | Value |
|---|---|
| Default pool fee | `fee_bps` per pool (e.g. 30 = 0.30%) |
| Integrator fee | `integrator_fee_bps`, optional, default 0 |
| Cap | `params.max_integrator_fee_bps` (default 100 = 1.00%), governance-adjustable |
| Token | taken from the **input** token |
| Multi-hop | charged once per swap, not per hop |
| Events | `swap{sender, integrator, integrator_fee, pool_fee, amount_in, amount_out}` |

Notes:

- The fee is deducted before the pool math: `amountInForPool = amountIn - integratorFee`.
- `integrator` may be any valid address; it does not need to be the caller. Contracts normally pass
  their own address.
- The cap is a **user-protection** parameter: users cannot easily inspect calldata, so without a cap
  a compromised frontend could charge almost everything. It is not a protocol revenue lever.
- There is no revenue share of the pool fee (referral model). See §15.

### Limit orders and order books

A limit order is just a swap with `min_out` that a relayer submits when the price is favourable; no
new mechanism is required. A full on-chain CLOB (matching engine, custody, settlement) is out of
scope for now. If built, it sits on top of the AMM, which acts as backstop liquidity.

## 14. Pricing & display

Spot prices come from `Quote`; portfolio values come from `Twap`. The module is **numeraire-agnostic**:
it quotes along a path and never hardcodes a reference asset.

| Need | Source | Numeraire |
|---|---|---|
| Pair price while trading | `Quote(path, amount)` | the pair itself |
| Universal price / portfolio | `Twap(pool, window)` | USD via a stable pool |
| Fee caps, gas, params | `Quote(A → akra)` | `akra` |

Rules:

- **Decimals**: normalise before display — `price = (out / 10^decOut) / (in / 10^decIn)`. Never compare
  raw integers: `akra` and ERC20 precompiles use 18 decimals, bridged stablecoins often use 6.
- **Liquidity threshold**: do not show a price for a pool below `min_display_liquidity`; show `—`.
- **No route, no price**: if `Quote` fails, show `—` instead of guessing.
- **Spot vs TWAP**: spot for the swap preview (that is what the user will get, including impact);
  TWAP for valuations and charts (manipulation-resistant, no flicker).
- **Stablecoin caveat**: if the quote asset is a bridged stablecoin trading at a discount, every USD
  number is skewed by that discount. Surface the stablecoin price somewhere in the UI.

## 15. Out of scope (for now)

- A token factory module (tokens on Karsa are `akra`, IBC vouchers, or ERC20 contracts)
- Referral / revenue-share of the pool fee (only integrator fees are supported)
- On-chain order book / CLOB (limit orders are implemented as `min_out` swaps)
- Solidity AMM/router contracts
- Flash swaps (module → EVM callback)
- Cross-chain swaps (IBC packet-forward based)
- Token whitelisting (pools are permissionless; compatibility is enforced by balance-delta checks)
- Paying gas with a non-native token (descoped, see §10)
