# Karsa AMM — Design

Status: **in progress** — `x/amm` implements constant-product and two-asset
stableswap pools, **bank-backed custody with automatic ERC20 ↔ bank conversion at
the swap/liquidity boundary**, multiple pools per pair selected by fee tier,
integrator fees, exact-in and exact-out swaps, LP shares with an ERC20 precompile,
an EVM precompile (`quote`, `getPool`, `getPoolById`, `getPools`, `swapExactIn`), and a cumulative-price TWAP.
Remaining: bounded multi-hop route search and conversion hardening.
Fee abstraction (paying gas in a token) is **descoped**.

## 1. Goals

1. A first-class automated market maker on Karsa, built as a **Cosmos SDK module** (`x/amm`).
2. Pools between **ERC20-represented assets** at the API boundary. Pool reserves are **bank denoms**: `akra`/IBC natively, `erc20:0x…` for external ERC20 contracts after automatic conversion.
3. Full AMM product: arbitrary asset pairs, multiple fee-tier pools per pair, LP shares, and multi-hop routing (Uniswap v2 style paths).
4. Optional (descoped): **fee abstraction** — letting a user pay gas in a supported token. Bank-canonical assets (`akra`, IBC vouchers) could use the ante handler; ERC20 contracts would require an ERC-4337 paymaster (§10).

## 2. Key decisions

| # | Decision | Rationale |
|---|---|---|
| D1 | AMM is a Cosmos module, **no Solidity contracts** | Deterministic accounting, native bank integration, and EVM access through a precompile |
| D2 | Pool assets are identified by **ERC20 address** at the API boundary; the internal reserve denom is resolved via `x/erc20` | Makes the pool interface identical for native, IBC, and external ERC20 assets |
| D3 | Pool reserves are **bank denoms**. External ERC20 contracts are auto-converted to `erc20:0x…` on the way in and back to the contract token on the way out (§2.2) | Bank ledger is authoritative; token quirks are isolated at the conversion boundary |
| D4 | LP shares are bank denoms (`amm/pool/{id}`) | Lets LP tokens participate in fee abstraction and be exposed as ERC20 precompiles |
| D5 | Routing: caller supplies the path; on-chain path search is bounded | Uniswap v2 semantics; predictable gas, no unbounded search |
| D6 | **Multiple pools per pair**, keyed by `(assetA, assetB, poolType, feeBps)`; max 6 per pair | Fee competition and anti-squatting without concentrated liquidity |
| D7 | Fee tiers are fixed per pool type: constant product `5/10/30` bps, stableswap `1/3/5` bps | Predictable UX, bounded routing, no fee spam |
| D8 | Integrator fee is capped at 100 bps and charged **before** conversion | User protection; integrator revenue stays separate from LP revenue |
| D9 | Pool status: `ACTIVE` or `WITHDRAW_ONLY`; there is no `CLOSED` or automatic `INACTIVE` state | Keeps the emergency brake but avoids a governance kill switch |

### Why pools are keyed by ERC20 address

An ERC20 address on Karsa can be one of:

| Kind | `ContractOwner` | Balances live in | Poolable |
|---|---|---|---|
| Native denom (`akra`) | `OWNER_MODULE` | bank (precompile at the native address) | ✅ no conversion |
| IBC voucher auto-pair | `OWNER_MODULE` | bank (address derived from trace hash) | ✅ no conversion |
| Coin-registered pair | `OWNER_MODULE` | bank | ✅ no conversion |
| User-deployed ERC20 | `OWNER_EXTERNAL` | bank denom `erc20:0x…` after auto-convert; contract only at the boundary | ✅ auto-convert |

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

Consequence: a Cosmos module can only move bank balances. The AMM converts an external ERC20 at the
boundary, so the pool itself only ever moves the bank denom `erc20:0x…`.

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
- ERC20 contracts become poolable through **auto-converted bank-backed pools** (§2.2).
- Fee abstraction in the ante handler only works for bank-canonical assets (`akra`, IBC).
  ERC20 contracts require an ERC-4337 paymaster (§10.2).

### 2.2 Bank-backed pools (external ERC20 auto-convert)

Pools always hold **bank denoms**. For an `OWNER_EXTERNAL` ERC20, the pool denom is
`erc20:0x…`; the AMM converts at the user boundary:

```
user ERC20 --convert--> erc20:0x… (escrow at x/erc20) --> pool
pool --> erc20:0x… --convert--> user ERC20
```

- **Input:** convert the user's ERC20 to `erc20:0x…` and move it to the AMM module.
- **Output:** convert the module's `erc20:0x…` back to the contract token and send it to the user.
- **Multi-hop:** only the first and last assets are converted; intermediate reserves are bank denoms.
- **Add/remove liquidity:** convert each external side.
- **Integrator fee:** paid in the input token **before** conversion.
- **Pool fee:** stays in the pool as bank denom; it is not converted again.

Consequences:

- Users never need to know about `erc20:0x…`; the UI shows the ERC20 contract/precompile.
- The AMM does not depend on arbitrary token behavior after conversion. `x/erc20` checks balance
  invariance and rejects fee-on-transfer.
- The AMM depends on `x/erc20` conversion staying enabled for the pair. If conversion is disabled,
  external pools must enter `WITHDRAW_ONLY` (or freeze if the guard is bypassed).
- The AMM module is excluded from `BlockedAddresses` so it can receive minted bank denom; EVM native
  transfers to the module are still rejected by the `isModule` check.
- Reentrancy guard still covers conversion + pool update; `x/erc20` performs an ERC20 transfer.
- No `assertCustody` EVM balance checks are needed; the bank ledger is authoritative.

Failure modes at the conversion boundary:

| Token behavior | Result |
|---|---|
| standard ERC20 | works |
| fee-on-transfer / reflection | rejected by x/erc20 balance invariance |
| rebasing | conversion may succeed, but escrow backing can drift; pool bank denom is unaffected |
| pausable / blacklist | conversion fails; pool is frozen until resolved |
| upgradeable | behavior can change; conversion failure/freeze is possible |

## 3. Asset model

```go
type AssetID = common.Address // 20 bytes, the token pair's ERC20 address
```

Resolution at the API boundary:

```
AssetID --(x/erc20 GetTokenPairID)--> TokenPair{Denom, Enabled, ContractOwner}
        --(OWNER_EXTERNAL)--> convert contract <-> denom erc20:0x…
        --(bank)--> pool reserve balance
```

Rejection rules (return an error, never silently skip):

- pair not found / `Enabled == false`
- conversion disabled for an `OWNER_EXTERNAL` pair (`x/erc20` `MintingEnabled` fails)
- asset A == asset B (self-pair)
- a pool with the same `(assetA, assetB, poolType, feeBps)` already exists
- `max_pools_per_pair` reached
- `feeBps` is not in the allowed tier list for the pool type
- the input is a denom string instead of a 20-byte address (e.g. `ibc/…`, `akra`,
  `erc20:0x…`) — the API boundary only accepts ERC20 addresses; denoms are an
  internal detail resolved via `x/erc20`

Special case: the asset whose resolved denom equals `evmtypes.GetEVMCoinDenom()` is the native asset. Its reserves are plain bank `akra`.

## 4. State

```go
type PoolStatus int32
const (
    ACTIVE PoolStatus = iota
    WITHDRAW_ONLY
)

type Pool struct {
    ID             uint64
    AssetA         common.Address // sorted: bytes.Compare(AssetA, AssetB) < 0
    AssetB         common.Address
    DenomA         string         // bank denom; erc20:0x… for external ERC20
    DenomB         string
    ReserveA       sdkmath.Int    // bank balance tracked by the pool
    ReserveB       sdkmath.Int
    TotalShares    sdkmath.Int
    LockedShares   sdkmath.Int
    LPAssetID      common.Address
    FeeBps         uint32         // fixed tier: 5/10/30 or 1/3/5
    PoolType       PoolType       // CONSTANT_PRODUCT (0) | STABLESWAP (1)
    Amplification  uint64         // A, stableswap only; 0 otherwise
    ScalingFactorA uint64         // 10^(18-decimals); 0 means 1
    ScalingFactorB uint64
    Status         PoolStatus     // ACTIVE | WITHDRAW_ONLY
}
```

Keys:

- `pool/{id}`
- `pool_by_assets/{assetA}/{assetB}` → list of pool ids
- `pool_key/{assetA}/{assetB}/{poolType}/{feeBps}` → id (uniqueness)
- `pools_by_asset/{asset}` → list of ids (routing candidate set)

Params (`MsgUpdateParams`, governance only):

| Param | Default | Notes |
|---|---|---|
| `max_hops` | 2 | hard cap for routing |
| `max_pools_per_pair` | 6 | 3 CP + 3 stableswap |
| `cp_fee_tiers_bps` | `[5, 10, 30]` | allowed constant-product tiers |
| `stable_fee_tiers_bps` | `[1, 3, 5]` | allowed stableswap tiers |
| `max_fee_bps` | 30 | cap for any pool fee |
| `max_integrator_fee_bps` | 100 | 1.00% cap |
| `max_total_fee_bps` | 130 | pool + integrator, user protection |
| `min_initial_liquidity` | 1000 | anti-spam, also locks a minimum share |
| `creation_fee` | 100 `akra` | one-off fee paid by the pool creator, routed to the community pool (see §15) |
| `fee_burn_bps` | 0 | share of `creation_fee` burned instead of pooled |
| `max_price_impact_bps` | 1000 | guard on `quote`/`swap` |

`amplification` is not a global param: it is chosen by the pool creator and
bounded by `MinAmplification`/`MaxAmplification` (1 … 1,000,000).

### Stableswap pools (2 assets)

A stableswap pool uses the Curve invariant generalised to two assets:

```
Ann*S + D = Ann*D + D^3/(4xy),   Ann = 2A,  S = x + y
```

- `x` and `y` are the reserves normalised to 18 decimals with the pool's
  `ScalingFactorA/B` (`10^(18-decimals)`). A zero factor is treated as 1.
- `A` controls how flat the curve is near 1:1. Higher `A` means less slippage and
  more exposure to a depegged asset; lower `A` behaves more like constant product.
- `D` is found with Newton iteration (max 255 rounds), the same bound Curve uses.
- Exact-in prices with the net input (`amountIn - fee`) and then adds the full
  input to the reserve, so the fee accrues to LPs. Exact-out solves for the input
  and grosses the fee up.
- Spot/TWAP prices use the marginal derivative of the invariant, not the raw
  reserve ratio, so a flat curve is not misreported as a large price move.
- Add/remove liquidity stay proportional (same code path as constant product);
  imbalanced deposits are not accepted as a single-sided operation.

Pool creation resolves decimals from bank metadata, then the denom prefix
(`u…` = 6, `a…` = 18), then an on-chain `decimals()` call. Assets with more than
18 decimals are rejected for stableswap.

Risk note: `A` is chosen by the creator and is immutable. A depeg can make the
pool absorb the falling asset at near-par; LPs bear that risk. There is no
protocol backstop and no curation list.

The EVM precompile's `getPool` and `getPoolById` return `poolType`, `amplification`,
both scaling factors and `status`; `getPools` returns every pool id for a pair.

### Fee tiers

| Pool type | Allowed `feeBps` | Max |
|---|---|---:|
| `CONSTANT_PRODUCT` | `5`, `10`, `30` | 30 bps |
| `STABLESWAP` | `1`, `3`, `5` | 5 bps |

- Fee is fixed at pool creation and immutable; a different fee requires a new pool.
- Multiple pools per pair are expected: `(assetA, assetB, poolType, feeBps)` is unique.
- `max_pools_per_pair = 6` (3 CP + 3 stableswap).
- Integrator fee is separate and capped at 100 bps (§13).

### Pool status and governance guard

`PoolStatus` prevents LPs from being trapped when the conversion layer is disabled:

| Status | Swap | Add liquidity | Remove liquidity |
|---|---|---|---|
| `ACTIVE` | ✅ | ✅ | ✅ |
| `WITHDRAW_ONLY` | ❌ | ❌ | ✅ |

- Governance may move a pool to `WITHDRAW_ONLY` at any time. This is the emergency path.
- A pool may return to `ACTIVE` only if `x/erc20` conversion is enabled for both external assets.
- There is no `CLOSED` or automatic `INACTIVE` state. A pool with no redeemable shares remains in
  state; the residual locked reserve is never redeemable.
- `EndBlock` runs `SyncPoolStatuses`: an `ACTIVE` pool with an external leg is downgraded to
  `WITHDRAW_ONLY` when `x/erc20` is disabled globally or its token pair is disabled. It never
  upgrades a pool automatically; governance must set `ACTIVE` again after conversion is restored.
- `x/erc20` governance cannot be intercepted directly (it is an upstream module). The on-chain guard
  is the automatic downgrade plus the `ACTIVE` transition check in `MsgSetPoolStatus`.

### Conversion boundary

With the AMM module excluded from `BlockedAddresses`, conversion can target the module directly:

```
input:  user ERC20 --x/erc20 convert--> erc20:0x… at AMM module
output: erc20:0x… at AMM module --x/erc20 convert--> user ERC20
```

- Integrator fee is transferred in the input ERC20 **before** the conversion of the net amount.
- The pool fee remains in the pool as bank denom; it is never converted in the same swap.
- Output conversion is implemented in the AMM: send the bank denom from the AMM module to the
  x/erc20 module, burn it, then transfer the escrowed ERC20 with the caller's stateDB. This keeps
  precompile execution atomic; `x/erc20.ConvertCoinNativeERC20` creates its own stateDB and cannot
  be used from the precompile path.
- Without the `BlockedAddresses` exception, input conversion would mint to the user and then require
  an extra bank send; the exception saves ~17k gas per external input.

## 5. Messages

| Message | Who | Notes |
|---|---|---|
| `MsgCreatePool{asset_a, asset_b, fee_bps, amount_a, amount_b, pool_type, amplification}` | anyone | fee must be an allowed tier for the pool type; uniqueness is `(assetA, assetB, poolType, feeBps)` |
| `MsgAddLiquidity{pool_id, max_a, max_b, min_shares}` | LP | proportional deposit; pool must be `ACTIVE` |
| `MsgRemoveLiquidity{pool_id, shares, min_a, min_b}` | LP | proportional withdrawal; allowed in `ACTIVE` or `WITHDRAW_ONLY` |
| `MsgSwapExactIn{sender, path[], pool_ids[], amount_in, min_out, receiver, deadline, integrator, integrator_fee_bps}` | user | `path` is a list of `AssetID`; `pool_ids[i]` selects the pool for hop `i`; empty `pool_ids` auto-selects the best single pool |
| `MsgSwapExactOut{sender, path[], pool_ids[], amount_out, max_amount_in, receiver, deadline, integrator, integrator_fee_bps}` | user | bounded by `max_amount_in`; integrator fee is grossed up on top of the pool input |
| `MsgSetPoolStatus{authority, pool_id, status}` | governance | `ACTIVE` / `WITHDRAW_ONLY`; guard rules in §4 |
| `MsgUpdateParams{authority, params}` | governance | fee tiers, caps, `max_pools_per_pair` |

All messages reject `deadline` in the past and `min_out == 0`.

## 6. Queries

| Query | Returns |
|---|---|
| `Pool{id}` / `Pools{pagination}` | pool state |
| `PoolsByAssets{a,b}` | all pools for the pair (id, type, fee, status, reserves) |
| `Quote{path, pool_ids, amount_in, integrator, integrator_fee_bps}` | `amount_out`, `pool_fee`, `integrator_fee`, `total_fee`, per-hop impact |
| `QuoteExactOut{path, pool_ids, amount_out}` | `amount_in` required (including pool fees) |
| `PoolsByAsset{asset}` | candidate pools for routing |
| `Twap{pool_id, window}` | time-weighted price per pool |

`Quote` is pure (no state writes) and is the function the ante handler uses for fee abstraction.

## 7. Math (constant product)

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

Effective total fee is compounded, not a plain sum:

```
totalFee = 1 - (1 - poolFee) * (1 - integratorFee)
```

For pool 0.30% + integrator 0.50%, the nominal total is 0.80% and the effective total is
≈0.7985%. Quotes must return both the breakdown and the effective total.

Rules:

- All arithmetic with `sdkmath.Int`; no floats.
- Round **down** for user output and **up** for required input (favours the pool).
- Enforce `k_after >= k_before`.
- Lock `min_initial_liquidity` shares forever on first deposit (inflation-attack guard).

## 8. Routing

- Caller-provided path, Uniswap v2 style: `[MOMO, USDT, akra]`.
- Each hop selects a pool. `pool_ids[i]` is explicit; empty `pool_ids` selects the best single pool
  (largest output for exact-in, smallest input for exact-out).
- No split routing: one pool per hop. Integrators may split off-chain with multiple swaps.
- Hard cap `len(path) - 1 <= max_hops` (default 2).
- Candidate set per hop is bounded by `max_pools_per_pair` (6).
- Auto-selection compares output (exact-in) or required input (exact-out) across candidate pools and
  rejects `WITHDRAW_ONLY` pools.
- Path validation: no duplicate assets, all assets poolable, all selected pools active, deadline respected.
- Optional (later): bounded on-chain route search over `pools_by_asset`, max 3 hops, gas-capped.

## 9. LP shares

- LP position is a bank denom `amm/pool/{id}`; holders can move it as a normal coin.
- The denom is exposed as an ERC20 precompile so EVM contracts can hold LP.
- Each pool (type + fee tier) has its own LP denom and ERC20 precompile address.
- LP shares can be redeemed while the pool is `ACTIVE` or `WITHDRAW_ONLY`.
- There is no `CLOSED` state; pools with no redeemable shares remain in state.

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
   (contract DEX, or a bank-backed AMM pool)
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
- [ ] Reentrancy: precompile entrypoint and conversion boundary
- [ ] Pool status transitions: only governance; `ACTIVE <-> WITHDRAW_ONLY`
- [ ] Governance guard: `SyncPoolStatuses` downgrades external pools to `WITHDRAW_ONLY`; `ACTIVE` transition requires conversion
- [ ] Conversion dependency: `x/erc20` pair enabled, `MintingEnabled`, `IsSendEnabledCoin`
- [ ] AMM module excluded from `BlockedAddresses`; precompile address still blocked
- [ ] Multi-pool uniqueness `(assetA, assetB, poolType, feeBps)` and `max_pools_per_pair`
- [ ] Fixed fee tiers per pool type; no arbitrary fee values
- [ ] Total fee cap (`pool + integrator`) and quote breakdown
- [ ] Pool creation spam: `min_initial_liquidity`, creation fee, tier whitelist
- [ ] Asset pair mutations: pair/ conversion can be disabled later — pools must re-validate on use
- [ ] Deterministic addresses: assert no collision between LP asset addresses and existing pairs
- [ ] Integrator fee cap enforced, emitted in events, and returned by `Quote`
- [ ] Decimal normalisation in every price/quote surface (18 vs 6 decimals)
- [ ] Price display gated by a minimum-liquidity threshold and canonical pool

## 12. Phasing

| Phase | Scope |
|---|---|
| 1 | Module skeleton, constant product, create/add/remove, exact-in and exact-out swap, `Quote`, integrator fee, 1–2 hop path, LP as bank denom + ERC20 precompile, precompile for `swap`/`quote`, TWAP |
| 2 | Bank-backed custody for external ERC20 with automatic conversion, multiple fee-tier pools per pair, pool status and governance guard |
| 3 | Bounded multi-hop route search; conversion hardening and failure-mode tests |
| 4 | ERC-4337 paymaster for ERC20 contracts (separate project) |

Fee abstraction remains descoped (see §10).

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
| Pool fee | fixed tier per pool: CP `5/10/30` bps, stable `1/3/5` bps |
| Integrator fee | `integrator_fee_bps`, optional, default 0 |
| Integrator cap | `params.max_integrator_fee_bps` (default 100 = 1.00%) |
| Total cap | `params.max_total_fee_bps` (default 130 = 1.30%) |
| Token | taken from the **input** token before conversion |
| Multi-hop | charged once per swap, not per hop |
| Events | `swap{sender, integrator, integrator_fee, pool_fee, total_fee, amount_in, amount_out}` |

Notes:

- The fee is deducted before the pool math and before conversion: `amountInForPool = amountIn - integratorFee`.
- For exact-output swaps the fee is grossed up on top of the pool input so it stays a percentage of
  the total amount paid: `totalIn = poolIn + ceil(poolIn * bps / (10_000 - bps))`.
- Nominal total is `poolFee + integratorFee`; effective total is
  `1 - (1 - poolFee)(1 - integratorFee)`. Quotes return both.
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
| Pair price while trading | `Quote(path, pool_ids, amount)` | the pair itself |
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
- **Multi-pool**: display pool type and fee tier; use a canonical pool for price display/routing
  defaults, and let the router compare candidates for execution.

## 15. Out of scope (for now)

- A token factory module (tokens on Karsa are `akra`, IBC vouchers, or ERC20 contracts)
- Referral / revenue-share of the pool fee (only integrator fees are supported)
- On-chain order book / CLOB (limit orders are implemented as `min_out` swaps)
- Solidity AMM/router contracts
- Flash swaps (module → EVM callback)
- Cross-chain swaps (IBC packet-forward based)
- Concentrated liquidity (v3-style ranges); the current model is full-range v2-style with fee tiers
- Token whitelisting (pools are permissionless; conversion compatibility is enforced by `x/erc20`)
- Paying gas with a non-native token (descoped, see §10)
