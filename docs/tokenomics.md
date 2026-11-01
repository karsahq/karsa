# Karsa Tokenomics

Status: **draft / proposed**. The values below are chain-level parameters
enforced by genesis. They are not AMM module parameters.

## Supply

| Item | Value |
|---|---:|
| Max supply | **1,000,000,000 KRA** |
| Validator allocation in `local_node.sh` | **100,000,000 KRA** |
| Dev accounts in `local_node.sh` | **1,000 KRA each** |
| Production initial allocation | policy decision for genesis |

`1 KRA = 10^18 akra`. The local node funds the validator with 100M KRA and each
dev account with 1,000 KRA for testing. That dev funding is not a production
allocation plan. Production genesis should set the intended balances explicitly.

The `x/mint` module mints new KRA until `max_supply` is reached. The cap is
enforced by the mint module parameters, not by the AMM or by a separate module.

## Proposed production allocation

The on-chain genesis only defines balances. How the initial 100M KRA is split is
a policy decision for the genesis account(s):

| Bucket | Share | Amount |
|---|---:|---:|
| Sale / circulating / liquidity incentives | 50% | 50,000,000 KRA |
| Core developers | 25% | 25,000,000 KRA |
| Treasury / ecosystem / partnerships | 25% | 25,000,000 KRA |

These buckets are **not enforced by the chain**; they are an operational
allocation commitment. Any vesting/lockup should be implemented with vesting
accounts in the production genesis.

## Inflation

| Param | Value |
|---|---:|
| `minter.inflation` | 5.00% |
| `params.inflation_rate_change` | 0% |
| `params.inflation_min` | 5.00% |
| `params.inflation_max` | 5.00% |
| `params.blocks_per_year` | 21,038,400 |
| `params.max_supply` | 1,000,000,000 KRA |

Inflation is fixed at **5% per year** and does not adjust with the bonded ratio.
The `max_supply` cap stops minting at 1B KRA.

Starting from 100M KRA, 5% compounding reaches 1B in roughly 47 years; the cap
makes the terminal supply deterministic.

`blocks_per_year` assumes **1.5 second blocks**:

```text
365.25 * 24 * 60 * 60 / 1.5 = 21,038,400
```

`local_node.sh` uses a faster 1s commit for development. Production block time
should match the value configured here; if it changes, update
`config.BlocksPerYear` and the genesis parameter together.

## Block limits

| Param | Value |
|---|---:|
| `consensus.params.block.max_bytes` | 3,000,000 (~2.86 MiB) |
| `consensus.params.block.max_gas` | 100,000,000 |

At ~1.5s blocks this is roughly 66.7M gas/second. `max_gas` is the practical
limiter for AMM traffic; `max_bytes` caps oversized blocks and stays well above
the 1 MiB per-transaction limit.

The AMM throughput test uses a 150M gas target for capacity evaluation. That is
not the current genesis value; current `local_node.sh` and e2e use 100M.

## Where inflation goes

The `x/mint` module mints to the fee collector account; `x/distribution` then
streams rewards to validators and delegators. The default community tax is 2%;
that share is routed to the community pool.

## Fees

- **Gas** is paid in `akra`. Karsa sets `feemarket.params.no_base_fee = true`,
  so the base fee is disabled. Transaction fees go to the fee collector and are
  distributed through `x/distribution`; the chain does not burn a protocol base
  fee by default.
- **AMM pool fee** goes to the LPs of the selected pool.
- **Integrator fee** goes to the integrator, not to LPs and not to the protocol.
- **AMM pool creation fee** defaults to **100 akra**. With the default
  `fee_burn_bps = 0`, the full fee is sent to the community pool. A nonzero
  `fee_burn_bps` can burn part of it instead.
- **Native-token creation fee** defaults to zero. It is a spam control, not a
  protocol revenue stream.

## Non-goals

- No rebasing or elastic supply.
- No protocol revenue share of AMM pool fees.
- No protocol allocation tied to the native-token factory. Native tokens are a
  chain feature; tokenomics does not create a protocol token for them.
- No guarantee that symbols are unique. Native tokens are identified by address
  and denom, not by symbol.

## Production checklist

1. Set genesis balances to the intended allocation.
2. Use vesting accounts for developer/treasury buckets where applicable.
3. Confirm `blocks_per_year` against the measured production block time.
4. Confirm `max_supply` and inflation parameters in the production genesis.
5. Confirm the community tax and AMM `creation_fee`/`fee_burn_bps` policy.
6. Publish the allocation and vesting schedule before launch.
