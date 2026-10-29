# Karsa Tokenomics

Status: **draft / proposed** — the values below are the launch configuration used by
`local_node.sh`. They are chain-level parameters, not AMM module parameters.

## Supply

| Item | Value |
|---|---:|
| Max supply | **1,000,000,000 KRA** |
| Initial supply at genesis | **100,000,000 KRA** |
| Initial allocation account | validator/genesis account created by `local_node.sh` |

`1 KRA = 10^18 akra`. The initial 100M KRA is minted into the genesis account; the
remaining 900M KRA is minted over time by the `x/mint` module until the max supply
cap is reached.

## Proposed initial allocation

The on-chain genesis only defines total supply. The 100M initial allocation is a
policy decision for the genesis account(s):

| Bucket | Share | Amount |
|---|---:|---:|
| Sale / circulating / liquidity incentives | 50% | 50,000,000 KRA |
| Core developers | 25% | 25,000,000 KRA |
| Treasury / ecosystem / partnerships | 25% | 25,000,000 KRA |

These buckets are **not enforced by the chain**; they are an operational allocation
commitment. Any vesting/lockup should be implemented with vesting accounts in the
production genesis.

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
This keeps validator/delegator income predictable while the network bootstraps.
The `max_supply` cap stops minting at 1B KRA.

Starting from 100M KRA, 5% compounding reaches 1B in roughly 47 years; the cap
makes the terminal supply deterministic.

`blocks_per_year` assumes **1.5 second blocks**:

```
365.25 * 24 * 60 * 60 / 1.5 = 21,038,400
```

If the target block time changes, update this value. Otherwise inflation per block
is wrong even though the annual percentage is correct.

## Block limits

| Param | Value |
|---|---:|
| `consensus.params.block.max_bytes` | 3,000,000 (~2.86 MiB) |
| `consensus.params.block.max_gas` | 100,000,000 |

At ~1.5s blocks this is roughly 66.7M gas/second. `max_gas` is the practical
limiter for AMM traffic; `max_bytes` caps oversized blocks and stays well above the
1 MiB per-transaction limit.

## Where inflation goes

The `x/mint` module mints to the fee collector account; `x/distribution` then
streams rewards to validators and delegators. The community tax (`community_tax`,
2% by default) is routed to the community pool.

## Fees

- **Gas** is paid in `akra` and burned/distributed according to the fee market.
- **AMM pool fee** goes to LPs of the selected pool.
- **Integrator fee** goes to the integrator, not to LPs and not to the protocol.
- **Pool creation fee** goes to the community pool (or is partially burned based on
  `fee_burn_bps`).

## Non-goals

- No token factory: Karsa tokens are `akra`, IBC vouchers, or ERC20 contracts.
- No rebasing or elastic supply.
- No protocol revenue share of AMM pool fees.

## Production checklist

1. Set the genesis account balances to the intended 100M allocation.
2. Use vesting accounts for developer/treasury buckets where applicable.
3. Confirm `blocks_per_year` against the measured block time.
4. Confirm `max_supply` and inflation parameters in the production genesis.
5. Publish the allocation and vesting schedule before launch.
