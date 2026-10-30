package types

import (
	"fmt"
	"strconv"
)

// DefaultGenesisState returns the default genesis state of the module.
func DefaultGenesisState() *GenesisState {
	return &GenesisState{
		Params:     DefaultParams(),
		Pools:      []Pool{},
		NextPoolId: 1,
	}
}

// Validate performs basic validation of the genesis state.
func (gs GenesisState) Validate() error {
	if err := gs.Params.Validate(); err != nil {
		return err
	}

	seen := make(map[uint64]bool, len(gs.Pools))
	seenKey := make(map[string]bool, len(gs.Pools))
	pairCounts := make(map[string]uint32, len(gs.Pools))
	var maxID uint64

	for _, pool := range gs.Pools {
		if seen[pool.Id] {
			return fmt.Errorf("duplicate pool id %d", pool.Id)
		}
		seen[pool.Id] = true
		if pool.Id > maxID {
			maxID = pool.Id
		}

		if pool.AssetA == "" || pool.AssetB == "" {
			return fmt.Errorf("pool %d: assets must not be empty", pool.Id)
		}
		if pool.AssetA >= pool.AssetB {
			return fmt.Errorf("pool %d: assets must be sorted ascending", pool.Id)
		}
		// Denoms are bank metadata only. External ERC20 assets have no bank
		// denom, so an empty field is valid; only compare non-empty denoms.
		if pool.DenomA != "" && pool.DenomB != "" && pool.DenomA == pool.DenomB {
			return fmt.Errorf("pool %d: invalid denoms", pool.Id)
		}
		if !pool.ReserveA.IsPositive() || !pool.ReserveB.IsPositive() {
			return fmt.Errorf("pool %d: reserves must be positive", pool.Id)
		}
		if !pool.TotalShares.IsPositive() {
			return fmt.Errorf("pool %d: total shares must be positive", pool.Id)
		}
		if pool.LockedShares.IsNegative() || pool.LockedShares.GT(pool.TotalShares) {
			return fmt.Errorf("pool %d: invalid locked shares", pool.Id)
		}
		if pool.LpDenom != LPDenom(pool.Id) {
			return fmt.Errorf("pool %d: lp denom must be %q, got %q", pool.Id, LPDenom(pool.Id), pool.LpDenom)
		}

		pairKey := pool.AssetA + "|" + pool.AssetB
		uniqueKey := pairKey + "|" + strconv.Itoa(int(pool.PoolType)) + "|" +
			strconv.FormatUint(uint64(pool.FeeBps), 10)
		if seenKey[uniqueKey] {
			return fmt.Errorf("pool %d: duplicate (pair, type, fee) configuration", pool.Id)
		}
		seenKey[uniqueKey] = true

		pairCounts[pairKey]++
		if pairCounts[pairKey] > gs.Params.MaxPoolsPerPair {
			return fmt.Errorf(
				"pool %d: pair %s exceeds max_pools_per_pair %d",
				pool.Id, pairKey, gs.Params.MaxPoolsPerPair,
			)
		}

		switch pool.PoolType {
		case PoolType_POOL_TYPE_CONSTANT_PRODUCT:
			if pool.Amplification != 0 {
				return fmt.Errorf("pool %d: constant-product amplification must be 0", pool.Id)
			}
		case PoolType_POOL_TYPE_STABLESWAP:
			if pool.Amplification < MinAmplification || pool.Amplification > MaxAmplification {
				return fmt.Errorf("pool %d: amplification must be in [%d,%d], got %d",
					pool.Id, MinAmplification, MaxAmplification, pool.Amplification)
			}
		default:
			return fmt.Errorf("pool %d: unknown pool type %d", pool.Id, pool.PoolType)
		}

		if !gs.Params.IsAllowedFeeBps(pool.PoolType, pool.FeeBps) {
			return fmt.Errorf("pool %d: fee %d bps is not an allowed tier", pool.Id, pool.FeeBps)
		}

		switch pool.Status {
		case PoolStatus_ACTIVE, PoolStatus_WITHDRAW_ONLY:
		default:
			return fmt.Errorf("pool %d: unknown status %d", pool.Id, pool.Status)
		}
	}

	if gs.NextPoolId <= maxID {
		return fmt.Errorf("next_pool_id (%d) must be greater than every pool id (%d)", gs.NextPoolId, maxID)
	}

	return nil
}
