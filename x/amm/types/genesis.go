package types

import "fmt"

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
		if pool.DenomA == "" || pool.DenomB == "" || pool.DenomA == pool.DenomB {
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
	}

	if gs.NextPoolId <= maxID {
		return fmt.Errorf("next_pool_id (%d) must be greater than every pool id (%d)", gs.NextPoolId, maxID)
	}

	return nil
}
