package types

import (
	"fmt"
	"slices"

	sdkmath "cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// Amplification bounds for stableswap pools.
const (
	MinAmplification uint64 = 1
	MaxAmplification uint64 = 1_000_000
)

// DefaultParams returns the default module parameters.
func DefaultParams() Params {
	return Params{
		MaxHops:             2,
		DefaultFeeBps:       30,
		MaxIntegratorFeeBps: 100,
		MinInitialLiquidity: sdkmath.NewInt(10_000),
		MinLockedShares:     sdkmath.NewInt(1_000),
		// Creation fee is a chain-level policy: 100 KRA. It matches
		// config.BaseDenom; the module cannot import the config package
		// without creating an import cycle.
		CreationFee: sdk.NewCoins(sdk.NewCoin("akra", sdkmath.NewIntWithDecimal(100, 18))),
		FeeBurnBps:  0,

		MaxPoolsPerPair:   6,
		CpFeeTiersBps:     []uint32{5, 10, 30},
		StableFeeTiersBps: []uint32{1, 3, 5},
		MaxFeeBps:         30,
		MaxTotalFeeBps:    130,
	}
}

// NewParams creates a new Params instance.
func NewParams(
	maxHops, defaultFeeBps, maxIntegratorFeeBps uint32,
	minInitialLiquidity, minLockedShares sdkmath.Int,
	creationFee sdk.Coins,
	feeBurnBps uint32,
	maxPoolsPerPair uint32,
	cpFeeTiersBps, stableFeeTiersBps []uint32,
	maxFeeBps, maxTotalFeeBps uint32,
) Params {
	return Params{
		MaxHops:             maxHops,
		DefaultFeeBps:       defaultFeeBps,
		MaxIntegratorFeeBps: maxIntegratorFeeBps,
		MinInitialLiquidity: minInitialLiquidity,
		MinLockedShares:     minLockedShares,
		CreationFee:         creationFee,
		FeeBurnBps:          feeBurnBps,

		MaxPoolsPerPair:   maxPoolsPerPair,
		CpFeeTiersBps:     slices.Clone(cpFeeTiersBps),
		StableFeeTiersBps: slices.Clone(stableFeeTiersBps),
		MaxFeeBps:         maxFeeBps,
		MaxTotalFeeBps:    maxTotalFeeBps,
	}
}

// FeeTiers returns the allowed fee tiers for a pool type.
func (p Params) FeeTiers(poolType PoolType) []uint32 {
	switch poolType {
	case PoolType_POOL_TYPE_CONSTANT_PRODUCT:
		return p.CpFeeTiersBps
	case PoolType_POOL_TYPE_STABLESWAP:
		return p.StableFeeTiersBps
	default:
		return nil
	}
}

// IsAllowedFeeBps reports whether feeBps is an allowed tier for poolType.
func (p Params) IsAllowedFeeBps(poolType PoolType, feeBps uint32) bool {
	return slices.Contains(p.FeeTiers(poolType), feeBps)
}

// Validate performs basic validation of the module parameters.
func (p Params) Validate() error {
	if p.MaxHops == 0 || p.MaxHops > 4 {
		return fmt.Errorf("max_hops must be in [1,4], got %d", p.MaxHops)
	}
	if p.MaxFeeBps == 0 || p.MaxFeeBps > 1_000 {
		return fmt.Errorf("max_fee_bps must be in [1,1000], got %d", p.MaxFeeBps)
	}
	if p.MaxIntegratorFeeBps > 1_000 {
		return fmt.Errorf("max_integrator_fee_bps must be <= 1000, got %d", p.MaxIntegratorFeeBps)
	}
	if p.MaxTotalFeeBps > 2_000 {
		return fmt.Errorf("max_total_fee_bps must be <= 2000, got %d", p.MaxTotalFeeBps)
	}
	if p.MaxTotalFeeBps < p.MaxFeeBps+p.MaxIntegratorFeeBps {
		return fmt.Errorf(
			"max_total_fee_bps (%d) must be >= max_fee_bps + max_integrator_fee_bps (%d)",
			p.MaxTotalFeeBps, p.MaxFeeBps+p.MaxIntegratorFeeBps,
		)
	}
	if err := validateFeeTiers("cp_fee_tiers_bps", p.CpFeeTiersBps, p.MaxFeeBps); err != nil {
		return err
	}
	if err := validateFeeTiers("stable_fee_tiers_bps", p.StableFeeTiersBps, p.MaxFeeBps); err != nil {
		return err
	}
	if !p.IsAllowedFeeBps(PoolType_POOL_TYPE_CONSTANT_PRODUCT, p.DefaultFeeBps) {
		return fmt.Errorf("default_fee_bps %d is not an allowed constant-product tier", p.DefaultFeeBps)
	}

	minPools := uint32(len(p.CpFeeTiersBps) + len(p.StableFeeTiersBps))
	if p.MaxPoolsPerPair < minPools {
		return fmt.Errorf(
			"max_pools_per_pair (%d) must be >= number of fee tiers (%d)",
			p.MaxPoolsPerPair, minPools,
		)
	}
	if p.MaxPoolsPerPair > 64 {
		return fmt.Errorf("max_pools_per_pair must be <= 64, got %d", p.MaxPoolsPerPair)
	}
	if !p.MinInitialLiquidity.IsPositive() {
		return fmt.Errorf("min_initial_liquidity must be positive")
	}
	if !p.MinLockedShares.IsPositive() {
		return fmt.Errorf("min_locked_shares must be positive")
	}
	if p.FeeBurnBps > 10_000 {
		return fmt.Errorf("fee_burn_bps must be <= 10000, got %d", p.FeeBurnBps)
	}
	if !p.CreationFee.IsValid() {
		return fmt.Errorf("invalid creation_fee %s", p.CreationFee)
	}

	return nil
}

func validateFeeTiers(name string, tiers []uint32, maxFee uint32) error {
	if len(tiers) == 0 {
		return fmt.Errorf("%s must not be empty", name)
	}

	for i, tier := range tiers {
		if tier == 0 || tier > 1_000 {
			return fmt.Errorf("%s[%d] must be in [1,1000], got %d", name, i, tier)
		}
		if tier > maxFee {
			return fmt.Errorf("%s[%d] = %d exceeds max_fee_bps %d", name, i, tier, maxFee)
		}
		if i > 0 && tier <= tiers[i-1] {
			return fmt.Errorf("%s must be strictly ascending, got %v", name, tiers)
		}
	}

	return nil
}
