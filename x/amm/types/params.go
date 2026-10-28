package types

import (
	"fmt"

	sdkmath "cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// DefaultParams returns the default module parameters.
func DefaultParams() Params {
	return Params{
		MaxHops:             2,
		DefaultFeeBps:       30,
		MaxIntegratorFeeBps: 100,
		MinInitialLiquidity: sdkmath.NewInt(10_000),
		MinLockedShares:     sdkmath.NewInt(1_000),
		CreationFee:         sdk.NewCoins(),
		FeeBurnBps:          0,
	}
}

// NewParams creates a new Params instance.
func NewParams(
	maxHops, defaultFeeBps, maxIntegratorFeeBps uint32,
	minInitialLiquidity, minLockedShares sdkmath.Int,
	creationFee sdk.Coins,
	feeBurnBps uint32,
) Params {
	return Params{
		MaxHops:             maxHops,
		DefaultFeeBps:       defaultFeeBps,
		MaxIntegratorFeeBps: maxIntegratorFeeBps,
		MinInitialLiquidity: minInitialLiquidity,
		MinLockedShares:     minLockedShares,
		CreationFee:         creationFee,
		FeeBurnBps:          feeBurnBps,
	}
}

// Validate performs basic validation of the module parameters.
func (p Params) Validate() error {
	if p.MaxHops == 0 || p.MaxHops > 4 {
		return fmt.Errorf("max_hops must be in [1,4], got %d", p.MaxHops)
	}
	if p.DefaultFeeBps > 1_000 {
		return fmt.Errorf("default_fee_bps must be <= 1000, got %d", p.DefaultFeeBps)
	}
	if p.MaxIntegratorFeeBps > 1_000 {
		return fmt.Errorf("max_integrator_fee_bps must be <= 1000, got %d", p.MaxIntegratorFeeBps)
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
