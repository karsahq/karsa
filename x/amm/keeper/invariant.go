package keeper

import (
	"github.com/karsahq/karsa/x/amm/types"

	sdkmath "cosmossdk.io/math"

	"github.com/ethereum/go-ethereum/common"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// CheckPool verifies that each direct-custody side still holds at least the
// recorded reserve.
//
// A shortfall means the pool no longer owns what its reserves claim: a forced
// burn, a clawback by the token admin, an upgrade that wiped balances, or a
// negative rebase. Trading against a stale reserve would let the first trader
// take the remaining balance at a price the pool cannot honour, so the pool is
// downgraded to WITHDRAW_ONLY. Holders can still exit.
func (k Keeper) CheckPool(ctx sdk.Context, poolID uint64) (bool, error) {
	pool, found := k.GetPool(ctx, poolID)
	if !found {
		return false, types.ErrPoolNotFound.Wrapf("pool %d", poolID)
	}

	shortA, err := k.sideShort(ctx, poolID, pool.AssetA, pool.ReserveA)
	if err != nil {
		return false, err
	}
	shortB, err := k.sideShort(ctx, poolID, pool.AssetB, pool.ReserveB)
	if err != nil {
		return false, err
	}

	if !shortA && !shortB {
		return false, nil
	}

	if pool.Status != types.PoolStatus_WITHDRAW_ONLY {
		pool.Status = types.PoolStatus_WITHDRAW_ONLY
		k.SetPool(ctx, pool)
		emitPoolStatus(ctx, pool)
	}

	return true, nil
}

// sideShort reports whether a side's custody balance is below its reserve.
func (k Keeper) sideShort(
	ctx sdk.Context, poolID uint64, assetAddress string, reserve sdkmath.Int,
) (bool, error) {
	asset, err := k.resolveAsset(ctx, assetAddress)
	if err != nil {
		return false, err
	}
	if !asset.DirectCustody {
		return false, nil
	}

	balance, err := k.evmBalanceWith(
		ctx, nil, common.HexToAddress(asset.Address), types.CustodyAddress(poolID),
	)
	if err != nil {
		return false, err
	}

	return balance.LT(reserve), nil
}

// ensureCustodyHealthy is the cheap inline guard used before pulling funds in: the
// caller already paid for the balance read, so the check costs a single pool
// lookup. It downgrades the pool and fails the operation on a shortfall.
func (k Keeper) ensureCustodyHealthy(
	ctx sdk.Context, poolID uint64, asset resolvedAsset, balance sdkmath.Int,
) error {
	pool, found := k.GetPool(ctx, poolID)
	if !found {
		// The pool record does not exist yet during creation, where moveIn runs
		// before the pool is stored. There is no reserve to fall short of.
		return nil
	}

	reserve := pool.ReserveB
	if pool.AssetA == asset.Address {
		reserve = pool.ReserveA
	}

	if balance.GTE(reserve) {
		return nil
	}

	_ = k.SetPoolStatus(ctx, poolID, types.PoolStatus_WITHDRAW_ONLY)

	return types.ErrPoolInactive.Wrapf(
		"custody balance %s is below reserve %s; pool set to withdraw-only", balance, reserve,
	)
}
