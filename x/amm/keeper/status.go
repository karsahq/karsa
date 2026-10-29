package keeper

import (
	"strconv"

	"github.com/karsahq/karsa/x/amm/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// SetPoolStatus changes a pool's operational status.
func (k Keeper) SetPoolStatus(ctx sdk.Context, poolID uint64, status types.PoolStatus) error {
	pool, found := k.GetPool(ctx, poolID)
	if !found {
		return types.ErrPoolNotFound.Wrapf("pool %d", poolID)
	}

	switch status {
	case types.PoolStatus_ACTIVE, types.PoolStatus_WITHDRAW_ONLY:
	default:
		return types.ErrInvalidParams.Wrapf("unknown pool status %d", status)
	}

	if status == types.PoolStatus_ACTIVE {
		external, available := k.poolConversionStatus(ctx, pool)
		if external && !available {
			return types.ErrPoolInactive.Wrap("ERC20 conversion is not available for this pool")
		}
	}

	pool.Status = status
	k.SetPool(ctx, pool)
	emitPoolStatus(ctx, pool)
	return nil
}

// SyncPoolStatuses downgrades active pools that depend on ERC20 conversion when
// conversion becomes unavailable. It never upgrades a pool automatically.
func (k Keeper) SyncPoolStatuses(ctx sdk.Context) {
	k.IteratePools(ctx, func(pool types.Pool) bool {
		if pool.Status != types.PoolStatus_ACTIVE {
			return false
		}

		external, available := k.poolConversionStatus(ctx, pool)
		if external && !available {
			pool.Status = types.PoolStatus_WITHDRAW_ONLY
			k.SetPool(ctx, pool)
			emitPoolStatus(ctx, pool)
		}
		return false
	})
}

// poolConversionStatus reports whether the pool has an external ERC20 leg and
// whether conversion is currently available for all of its assets.
func (k Keeper) poolConversionStatus(ctx sdk.Context, pool types.Pool) (external, available bool) {
	available = k.erc20Keeper.IsERC20Enabled(ctx)

	for _, asset := range []string{pool.AssetA, pool.AssetB} {
		pairID := k.erc20Keeper.GetTokenPairID(ctx, asset)
		if len(pairID) == 0 {
			return true, false
		}

		pair, found := k.erc20Keeper.GetTokenPair(ctx, pairID)
		if !found {
			return true, false
		}
		if !pair.Enabled {
			available = false
		}
		if !pair.IsNativeCoin() {
			external = true
		}
	}

	return external, available
}

func emitPoolStatus(ctx sdk.Context, pool types.Pool) {
	ctx.EventManager().EmitEvent(sdk.NewEvent(
		types.EventTypePoolStatus,
		sdk.NewAttribute(types.AttributeKeyPoolID, strconv.FormatUint(pool.Id, 10)),
		sdk.NewAttribute(types.AttributeKeyStatus, pool.Status.String()),
	))
}
