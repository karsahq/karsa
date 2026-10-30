package keeper

import (
	"strconv"

	"github.com/karsahq/karsa/x/amm/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// SetPoolStatus changes a pool's operational status.
//
// With direct custody there is no external dependency to guard: a pool works as
// long as the token contracts accept transfers. Governance uses this as a manual
// brake; the custody invariant is handled separately (see CheckPool).
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

	pool.Status = status
	k.SetPool(ctx, pool)
	emitPoolStatus(ctx, pool)

	return nil
}

func emitPoolStatus(ctx sdk.Context, pool types.Pool) {
	ctx.EventManager().EmitEvent(sdk.NewEvent(
		types.EventTypePoolStatus,
		sdk.NewAttribute(types.AttributeKeyPoolID, strconv.FormatUint(pool.Id, 10)),
		sdk.NewAttribute(types.AttributeKeyStatus, pool.Status.String()),
	))
}
