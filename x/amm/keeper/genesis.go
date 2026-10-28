package keeper

import (
	"github.com/karsahq/karsa/x/amm/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// InitGenesis initializes the module state from genesis.
func (k Keeper) InitGenesis(ctx sdk.Context, gs types.GenesisState) {
	if err := k.SetParams(ctx, gs.Params); err != nil {
		panic(err)
	}

	for _, pool := range gs.Pools {
		k.SetPool(ctx, pool)
		k.SetPoolIDByAssets(ctx, pool.AssetA, pool.AssetB, pool.Id)
	}

	k.SetNextPoolID(ctx, gs.NextPoolId)
}

// ExportGenesis exports the module state.
func (k Keeper) ExportGenesis(ctx sdk.Context) types.GenesisState {
	var pools []types.Pool
	k.IteratePools(ctx, func(pool types.Pool) bool {
		pools = append(pools, pool)
		return false
	})

	return types.GenesisState{
		Params:     k.GetParams(ctx),
		Pools:      pools,
		NextPoolId: k.GetNextPoolID(ctx),
	}
}
