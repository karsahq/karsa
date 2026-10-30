package keeper

import (
	"github.com/karsahq/karsa/x/nativetoken/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// GetParams returns the module params, falling back to defaults.
func (k Keeper) GetParams(ctx sdk.Context) types.Params {
	bz := k.Store(ctx).Get(types.ParamsKey)
	if bz == nil {
		return types.DefaultParams()
	}

	var params types.Params
	k.cdc.MustUnmarshal(bz, &params)

	return params
}

// SetParams stores the module params after validation.
func (k Keeper) SetParams(ctx sdk.Context, params types.Params) error {
	if err := params.Validate(); err != nil {
		return types.ErrInvalidParams.Wrap(err.Error())
	}

	k.Store(ctx).Set(types.ParamsKey, k.cdc.MustMarshal(&params))

	return nil
}
