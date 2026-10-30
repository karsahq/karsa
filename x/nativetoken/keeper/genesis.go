package keeper

import (
	"github.com/karsahq/karsa/x/nativetoken/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// InitGenesis initializes the module state.
func (k Keeper) InitGenesis(ctx sdk.Context, gs types.GenesisState) {
	if err := k.SetParams(ctx, gs.Params); err != nil {
		panic(err)
	}

	for _, token := range gs.Tokens {
		k.SetToken(ctx, token)
	}

	for _, sequence := range gs.Sequences {
		k.SetSequence(ctx, sequence.Creator, sequence.Sequence)
	}
}

// ExportGenesis exports the module state.
//
// Sequences are part of the export: addresses are derived from them, so dropping
// them would let a re-import reuse a sequence and collide with an existing token.
func (k Keeper) ExportGenesis(ctx sdk.Context) *types.GenesisState {
	return &types.GenesisState{
		Params:    k.GetParams(ctx),
		Tokens:    k.GetAllTokens(ctx),
		Sequences: k.GetAllSequences(ctx),
	}
}
