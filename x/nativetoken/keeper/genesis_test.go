//go:build test

package keeper_test

import (
	"testing"

	sdkmath "cosmossdk.io/math"

	"github.com/stretchr/testify/require"
)

// ExportGenesis must carry the per-creator sequence counters. Addresses are
// derived from them, so losing them on re-import would let the next token reuse
// a sequence and collide with an existing address.
func TestGenesisRoundTripKeepsSequences(t *testing.T) {
	app, ctx := newTestApp(t)
	creator, _ := newContractCreator(t, app, ctx)

	first, err := app.NativeTokenKeeper.CreateNativeToken(
		ctx, creator, "Momo", "Momo", sdkmath.NewInt(1_000), "",
	)
	require.NoError(t, err)
	second, err := app.NativeTokenKeeper.CreateNativeToken(
		ctx, creator, "Mimi", "Mimi", sdkmath.NewInt(2_000), "",
	)
	require.NoError(t, err)

	genesis := app.NativeTokenKeeper.ExportGenesis(ctx)
	require.NoError(t, genesis.Validate())
	require.Len(t, genesis.Tokens, 2)
	require.Len(t, genesis.Sequences, 1)
	require.Equal(t, uint64(2), genesis.Sequences[0].Sequence)

	// A fresh app imports the exported state and must see the same tokens and
	// the same sequence counter.
	other, otherCtx := newTestApp(t)
	other.NativeTokenKeeper.InitGenesis(otherCtx, *genesis)

	imported, found := other.NativeTokenKeeper.GetToken(otherCtx, first.Denom)
	require.True(t, found)
	require.Equal(t, first, imported)

	byAddress, found := other.NativeTokenKeeper.GetTokenByAddress(otherCtx, second.Address)
	require.True(t, found)
	require.Equal(t, second.Denom, byAddress.Denom)

	require.Equal(t, uint64(2), other.NativeTokenKeeper.GetSequence(otherCtx, first.Creator))
	require.Len(t, other.NativeTokenKeeper.GetAllTokens(otherCtx), 2)

	// Re-exporting must produce the same state.
	reexported := other.NativeTokenKeeper.ExportGenesis(otherCtx)
	require.Equal(t, genesis.Tokens, reexported.Tokens)
	require.Equal(t, genesis.Sequences, reexported.Sequences)
}

func TestGenesisValidationRejectsBadEntries(t *testing.T) {
	app, ctx := newTestApp(t)
	creator, _ := newContractCreator(t, app, ctx)

	_, err := app.NativeTokenKeeper.CreateNativeToken(
		ctx, creator, "Momo", "Momo", sdkmath.NewInt(1_000), "",
	)
	require.NoError(t, err)

	genesis := app.NativeTokenKeeper.ExportGenesis(ctx)
	require.NoError(t, genesis.Validate())

	invalidDenom := *genesis
	invalidDenom.Tokens = append(invalidDenom.Tokens[:0:0], genesis.Tokens...)
	invalidDenom.Tokens[0].Denom = "not-a-native-denom"
	require.Error(t, invalidDenom.Validate())

	badSymbol := *genesis
	badSymbol.Tokens = append(badSymbol.Tokens[:0:0], genesis.Tokens...)
	badSymbol.Tokens[0].Symbol = "a"
	require.Error(t, badSymbol.Validate())

	duplicate := *genesis
	duplicate.Tokens = append(duplicate.Tokens[:0:0], genesis.Tokens...)
	duplicate.Tokens = append(duplicate.Tokens, genesis.Tokens[0])
	require.Error(t, duplicate.Validate())
}
