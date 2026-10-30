package keeper

import (
	"strings"

	"github.com/karsahq/karsa/x/nativetoken/types"

	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// GetToken returns a token by denom.
func (k Keeper) GetToken(ctx sdk.Context, denom string) (types.Token, bool) {
	bz := k.Store(ctx).Get(types.TokenKey(denom))
	if bz == nil {
		return types.Token{}, false
	}

	var token types.Token
	k.cdc.MustUnmarshal(bz, &token)

	return token, true
}

// HasToken reports whether a denom is registered.
func (k Keeper) HasToken(ctx sdk.Context, denom string) bool {
	return k.Store(ctx).Has(types.TokenKey(denom))
}

// GetTokenByAddress returns a token by its lowercase 0x address.
func (k Keeper) GetTokenByAddress(ctx sdk.Context, address string) (types.Token, bool) {
	denom := k.Store(ctx).Get(types.AddressIndexKey(address))
	if denom == nil {
		return types.Token{}, false
	}

	return k.GetToken(ctx, string(denom))
}

// SetToken stores a token and refreshes its indexes.
func (k Keeper) SetToken(ctx sdk.Context, token types.Token) {
	store := k.Store(ctx)
	store.Set(types.TokenKey(token.Denom), k.cdc.MustMarshal(&token))
	store.Set(types.TokenListKey(token.Denom), []byte{})
	store.Set(types.AddressIndexKey(token.Address), []byte(token.Denom))
}

// GetSequence returns how many tokens a creator has issued.
func (k Keeper) GetSequence(ctx sdk.Context, creator string) uint64 {
	bz := k.Store(ctx).Get(types.SequenceKey(strings.ToLower(creator)))
	if bz == nil {
		return 0
	}

	return sdk.BigEndianToUint64(bz)
}

// SetSequence stores the sequence counter for a creator.
func (k Keeper) SetSequence(ctx sdk.Context, creator string, sequence uint64) {
	k.Store(ctx).Set(types.SequenceKey(strings.ToLower(creator)), sdk.Uint64ToBigEndian(sequence))
}

// IterateTokens walks every token. Returning true stops the iteration.
func (k Keeper) IterateTokens(ctx sdk.Context, cb func(types.Token) bool) {
	iterator := storetypes.KVStorePrefixIterator(k.Store(ctx), types.TokenListKeyPrefix)
	defer iterator.Close()

	for ; iterator.Valid(); iterator.Next() {
		denom := string(iterator.Key()[len(types.TokenListKeyPrefix):])
		token, found := k.GetToken(ctx, denom)
		if !found {
			continue
		}
		if cb(token) {
			return
		}
	}
}

// GetAllTokens returns every registered token.
func (k Keeper) GetAllTokens(ctx sdk.Context) []types.Token {
	tokens := []types.Token{}
	k.IterateTokens(ctx, func(token types.Token) bool {
		tokens = append(tokens, token)
		return false
	})

	return tokens
}

// GetAllSequences returns every creator sequence counter, for genesis export.
func (k Keeper) GetAllSequences(ctx sdk.Context) []types.CreatorSequence {
	sequences := []types.CreatorSequence{}

	iterator := storetypes.KVStorePrefixIterator(k.Store(ctx), types.SequenceKeyPrefix)
	defer iterator.Close()

	for ; iterator.Valid(); iterator.Next() {
		creator := string(iterator.Key()[len(types.SequenceKeyPrefix):])
		sequences = append(sequences, types.CreatorSequence{
			Creator:  creator,
			Sequence: sdk.BigEndianToUint64(iterator.Value()),
		})
	}

	return sequences
}
