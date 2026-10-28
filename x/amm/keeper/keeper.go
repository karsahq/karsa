package keeper

import (
	"fmt"

	"github.com/karsahq/karsa/x/amm/types"

	"github.com/cosmos/cosmos-sdk/codec"
	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// Keeper manages the amm module state.
type Keeper struct {
	storeKey    storetypes.StoreKey
	cdc         codec.BinaryCodec
	bankKeeper  types.BankKeeper
	erc20Keeper types.Erc20Keeper
	authority   string
}

// NewKeeper creates a new amm Keeper.
func NewKeeper(
	storeKey storetypes.StoreKey,
	cdc codec.BinaryCodec,
	bankKeeper types.BankKeeper,
	erc20Keeper types.Erc20Keeper,
	authority string,
) Keeper {
	if _, err := sdk.AccAddressFromBech32(authority); err != nil {
		panic(fmt.Sprintf("invalid amm authority address: %s", err))
	}

	return Keeper{
		storeKey:    storeKey,
		cdc:         cdc,
		bankKeeper:  bankKeeper,
		erc20Keeper: erc20Keeper,
		authority:   authority,
	}
}

// Authority returns the address allowed to update module params.
func (k Keeper) Authority() string { return k.authority }

// Store returns the module store.
func (k Keeper) Store(ctx sdk.Context) storetypes.KVStore { return ctx.KVStore(k.storeKey) }
