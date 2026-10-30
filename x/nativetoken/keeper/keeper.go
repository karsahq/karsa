package keeper

import (
	"fmt"

	"github.com/karsahq/karsa/x/nativetoken/types"

	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"

	"github.com/cosmos/cosmos-sdk/codec"
	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// Keeper manages native token issuance.
type Keeper struct {
	storeKey    storetypes.StoreKey
	cdc         codec.BinaryCodec
	bankKeeper  types.BankKeeper
	erc20Keeper types.Erc20Keeper
	evmKeeper   types.EVMKeeper
	distrKeeper types.DistributionKeeper
	authority   string
	moduleAddr  sdk.AccAddress
}

// NewKeeper creates a new nativetoken Keeper.
func NewKeeper(
	storeKey storetypes.StoreKey,
	cdc codec.BinaryCodec,
	bankKeeper types.BankKeeper,
	erc20Keeper types.Erc20Keeper,
	evmKeeper types.EVMKeeper,
	distrKeeper types.DistributionKeeper,
	authority string,
) Keeper {
	if _, err := sdk.AccAddressFromBech32(authority); err != nil {
		panic(fmt.Sprintf("invalid nativetoken authority address: %s", err))
	}

	return Keeper{
		storeKey:    storeKey,
		cdc:         cdc,
		bankKeeper:  bankKeeper,
		erc20Keeper: erc20Keeper,
		evmKeeper:   evmKeeper,
		distrKeeper: distrKeeper,
		authority:   authority,
		moduleAddr:  authtypes.NewModuleAddress(types.ModuleName),
	}
}

// Store returns the module store.
func (k Keeper) Store(ctx sdk.Context) storetypes.KVStore { return ctx.KVStore(k.storeKey) }

// Authority returns the address allowed to update module params and curation.
func (k Keeper) Authority() string { return k.authority }

// ModuleAddress returns the module account address, which mints initial supply.
func (k Keeper) ModuleAddress() sdk.AccAddress { return k.moduleAddr }
