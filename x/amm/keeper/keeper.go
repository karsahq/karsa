package keeper

import (
	"fmt"

	"github.com/karsahq/karsa/x/amm/types"

	"github.com/ethereum/go-ethereum/common"

	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"

	"github.com/cosmos/cosmos-sdk/codec"
	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// Keeper manages the amm module state.
type Keeper struct {
	storeKey      storetypes.StoreKey
	cdc           codec.BinaryCodec
	bankKeeper    types.BankKeeper
	erc20Keeper   types.Erc20Keeper
	evmKeeper     types.EVMKeeper
	distrKeeper   types.DistributionKeeper
	accountKeeper types.AccountKeeper
	authority     string
	moduleAddress common.Address
}

// NewKeeper creates a new amm Keeper.
func NewKeeper(
	storeKey storetypes.StoreKey,
	cdc codec.BinaryCodec,
	bankKeeper types.BankKeeper,
	erc20Keeper types.Erc20Keeper,
	evmKeeper types.EVMKeeper,
	distrKeeper types.DistributionKeeper,
	accountKeeper types.AccountKeeper,
	authority string,
) Keeper {
	if _, err := sdk.AccAddressFromBech32(authority); err != nil {
		panic(fmt.Sprintf("invalid amm authority address: %s", err))
	}

	return Keeper{
		storeKey:      storeKey,
		cdc:           cdc,
		bankKeeper:    bankKeeper,
		erc20Keeper:   erc20Keeper,
		evmKeeper:     evmKeeper,
		distrKeeper:   distrKeeper,
		accountKeeper: accountKeeper,
		authority:     authority,
		moduleAddress: common.BytesToAddress(authtypes.NewModuleAddress(types.ModuleName).Bytes()),
	}
}

// Authority returns the address allowed to update module params.
func (k Keeper) Authority() string { return k.authority }

// ModuleAddress returns the EVM address that holds external ERC20 reserves.
func (k Keeper) ModuleAddress() common.Address { return k.moduleAddress }

// Store returns the module store.
func (k Keeper) Store(ctx sdk.Context) storetypes.KVStore { return ctx.KVStore(k.storeKey) }

// acquireLock sets the reentrancy guard for the duration of a message. External
// ERC20 transfers execute contract code, so a hostile token could otherwise call
// back into the module while state is half-updated.
func (k Keeper) acquireLock(ctx sdk.Context) error {
	store := k.Store(ctx)
	if store.Has(types.ReentrancyKey) {
		return types.ErrReentrancy
	}

	store.Set(types.ReentrancyKey, []byte{1})
	return nil
}

// releaseLock clears the reentrancy guard.
func (k Keeper) releaseLock(ctx sdk.Context) {
	k.Store(ctx).Delete(types.ReentrancyKey)
}
