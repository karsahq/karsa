package types

import (
	"context"

	erc20types "github.com/cosmos/evm/x/erc20/types"

	"github.com/ethereum/go-ethereum/common"

	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// BankKeeper defines the subset of the bank keeper used by the module.
type BankKeeper interface {
	SendCoinsFromAccountToModule(ctx context.Context, senderAddr sdk.AccAddress, recipientModule string, amt sdk.Coins) error
	SendCoinsFromModuleToAccount(ctx context.Context, senderModule string, recipientAddr sdk.AccAddress, amt sdk.Coins) error
	MintCoins(ctx context.Context, moduleName string, amt sdk.Coins) error
	BurnCoins(ctx context.Context, moduleName string, amt sdk.Coins) error
	SpendableCoins(ctx context.Context, addr sdk.AccAddress) sdk.Coins
	SetDenomMetaData(ctx context.Context, metadata banktypes.Metadata)
	GetDenomMetaData(ctx context.Context, denom string) (banktypes.Metadata, bool)
}

// EVMKeeper is the subset of the EVM keeper used to validate controllers.
type EVMKeeper interface {
	IsContract(ctx sdk.Context, addr common.Address) bool
}

// Erc20Keeper registers native tokens as dynamic ERC20 precompiles.
type Erc20Keeper interface {
	IsERC20Registered(ctx sdk.Context, erc20 common.Address) bool
	IsDenomRegistered(ctx sdk.Context, denom string) bool
	SetToken(ctx sdk.Context, pair erc20types.TokenPair) error
	EnableDynamicPrecompile(ctx sdk.Context, address common.Address) error
}

// DistributionKeeper funds the community pool with the creation fee.
type DistributionKeeper interface {
	FundCommunityPool(ctx context.Context, amount sdk.Coins, sender sdk.AccAddress) error
}
