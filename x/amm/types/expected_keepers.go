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
	SendCoins(ctx context.Context, fromAddr, toAddr sdk.AccAddress, amt sdk.Coins) error
	SendCoinsFromAccountToModule(ctx context.Context, senderAddr sdk.AccAddress, recipientModule string, amt sdk.Coins) error
	SendCoinsFromModuleToAccount(ctx context.Context, senderModule string, recipientAddr sdk.AccAddress, amt sdk.Coins) error
	MintCoins(ctx context.Context, moduleName string, amt sdk.Coins) error
	BurnCoins(ctx context.Context, moduleName string, amt sdk.Coins) error
	SpendableCoins(ctx context.Context, addr sdk.AccAddress) sdk.Coins
	SetDenomMetaData(ctx context.Context, metadata banktypes.Metadata)
}

// Erc20Keeper resolves ERC20 addresses to token pairs and registers LP shares as
// ERC20 precompiles.
type Erc20Keeper interface {
	GetTokenPairID(ctx sdk.Context, token string) []byte
	GetTokenPair(ctx sdk.Context, id []byte) (erc20types.TokenPair, bool)
	IsDenomRegistered(ctx sdk.Context, denom string) bool
	IsERC20Registered(ctx sdk.Context, erc20 common.Address) bool
	SetToken(ctx sdk.Context, pair erc20types.TokenPair) error
	EnableDynamicPrecompile(ctx sdk.Context, address common.Address) error
}

// EVMKeeper is the subset of the EVM keeper needed to move external ERC20
// tokens held by the module (direct custody).
type EVMKeeper interface {
	erc20types.EVMKeeper
}
