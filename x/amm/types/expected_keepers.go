package types

import (
	"context"

	sdkmath "cosmossdk.io/math"

	erc20types "github.com/cosmos/evm/x/erc20/types"
	"github.com/cosmos/evm/x/vm/statedb"

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
	GetDenomMetaData(ctx context.Context, denom string) (banktypes.Metadata, bool)
}

// Erc20Keeper resolves ERC20 addresses to token pairs and registers LP shares as
// ERC20 precompiles.
type Erc20Keeper interface {
	GetTokenPairID(ctx sdk.Context, token string) []byte
	GetTokenPair(ctx sdk.Context, id []byte) (erc20types.TokenPair, bool)
	IsDenomRegistered(ctx sdk.Context, denom string) bool
	IsERC20Registered(ctx sdk.Context, erc20 common.Address) bool
	IsERC20Enabled(ctx sdk.Context) bool
	SetToken(ctx sdk.Context, pair erc20types.TokenPair) error
	EnableDynamicPrecompile(ctx sdk.Context, address common.Address) error
	ConvertERC20IntoCoinsForNativeToken(
		ctx sdk.Context,
		stateDB *statedb.StateDB,
		contract common.Address,
		amount sdkmath.Int,
		receiver sdk.AccAddress,
		sender common.Address,
		commit bool,
		callFromPrecompile bool,
	) (*erc20types.MsgConvertERC20Response, error)
}

// EVMKeeper is the subset of the EVM keeper needed to move external ERC20
// tokens held by the module (direct custody).
type EVMKeeper interface {
	erc20types.EVMKeeper
}

// DistributionKeeper funds the community pool with the creation fee.
type DistributionKeeper interface {
	FundCommunityPool(ctx context.Context, amount sdk.Coins, sender sdk.AccAddress) error
}

// AccountKeeper registers the account of a pool's custody address.
//
// CallEVM reads the sender's sequence, so a custody address needs a base account
// before it can act as the `from` of an ERC20 transfer. Holding tokens in
// contract storage does not create a Cosmos account on its own.
type AccountKeeper interface {
	GetAccount(ctx context.Context, addr sdk.AccAddress) sdk.AccountI
	// NewAccountWithAddress assigns the next account number; constructing a base
	// account by hand reuses number 0 and collides with an existing account.
	NewAccountWithAddress(ctx context.Context, addr sdk.AccAddress) sdk.AccountI
	SetAccount(ctx context.Context, acc sdk.AccountI)
}
