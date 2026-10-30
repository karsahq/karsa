//go:build test

package keeper_test

import (
	"strings"
	"testing"

	ammtypes "github.com/karsahq/karsa/x/amm/types"

	testconstants "github.com/cosmos/evm/testutil/constants"
	erc20types "github.com/cosmos/evm/x/erc20/types"

	sdkmath "cosmossdk.io/math"

	"github.com/ethereum/go-ethereum/common"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

// A pool that will hold an external ERC20 directly needs a Cosmos account for
// its custody address. CallEVM reads the sender's sequence, and ERC20 balances
// alone do not create an account.
func TestCustodyAccountCreatedForExternalPool(t *testing.T) {
	app, ctx := newTestApp(t)

	deployer := common.HexToAddress("0x00000000000000000000000000000000000000EE")
	sender := sdk.AccAddress(deployer.Bytes())

	nativeCoins := sdk.NewCoins(sdk.NewCoin("akra", sdkmath.NewIntWithDecimal(1_000, 18)))
	require.NoError(t, app.BankKeeper.MintCoins(ctx, ammtypes.ModuleName, nativeCoins))
	require.NoError(t, app.BankKeeper.SendCoinsFromModuleToAccount(
		ctx, ammtypes.ModuleName, sender, nativeCoins,
	))

	token := deployTestERC20(t, app, ctx, deployer, "Momo", "MOMO", 18)
	mintTestERC20(t, app, ctx, token, deployer, sdkmath.NewInt(1_000_000))

	require.NoError(t, app.Erc20Keeper.SetToken(ctx, erc20types.NewTokenPair(
		token, "erc20:"+strings.ToLower(token.Hex()), erc20types.OWNER_EXTERNAL,
	)))

	akra := common.HexToAddress(testconstants.WEVMOSContractMainnet)

	poolID, _, err := app.AmmKeeper.CreatePool(
		ctx, sender, akra.Hex(), token.Hex(), 30,
		sdkmath.NewInt(100_000), sdkmath.NewInt(100_000),
	)
	require.NoError(t, err)

	custody := ammtypes.CustodyAddress(poolID)
	account := app.AccountKeeper.GetAccount(ctx, sdk.AccAddress(custody.Bytes()))
	require.NotNil(t, account, "custody account must exist for a direct-custody pool")
	require.False(t, app.EVMKeeper.IsContract(ctx, custody), "custody address has no code")
}

// A pool between two bank-canonical assets must not create a custody account.
func TestCustodyAccountSkippedForBankPool(t *testing.T) {
	app, ctx := newTestApp(t)
	registerTestUSDCPair(t, app, ctx)

	sender := sdk.AccAddress(common.HexToAddress("0x00000000000000000000000000000000000000AA").Bytes())
	fundTestDenoms(t, app, ctx, sender, sdkmath.NewIntWithDecimal(10_000, 18))

	akra := common.HexToAddress(testconstants.WEVMOSContractMainnet)

	poolID, _, err := app.AmmKeeper.CreatePool(
		ctx, sender, akra.Hex(), testUSDCPair.Hex(), 30,
		sdkmath.NewInt(100_000), sdkmath.NewInt(100_000),
	)
	require.NoError(t, err)

	custody := ammtypes.CustodyAddress(poolID)
	require.Nil(t, app.AccountKeeper.GetAccount(ctx, sdk.AccAddress(custody.Bytes())))
}
