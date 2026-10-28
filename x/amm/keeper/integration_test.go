//go:build test

package keeper_test

import (
	"strings"
	"testing"

	karsa "github.com/karsahq/karsa"
	ammtypes "github.com/karsahq/karsa/x/amm/types"

	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"

	testconstants "github.com/cosmos/evm/testutil/constants"
	erc20types "github.com/cosmos/evm/x/erc20/types"
	evmtypes "github.com/cosmos/evm/x/vm/types"

	sdkmath "cosmossdk.io/math"

	"github.com/ethereum/go-ethereum/common"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/stretchr/testify/require"
)

const (
	testChainID    = "karsa_262144-1"
	testEVMChainID = uint64(262144)

	// A bank-backed test denom (stands in for USDC in tests).
	testUSDCDenom = "uusdc"
)

// testUSDCPair is the module-owned ERC20 address we assign to the test denom.
var testUSDCPair = common.HexToAddress("0x1000000000000000000000000000000000000001")

func newTestApp(t *testing.T) (*karsa.App, sdk.Context) {
	t.Helper()

	// cosmos/evm keeps process-wide EVM config; reset it before building a new app.
	// This requires running the tests with -tags=test.
	evmtypes.NewEVMConfigurator().ResetTestConfig()

	app := karsa.Setup(t, testChainID, testEVMChainID)
	ctx := app.NewContextLegacy(false, cmtproto.Header{Height: 1, ChainID: testChainID})

	return app, ctx
}

// fundTestDenoms mints the native denom and the test denom to the sender using
// the amm module account (which holds Minter permissions).
func fundTestDenoms(t *testing.T, app *karsa.App, ctx sdk.Context, sender sdk.AccAddress, amount sdkmath.Int) {
	t.Helper()

	coins := sdk.NewCoins(
		sdk.NewCoin(karsaNativeDenom(), amount),
		sdk.NewCoin(testUSDCDenom, amount),
	)

	require.NoError(t, app.BankKeeper.MintCoins(ctx, ammtypes.ModuleName, coins))
	require.NoError(t, app.BankKeeper.SendCoinsFromModuleToAccount(ctx, ammtypes.ModuleName, sender, coins))
}

// karsaNativeDenom returns the native bank denom used by the app.
func karsaNativeDenom() string {
	return "akra"
}

// registerTestUSDCPair registers the test denom as a module-owned token pair.
func registerTestUSDCPair(t *testing.T, app *karsa.App, ctx sdk.Context) {
	t.Helper()

	pair := erc20types.NewTokenPair(testUSDCPair, testUSDCDenom, erc20types.OWNER_MODULE)
	require.NoError(t, app.Erc20Keeper.SetToken(ctx, pair))
	require.NoError(t, app.Erc20Keeper.EnableDynamicPrecompile(ctx, testUSDCPair))
}

// TestCreatePoolAddRemoveAndSwap exercises the full pool lifecycle with two
// bank-backed assets: the native denom and a test denom.
func TestCreatePoolAddRemoveAndSwap(t *testing.T) {
	app, ctx := newTestApp(t)
	require.False(t, app.Erc20Keeper.IsDenomRegistered(ctx, testUSDCDenom))
	registerTestUSDCPair(t, app, ctx)

	sender := sdk.AccAddress(common.HexToAddress("0x00000000000000000000000000000000000000AA").Bytes())
	initial := sdkmath.NewInt(1_000_000_000)
	fundTestDenoms(t, app, ctx, sender, initial)

	akraAsset := common.HexToAddress(testconstants.WEVMOSContractMainnet)

	// --- create pool -------------------------------------------------------
	poolID, shares, err := app.AmmKeeper.CreatePool(
		ctx, sender, akraAsset.Hex(), testUSDCPair.Hex(), 30,
		sdkmath.NewInt(1_000_000), sdkmath.NewInt(1_000_000),
	)
	require.NoError(t, err)
	require.Equal(t, uint64(1), poolID)
	require.True(t, shares.IsPositive())

	pool, found := app.AmmKeeper.GetPool(ctx, poolID)
	require.True(t, found)
	// Assets are stored sorted ascending by lowercase address.
	akraLower := strings.ToLower(akraAsset.Hex())
	usdcLower := strings.ToLower(testUSDCPair.Hex())
	require.ElementsMatch(t,
		[]string{akraLower, usdcLower},
		[]string{pool.AssetA, pool.AssetB},
	)
	require.ElementsMatch(t,
		[]string{karsaNativeDenom(), testUSDCDenom},
		[]string{pool.DenomA, pool.DenomB},
	)
	require.NotEqual(t, pool.AssetA, pool.AssetB)
	require.True(t, pool.LockedShares.IsPositive())

	// LP shares must exist as a bank denom and be registered as an ERC20 precompile.
	lpDenom := ammtypes.LPDenom(poolID)
	require.Equal(t, lpDenom, pool.LpDenom)
	require.True(t, app.Erc20Keeper.IsDenomRegistered(ctx, lpDenom))
	require.True(t, app.Erc20Keeper.IsERC20Registered(ctx, ammtypes.LPAssetAddress(lpDenom)))
	require.Equal(t, strings.ToLower(ammtypes.LPAssetAddress(lpDenom).Hex()), pool.LpAssetId)

	lpBalance := app.BankKeeper.GetBalance(ctx, sender, lpDenom)
	require.Equal(t, shares, lpBalance.Amount)

	// --- add liquidity -----------------------------------------------------
	addedShares, err := app.AmmKeeper.AddLiquidity(
		ctx, sender, poolID,
		sdkmath.NewInt(500_000), sdkmath.NewInt(500_000), sdkmath.NewInt(1),
	)
	require.NoError(t, err)
	require.True(t, addedShares.IsPositive())

	// --- quote and swap ----------------------------------------------------
	path := []string{akraAsset.Hex(), testUSDCPair.Hex()}
	amountIn := sdkmath.NewInt(10_000)

	quoted, err := app.AmmKeeper.Quote(ctx, path, amountIn)
	require.NoError(t, err)
	require.True(t, quoted.IsPositive())

	usdcBefore := app.BankKeeper.GetBalance(ctx, sender, testUSDCDenom).Amount

	amountOut, integratorFee, err := app.AmmKeeper.Swap(
		ctx, sender, sender, path, amountIn, sdkmath.NewInt(1), nil, 0,
	)
	require.NoError(t, err)
	require.Equal(t, quoted, amountOut)
	require.True(t, integratorFee.IsZero())

	usdcAfter := app.BankKeeper.GetBalance(ctx, sender, testUSDCDenom).Amount
	require.Equal(t, usdcBefore.Add(amountOut), usdcAfter)

	// --- remove liquidity --------------------------------------------------
	removedA, removedB, err := app.AmmKeeper.RemoveLiquidity(
		ctx, sender, poolID, addedShares, sdkmath.NewInt(1), sdkmath.NewInt(1),
	)
	require.NoError(t, err)
	require.True(t, removedA.IsPositive())
	require.True(t, removedB.IsPositive())
}

// TestSwapWithIntegratorFee checks that the integrator fee is taken from the
// input token and capped by params.
func TestSwapWithIntegratorFee(t *testing.T) {
	app, ctx := newTestApp(t)
	registerTestUSDCPair(t, app, ctx)

	sender := sdk.AccAddress(common.HexToAddress("0x00000000000000000000000000000000000000BB").Bytes())
	integrator := sdk.AccAddress(common.HexToAddress("0x00000000000000000000000000000000000000CC").Bytes())
	fundTestDenoms(t, app, ctx, sender, sdkmath.NewInt(1_000_000_000))

	akraAsset := common.HexToAddress(testconstants.WEVMOSContractMainnet)
	_, _, err := app.AmmKeeper.CreatePool(
		ctx, sender, akraAsset.Hex(), testUSDCPair.Hex(), 30,
		sdkmath.NewInt(1_000_000), sdkmath.NewInt(1_000_000),
	)
	require.NoError(t, err)

	path := []string{akraAsset.Hex(), testUSDCPair.Hex()}
	amountIn := sdkmath.NewInt(100_000)

	_, _, err = app.AmmKeeper.Swap(ctx, sender, sender, path, amountIn, sdkmath.NewInt(1), integrator, 20)
	require.NoError(t, err)

	// 20 bps of the input goes to the integrator.
	expectedFee := amountIn.MulRaw(20).QuoRaw(10_000)
	require.Equal(t, expectedFee, app.BankKeeper.GetBalance(ctx, integrator, karsaNativeDenom()).Amount)

	// Fees above the cap are rejected.
	params := app.AmmKeeper.GetParams(ctx)
	_, _, err = app.AmmKeeper.Swap(
		ctx, sender, sender, path, amountIn, sdkmath.NewInt(1), integrator, params.MaxIntegratorFeeBps+1,
	)
	require.ErrorIs(t, err, ammtypes.ErrInvalidFee)
}

// TestExternalERC20IsRejected documents the current boundary: pools only accept
// bank-backed (module-owned) token pairs until direct custody is implemented.
func TestExternalERC20IsRejected(t *testing.T) {
	app, ctx := newTestApp(t)

	externalAddr := common.HexToAddress("0x2000000000000000000000000000000000000001")
	externalDenom := "erc20:" + strings.ToLower(externalAddr.Hex())
	require.NoError(t, app.Erc20Keeper.SetToken(ctx, erc20types.NewTokenPair(
		externalAddr, externalDenom, erc20types.OWNER_EXTERNAL,
	)))

	sender := sdk.AccAddress(common.HexToAddress("0x00000000000000000000000000000000000000DD").Bytes())
	akraAsset := common.HexToAddress(testconstants.WEVMOSContractMainnet)

	_, _, err := app.AmmKeeper.CreatePool(
		ctx, sender, akraAsset.Hex(), externalAddr.Hex(), 30,
		sdkmath.NewInt(1_000_000), sdkmath.NewInt(1_000_000),
	)
	require.ErrorIs(t, err, ammtypes.ErrUnsupportedAsset)
}
