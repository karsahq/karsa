//go:build test

package keeper_test

import (
	"math/big"
	"strings"
	"testing"
	"time"

	karsa "github.com/karsahq/karsa"
	ammkeeper "github.com/karsahq/karsa/x/amm/keeper"
	ammprecompile "github.com/karsahq/karsa/x/amm/precompile"
	ammtypes "github.com/karsahq/karsa/x/amm/types"

	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"

	contracts "github.com/cosmos/evm/contracts"
	testconstants "github.com/cosmos/evm/testutil/constants"
	erc20types "github.com/cosmos/evm/x/erc20/types"
	"github.com/cosmos/evm/x/vm/statedb"
	evmtypes "github.com/cosmos/evm/x/vm/types"

	sdkmath "cosmossdk.io/math"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/stretchr/testify/require"
)

const (
	testChainID    = "karsa_262144-1"
	testEVMChainID = uint64(262144)

	// A bank-backed test denom (stands in for USDC in tests).
	testUSDCDenom = "uusdc"
	// A second bank-backed test denom (stands in for USDT in tests).
	testUSDTDenom = "uusdt"
)

// testUSDCPair is the module-owned ERC20 address we assign to the test denom.
var testUSDCPair = common.HexToAddress("0x1000000000000000000000000000000000000001")

// testUSDTPair is the module-owned ERC20 address assigned to the USDT test denom.
var testUSDTPair = common.HexToAddress("0x1000000000000000000000000000000000000003")

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

// registerTestPair registers a bank denom as a module-owned token pair.
func registerTestPair(t *testing.T, app *karsa.App, ctx sdk.Context, pair common.Address, denom string) {
	t.Helper()

	tokenPair := erc20types.NewTokenPair(pair, denom, erc20types.OWNER_MODULE)
	require.NoError(t, app.Erc20Keeper.SetToken(ctx, tokenPair))
	require.NoError(t, app.Erc20Keeper.EnableDynamicPrecompile(ctx, pair))
}

// registerTestUSDCPair registers the test denom as a module-owned token pair.
func registerTestUSDCPair(t *testing.T, app *karsa.App, ctx sdk.Context) {
	t.Helper()
	registerTestPair(t, app, ctx, testUSDCPair, testUSDCDenom)
}

// TestCreatePoolAddRemoveAndSwap exercises the full pool lifecycle with two
// bank-backed assets: the native denom and a test denom.
func TestCreatePoolAddRemoveAndSwap(t *testing.T) {
	app, ctx := newTestApp(t)
	require.False(t, app.Erc20Keeper.IsDenomRegistered(ctx, testUSDCDenom))
	registerTestUSDCPair(t, app, ctx)

	sender := sdk.AccAddress(common.HexToAddress("0x00000000000000000000000000000000000000AA").Bytes())
	initial := sdkmath.NewIntWithDecimal(1_000, 18)
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
	fundTestDenoms(t, app, ctx, sender, sdkmath.NewIntWithDecimal(1_000, 18))

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

// TestSwapExactOut checks exact-output swaps: the receiver gets exactly the
// requested amount and the sender pays the quoted input, bounded by max_in.
func TestSwapExactOut(t *testing.T) {
	app, ctx := newTestApp(t)
	registerTestUSDCPair(t, app, ctx)

	sender := sdk.AccAddress(common.HexToAddress("0x00000000000000000000000000000000000000AD").Bytes())
	receiver := sdk.AccAddress(common.HexToAddress("0x00000000000000000000000000000000000000AE").Bytes())
	fundTestDenoms(t, app, ctx, sender, sdkmath.NewIntWithDecimal(1_000, 18))

	akraAsset := common.HexToAddress(testconstants.WEVMOSContractMainnet)
	_, _, err := app.AmmKeeper.CreatePool(
		ctx, sender, akraAsset.Hex(), testUSDCPair.Hex(), 30,
		sdkmath.NewInt(1_000_000), sdkmath.NewInt(1_000_000),
	)
	require.NoError(t, err)

	path := []string{akraAsset.Hex(), testUSDCPair.Hex()}
	amountOut := sdkmath.NewInt(9_000)

	quotedIn, err := app.AmmKeeper.QuoteExactOut(ctx, path, amountOut)
	require.NoError(t, err)
	require.True(t, quotedIn.IsPositive())

	// The bound is checked before any funds move.
	_, _, err = app.AmmKeeper.SwapExactOut(
		ctx, sender, receiver, path, amountOut, quotedIn.SubRaw(1), nil, 0,
	)
	require.ErrorIs(t, err, ammtypes.ErrSlippageExceeded)

	akraBefore := app.BankKeeper.GetBalance(ctx, sender, karsaNativeDenom()).Amount
	usdcBefore := app.BankKeeper.GetBalance(ctx, receiver, testUSDCDenom).Amount

	amountIn, integratorFee, err := app.AmmKeeper.SwapExactOut(
		ctx, sender, receiver, path, amountOut, quotedIn, nil, 0,
	)
	require.NoError(t, err)
	require.Equal(t, quotedIn, amountIn)
	require.True(t, integratorFee.IsZero())

	require.Equal(t, usdcBefore.Add(amountOut), app.BankKeeper.GetBalance(ctx, receiver, testUSDCDenom).Amount)
	require.Equal(t, akraBefore.Sub(amountIn), app.BankKeeper.GetBalance(ctx, sender, karsaNativeDenom()).Amount)
}

// TestSwapExactOutIntegratorFee checks that the integrator fee is grossed up on
// top of the pool input so it is a percentage of the total amount paid.
func TestSwapExactOutIntegratorFee(t *testing.T) {
	app, ctx := newTestApp(t)
	registerTestUSDCPair(t, app, ctx)

	sender := sdk.AccAddress(common.HexToAddress("0x00000000000000000000000000000000000000BA").Bytes())
	integrator := sdk.AccAddress(common.HexToAddress("0x00000000000000000000000000000000000000CA").Bytes())
	fundTestDenoms(t, app, ctx, sender, sdkmath.NewIntWithDecimal(1_000, 18))

	akraAsset := common.HexToAddress(testconstants.WEVMOSContractMainnet)
	_, _, err := app.AmmKeeper.CreatePool(
		ctx, sender, akraAsset.Hex(), testUSDCPair.Hex(), 30,
		sdkmath.NewInt(1_000_000), sdkmath.NewInt(1_000_000),
	)
	require.NoError(t, err)

	path := []string{akraAsset.Hex(), testUSDCPair.Hex()}
	amountOut := sdkmath.NewInt(9_000)

	poolNeed, err := app.AmmKeeper.QuoteExactOut(ctx, path, amountOut)
	require.NoError(t, err)

	feeBps := uint32(20)
	// fee = ceil(poolNeed * bps / (10_000 - bps))
	expectedFee := poolNeed.MulRaw(int64(feeBps)).AddRaw(10_000 - int64(feeBps) - 1).QuoRaw(10_000 - int64(feeBps))
	senderBefore := app.BankKeeper.GetBalance(ctx, sender, karsaNativeDenom()).Amount

	amountIn, integratorFee, err := app.AmmKeeper.SwapExactOut(
		ctx, sender, sender, path, amountOut, poolNeed.Add(expectedFee), integrator, feeBps,
	)
	require.NoError(t, err)
	require.Equal(t, expectedFee, integratorFee)
	require.Equal(t, poolNeed.Add(expectedFee), amountIn)
	require.Equal(t, expectedFee, app.BankKeeper.GetBalance(ctx, integrator, karsaNativeDenom()).Amount)
	require.Equal(t, senderBefore.Sub(amountIn), app.BankKeeper.GetBalance(ctx, sender, karsaNativeDenom()).Amount)
}

// TestSwapExactOutMultiHop exercises the backward pass over two pools.
func TestSwapExactOutMultiHop(t *testing.T) {
	app, ctx := newTestApp(t)
	registerTestUSDCPair(t, app, ctx)

	const momoDenom = "umomo"
	momoPair := common.HexToAddress("0x1000000000000000000000000000000000000002")
	require.NoError(t, app.Erc20Keeper.SetToken(
		ctx, erc20types.NewTokenPair(momoPair, momoDenom, erc20types.OWNER_MODULE),
	))
	require.NoError(t, app.Erc20Keeper.EnableDynamicPrecompile(ctx, momoPair))

	sender := sdk.AccAddress(common.HexToAddress("0x00000000000000000000000000000000000000BD").Bytes())
	receiver := sdk.AccAddress(common.HexToAddress("0x00000000000000000000000000000000000000CE").Bytes())
	fundTestDenoms(t, app, ctx, sender, sdkmath.NewIntWithDecimal(1_000, 18))

	momoCoins := sdk.NewCoins(sdk.NewCoin(momoDenom, sdkmath.NewIntWithDecimal(1_000, 18)))
	require.NoError(t, app.BankKeeper.MintCoins(ctx, ammtypes.ModuleName, momoCoins))
	require.NoError(t, app.BankKeeper.SendCoinsFromModuleToAccount(ctx, ammtypes.ModuleName, sender, momoCoins))

	akraAsset := common.HexToAddress(testconstants.WEVMOSContractMainnet)
	deposit := sdkmath.NewInt(1_000_000)
	_, _, err := app.AmmKeeper.CreatePool(
		ctx, sender, akraAsset.Hex(), testUSDCPair.Hex(), 30, deposit, deposit,
	)
	require.NoError(t, err)
	_, _, err = app.AmmKeeper.CreatePool(
		ctx, sender, testUSDCPair.Hex(), momoPair.Hex(), 30, deposit, deposit,
	)
	require.NoError(t, err)

	path := []string{akraAsset.Hex(), testUSDCPair.Hex(), momoPair.Hex()}
	amountOut := sdkmath.NewInt(5_000)

	quotedIn, err := app.AmmKeeper.QuoteExactOut(ctx, path, amountOut)
	require.NoError(t, err)

	akraBefore := app.BankKeeper.GetBalance(ctx, sender, karsaNativeDenom()).Amount
	momoBefore := app.BankKeeper.GetBalance(ctx, receiver, momoDenom).Amount

	amountIn, _, err := app.AmmKeeper.SwapExactOut(
		ctx, sender, receiver, path, amountOut, quotedIn, nil, 0,
	)
	require.NoError(t, err)
	require.Equal(t, quotedIn, amountIn)
	require.Equal(t, momoBefore.Add(amountOut), app.BankKeeper.GetBalance(ctx, receiver, momoDenom).Amount)
	require.Equal(t, akraBefore.Sub(amountIn), app.BankKeeper.GetBalance(ctx, sender, karsaNativeDenom()).Amount)
}

// fundDenom mints and sends an arbitrary coin to an account using the amm
// module account (which holds Minter permissions).
func fundDenom(t *testing.T, app *karsa.App, ctx sdk.Context, sender sdk.AccAddress, denom string, amount sdkmath.Int) {
	t.Helper()

	coins := sdk.NewCoins(sdk.NewCoin(denom, amount))
	require.NoError(t, app.BankKeeper.MintCoins(ctx, ammtypes.ModuleName, coins))
	require.NoError(t, app.BankKeeper.SendCoinsFromModuleToAccount(ctx, ammtypes.ModuleName, sender, coins))
}

// TestStableSwapPool exercises a two-asset stableswap pool with 6-decimal
// assets: creation, quote, exact-in and exact-out swaps.
func TestStableSwapPool(t *testing.T) {
	app, ctx := newTestApp(t)
	registerTestUSDCPair(t, app, ctx)
	registerTestPair(t, app, ctx, testUSDTPair, testUSDTDenom)

	sender := sdk.AccAddress(common.HexToAddress("0x00000000000000000000000000000000000000D1").Bytes())
	receiver := sdk.AccAddress(common.HexToAddress("0x00000000000000000000000000000000000000D2").Bytes())
	fundTestDenoms(t, app, ctx, sender, sdkmath.NewIntWithDecimal(1_000, 18))
	fundDenom(t, app, ctx, sender, testUSDTDenom, sdkmath.NewIntWithDecimal(1_000, 18))

	deposit := sdkmath.NewInt(1_000_000)
	poolID, _, err := app.AmmKeeper.CreatePoolWithType(
		ctx, sender, testUSDCPair.Hex(), testUSDTPair.Hex(), 3, deposit, deposit,
		ammtypes.PoolType_POOL_TYPE_STABLESWAP, 100,
	)
	require.NoError(t, err)

	pool, found := app.AmmKeeper.GetPool(ctx, poolID)
	require.True(t, found)
	require.Equal(t, ammtypes.PoolType_POOL_TYPE_STABLESWAP, pool.PoolType)
	require.Equal(t, uint64(100), pool.Amplification)
	// Both assets have 6 decimals, so the normalisation factor is 10^12.
	require.Equal(t, uint64(1_000_000_000_000), pool.ScalingFactorA)
	require.Equal(t, uint64(1_000_000_000_000), pool.ScalingFactorB)

	// The precompile must expose the stableswap configuration.
	getPoolInput, err := ammprecompile.ABI.Pack("getPool", testUSDCPair, testUSDTPair)
	require.NoError(t, err)

	stateDB := statedb.New(ctx, app.EVMKeeper, statedb.NewEmptyTxConfig())
	res, err := app.EVMKeeper.CallEVMWithData(
		ctx, stateDB, common.BytesToAddress(sender.Bytes()), &ammprecompile.Address, getPoolInput, false, false, nil,
	)
	require.NoError(t, err)
	require.False(t, res.Failed(), res.VmError)

	info, err := ammprecompile.ABI.Unpack("getPool", res.Ret)
	require.NoError(t, err)
	require.Len(t, info, 10)
	require.Equal(t, uint8(1), info[5], "pool type")
	require.Equal(t, uint64(100), info[6], "amplification")
	require.ElementsMatch(t,
		[]uint64{1_000_000_000_000, 1_000_000_000_000},
		[]uint64{info[7].(*big.Int).Uint64(), info[8].(*big.Int).Uint64()},
	)
	require.Equal(t, uint8(ammtypes.PoolStatus_ACTIVE), info[9], "status")

	path := []string{testUSDCPair.Hex(), testUSDTPair.Hex()}
	amountIn := sdkmath.NewInt(10_000)

	quoted, err := app.AmmKeeper.Quote(ctx, path, amountIn)
	require.NoError(t, err)
	// Constant product would return ~9_871; stableswap should stay near par.
	require.True(t, quoted.GT(sdkmath.NewInt(9_900)), "quote = %s", quoted)
	require.True(t, quoted.LT(amountIn), "quote = %s", quoted)

	usdtBefore := app.BankKeeper.GetBalance(ctx, receiver, testUSDTDenom).Amount
	usdcBefore := app.BankKeeper.GetBalance(ctx, sender, testUSDCDenom).Amount

	amountOut, _, err := app.AmmKeeper.Swap(
		ctx, sender, receiver, path, amountIn, sdkmath.NewInt(1), nil, 0,
	)
	require.NoError(t, err)
	require.Equal(t, quoted, amountOut)
	require.Equal(t, usdtBefore.Add(amountOut), app.BankKeeper.GetBalance(ctx, receiver, testUSDTDenom).Amount)
	require.Equal(t, usdcBefore.Sub(amountIn), app.BankKeeper.GetBalance(ctx, sender, testUSDCDenom).Amount)

	// Exact output.
	exactOut := sdkmath.NewInt(5_000)
	quotedIn, err := app.AmmKeeper.QuoteExactOut(ctx, path, exactOut)
	require.NoError(t, err)
	require.True(t, quotedIn.IsPositive())

	usdtBefore = app.BankKeeper.GetBalance(ctx, receiver, testUSDTDenom).Amount
	amountInUsed, _, err := app.AmmKeeper.SwapExactOut(
		ctx, sender, receiver, path, exactOut, quotedIn, nil, 0,
	)
	require.NoError(t, err)
	require.Equal(t, quotedIn, amountInUsed)
	require.Equal(t, usdtBefore.Add(exactOut), app.BankKeeper.GetBalance(ctx, receiver, testUSDTDenom).Amount)

	// The pool stays close to 1:1 after small swaps.
	priceA, priceB, _, err := app.AmmKeeper.Twap(ctx, poolID, 60)
	require.NoError(t, err)
	require.True(t, priceA.Sub(sdkmath.LegacyOneDec()).Abs().LT(sdkmath.LegacyNewDecWithPrec(1, 2)), "priceA = %s", priceA)
	require.True(t, priceB.Sub(sdkmath.LegacyOneDec()).Abs().LT(sdkmath.LegacyNewDecWithPrec(1, 2)), "priceB = %s", priceB)
}

// TestStableSwapMixedDecimals checks that scaling factors normalise an
// 18-decimal and a 6-decimal asset to the same unit.
func TestStableSwapMixedDecimals(t *testing.T) {
	app, ctx := newTestApp(t)
	registerTestUSDCPair(t, app, ctx)

	sender := sdk.AccAddress(common.HexToAddress("0x00000000000000000000000000000000000000D3").Bytes())
	fundTestDenoms(t, app, ctx, sender, sdkmath.NewIntWithDecimal(1_000, 18))

	akraAsset := common.HexToAddress(testconstants.WEVMOSContractMainnet)

	// 1e18 raw akra and 1e6 raw USDC are both one whole token after scaling.
	poolID, _, err := app.AmmKeeper.CreatePoolWithType(
		ctx, sender, akraAsset.Hex(), testUSDCPair.Hex(), 3,
		sdkmath.NewIntWithDecimal(1, 18), sdkmath.NewIntWithDecimal(1, 6),
		ammtypes.PoolType_POOL_TYPE_STABLESWAP, 100,
	)
	require.NoError(t, err)

	pool, found := app.AmmKeeper.GetPool(ctx, poolID)
	require.True(t, found)
	require.ElementsMatch(t,
		[]uint64{1, 1_000_000_000_000},
		[]uint64{pool.ScalingFactorA, pool.ScalingFactorB},
	)

	path := []string{testUSDCPair.Hex(), akraAsset.Hex()}
	amountIn := sdkmath.NewInt(10_000) // 0.01 USDC

	quoted, err := app.AmmKeeper.Quote(ctx, path, amountIn)
	require.NoError(t, err)
	maxOut := sdkmath.NewIntWithDecimal(1, 16) // 0.01 akra, in 18-decimal units
	require.True(t, quoted.GT(maxOut.MulRaw(99).QuoRaw(100)), "quote = %s", quoted)
	require.True(t, quoted.LT(maxOut), "quote = %s", quoted)

	usdcBefore := app.BankKeeper.GetBalance(ctx, sender, testUSDCDenom).Amount
	akraBefore := app.BankKeeper.GetBalance(ctx, sender, karsaNativeDenom()).Amount

	amountOut, _, err := app.AmmKeeper.Swap(
		ctx, sender, sender, path, amountIn, sdkmath.NewInt(1), nil, 0,
	)
	require.NoError(t, err)
	require.Equal(t, quoted, amountOut)
	require.Equal(t, usdcBefore.Sub(amountIn), app.BankKeeper.GetBalance(ctx, sender, testUSDCDenom).Amount)
	require.Equal(t, akraBefore.Add(amountOut), app.BankKeeper.GetBalance(ctx, sender, karsaNativeDenom()).Amount)
}

// TestCreatePoolFeeTiers checks fixed tier validation for both pool types.
func TestCreatePoolFeeTiers(t *testing.T) {
	app, ctx := newTestApp(t)
	registerTestUSDCPair(t, app, ctx)

	sender := sdk.AccAddress(common.HexToAddress("0x00000000000000000000000000000000000000D4").Bytes())
	fundTestDenoms(t, app, ctx, sender, sdkmath.NewIntWithDecimal(1_000, 18))

	akraAsset := common.HexToAddress(testconstants.WEVMOSContractMainnet)
	deposit := sdkmath.NewInt(1_000_000)

	// Constant product does not allow 7 bps.
	_, _, err := app.AmmKeeper.CreatePool(
		ctx, sender, akraAsset.Hex(), testUSDCPair.Hex(), 7, deposit, deposit,
	)
	require.ErrorIs(t, err, ammtypes.ErrInvalidFee)

	// Stableswap does not allow the constant-product 30 bps tier.
	_, _, err = app.AmmKeeper.CreatePoolWithType(
		ctx, sender, akraAsset.Hex(), testUSDCPair.Hex(), 30, deposit, deposit,
		ammtypes.PoolType_POOL_TYPE_STABLESWAP, 100,
	)
	require.ErrorIs(t, err, ammtypes.ErrInvalidFee)

	// 3 bps is the valid stableswap tier.
	_, _, err = app.AmmKeeper.CreatePoolWithType(
		ctx, sender, akraAsset.Hex(), testUSDCPair.Hex(), 3, deposit, deposit,
		ammtypes.PoolType_POOL_TYPE_STABLESWAP, 100,
	)
	require.NoError(t, err)
	require.Equal(t, uint32(1), app.AmmKeeper.CountPoolsForAssets(ctx, akraAsset.Hex(), testUSDCPair.Hex()))
}

// deployTestERC20 deploys the example ERC20 contract from the given address and
// returns its address.
func deployTestERC20(t *testing.T, app *karsa.App, ctx sdk.Context, deployer common.Address, name, symbol string, decimals uint8) common.Address {
	t.Helper()

	nonce, err := app.AccountKeeper.GetSequence(ctx, deployer.Bytes())
	require.NoError(t, err)
	expected := crypto.CreateAddress(deployer, nonce)

	ctorArgs, err := contracts.ERC20MinterBurnerDecimalsContract.ABI.Pack("", name, symbol, decimals)
	require.NoError(t, err)

	initCode := append(append([]byte{}, contracts.ERC20MinterBurnerDecimalsContract.Bin...), ctorArgs...)

	stateDB := statedb.New(ctx, app.EVMKeeper, statedb.NewEmptyTxConfig())
	_, err = app.EVMKeeper.CallEVMWithData(ctx, stateDB, deployer, nil, initCode, true, false, nil)
	require.NoError(t, err)
	require.True(t, app.EVMKeeper.IsContract(ctx, expected), "contract not deployed")

	return expected
}

func mintTestERC20(t *testing.T, app *karsa.App, ctx sdk.Context, token, to common.Address, amount sdkmath.Int) {
	t.Helper()

	stateDB := statedb.New(ctx, app.EVMKeeper, statedb.NewEmptyTxConfig())
	res, err := app.EVMKeeper.CallEVM(
		ctx, stateDB, contracts.ERC20MinterBurnerDecimalsContract.ABI, to, token, true, false, nil,
		"mint", to, amount.BigInt(),
	)
	require.NoError(t, err)
	require.False(t, res.Failed(), res.VmError)
}

func erc20BalanceOf(t *testing.T, app *karsa.App, ctx sdk.Context, token, account common.Address) sdkmath.Int {
	t.Helper()

	stateDB := statedb.New(ctx, app.EVMKeeper, statedb.NewEmptyTxConfig())
	res, err := app.EVMKeeper.CallEVM(
		ctx, stateDB, contracts.ERC20MinterBurnerDecimalsContract.ABI, app.AmmKeeper.ModuleAddress(), token, false, false, nil,
		"balanceOf", account,
	)
	require.NoError(t, err)
	require.False(t, res.Failed(), res.VmError)

	out, err := contracts.ERC20MinterBurnerDecimalsContract.ABI.Unpack("balanceOf", res.Ret)
	require.NoError(t, err)
	require.Len(t, out, 1)

	amount, ok := out[0].(*big.Int)
	require.True(t, ok)

	return sdkmath.NewIntFromBigInt(amount)
}

// TestCreationFee verifies the fee is charged on pool creation.
func TestCreationFee(t *testing.T) {
	app, ctx := newTestApp(t)
	registerTestUSDCPair(t, app, ctx)

	sender := sdk.AccAddress(common.HexToAddress("0x00000000000000000000000000000000000000AC").Bytes())
	fundTestDenoms(t, app, ctx, sender, sdkmath.NewIntWithDecimal(1_000, 18))

	params := app.AmmKeeper.GetParams(ctx)
	require.False(t, params.CreationFee.IsZero(), "creation fee should default to a positive amount")

	fee := params.CreationFee.AmountOf(karsaNativeDenom())
	require.True(t, fee.IsPositive())

	akraAsset := common.HexToAddress(testconstants.WEVMOSContractMainnet)
	deposit := sdkmath.NewInt(1_000_000)

	before := app.BankKeeper.GetBalance(ctx, sender, karsaNativeDenom()).Amount

	_, _, err := app.AmmKeeper.CreatePool(
		ctx, sender, akraAsset.Hex(), testUSDCPair.Hex(), 30, deposit, deposit,
	)
	require.NoError(t, err)

	after := app.BankKeeper.GetBalance(ctx, sender, karsaNativeDenom()).Amount
	require.Equal(t, before.Sub(fee).Sub(deposit), after)
}

// TestTwap checks the time-weighted price over a controlled window.
func TestTwap(t *testing.T) {
	app, ctx := newTestApp(t)
	registerTestUSDCPair(t, app, ctx)

	ctx = ctx.WithBlockTime(time.Unix(1_000, 0))

	sender := sdk.AccAddress(common.HexToAddress("0x00000000000000000000000000000000000000AB").Bytes())
	fundTestDenoms(t, app, ctx, sender, sdkmath.NewIntWithDecimal(1_000, 18))

	akraAsset := common.HexToAddress(testconstants.WEVMOSContractMainnet)
	poolID, _, err := app.AmmKeeper.CreatePool(
		ctx, sender, akraAsset.Hex(), testUSDCPair.Hex(), 30,
		sdkmath.NewInt(1_000_000), sdkmath.NewInt(1_000_000),
	)
	require.NoError(t, err)

	// Advance the clock and add liquidity at the same price (1:1).
	ctx = ctx.WithBlockTime(time.Unix(1_100, 0))
	_, err = app.AmmKeeper.AddLiquidity(
		ctx, sender, poolID, sdkmath.NewInt(1_000), sdkmath.NewInt(1_000), sdkmath.NewInt(1),
	)
	require.NoError(t, err)

	priceA, priceB, window, err := app.AmmKeeper.Twap(ctx, poolID, 100)
	require.NoError(t, err)
	require.Equal(t, int64(100), window)
	require.True(t, priceA.Equal(sdkmath.LegacyOneDec()), "priceA = %s", priceA)
	require.True(t, priceB.Equal(sdkmath.LegacyOneDec()), "priceB = %s", priceB)
}

// TestAmmPrecompile exercises the EVM-facing precompile: quote and swap.
func TestAmmPrecompile(t *testing.T) {
	app, ctx := newTestApp(t)
	registerTestUSDCPair(t, app, ctx)

	caller := common.HexToAddress("0x00000000000000000000000000000000000000F1")
	initial := sdkmath.NewIntWithDecimal(1_000, 18)
	fundTestDenoms(t, app, ctx, sdk.AccAddress(caller.Bytes()), initial)

	akraAsset := common.HexToAddress(testconstants.WEVMOSContractMainnet)
	_, _, err := app.AmmKeeper.CreatePool(
		ctx, sdk.AccAddress(caller.Bytes()), akraAsset.Hex(), testUSDCPair.Hex(), 30,
		sdkmath.NewInt(1_000_000), sdkmath.NewInt(1_000_000),
	)
	require.NoError(t, err)

	path := []common.Address{akraAsset, testUSDCPair}
	amountIn := big.NewInt(10_000)

	// --- quote through the precompile -------------------------------------
	quoteInput, err := ammprecompile.ABI.Pack("quote", path, []uint64{}, amountIn)
	require.NoError(t, err)

	stateDB := statedb.New(ctx, app.EVMKeeper, statedb.NewEmptyTxConfig())
	res, err := app.EVMKeeper.CallEVMWithData(ctx, stateDB, caller, &ammprecompile.Address, quoteInput, false, false, nil)
	require.NoError(t, err)
	require.False(t, res.Failed(), res.VmError)

	quoteOut, err := ammprecompile.ABI.Unpack("quote", res.Ret)
	require.NoError(t, err)
	require.Len(t, quoteOut, 1)

	expectedQuote, err := app.AmmKeeper.Quote(ctx, []string{akraAsset.Hex(), testUSDCPair.Hex()}, sdkmath.NewIntFromBigInt(amountIn))
	require.NoError(t, err)
	require.Equal(t, expectedQuote.BigInt(), quoteOut[0].(*big.Int))

	// --- swap through the precompile --------------------------------------
	before := app.BankKeeper.GetBalance(ctx, sdk.AccAddress(caller.Bytes()), testUSDCDenom).Amount

	swapInput, err := ammprecompile.ABI.Pack(
		"swapExactIn", path, []uint64{}, amountIn, big.NewInt(1), common.Address{}, common.Address{}, big.NewInt(0),
	)
	require.NoError(t, err)

	stateDB = statedb.New(ctx, app.EVMKeeper, statedb.NewEmptyTxConfig())
	res, err = app.EVMKeeper.CallEVMWithData(ctx, stateDB, caller, &ammprecompile.Address, swapInput, true, false, nil)
	require.NoError(t, err)
	require.False(t, res.Failed(), res.VmError)

	swapOut, err := ammprecompile.ABI.Unpack("swapExactIn", res.Ret)
	require.NoError(t, err)
	require.Len(t, swapOut, 2)

	amountOut := swapOut[0].(*big.Int)
	require.Equal(t, expectedQuote.BigInt(), amountOut)

	after := app.BankKeeper.GetBalance(ctx, sdk.AccAddress(caller.Bytes()), testUSDCDenom).Amount
	require.Equal(t, before.Add(sdkmath.NewIntFromBigInt(amountOut)), after)
}

// TestAmmPrecompileExternal exercises auto-conversion through the EVM precompile:
// bank -> ERC20 output and ERC20 -> bank input.
func TestAmmPrecompileExternal(t *testing.T) {
	app, ctx := newTestApp(t)

	caller := common.HexToAddress("0x00000000000000000000000000000000000000F2")
	nativeCoins := sdk.NewCoins(sdk.NewCoin(karsaNativeDenom(), sdkmath.NewIntWithDecimal(1_000, 18)))
	require.NoError(t, app.BankKeeper.MintCoins(ctx, ammtypes.ModuleName, nativeCoins))
	require.NoError(t, app.BankKeeper.SendCoinsFromModuleToAccount(
		ctx, ammtypes.ModuleName, sdk.AccAddress(caller.Bytes()), nativeCoins,
	))

	token := deployTestERC20(t, app, ctx, caller, "Momo", "MOMO", 18)
	mintTestERC20(t, app, ctx, token, caller, sdkmath.NewInt(1_000_000))

	denom := "erc20:" + strings.ToLower(token.Hex())
	require.NoError(t, app.Erc20Keeper.SetToken(ctx, erc20types.NewTokenPair(
		token, denom, erc20types.OWNER_EXTERNAL,
	)))

	akraAsset := common.HexToAddress(testconstants.WEVMOSContractMainnet)
	sender := sdk.AccAddress(caller.Bytes())
	_, _, err := app.AmmKeeper.CreatePool(
		ctx, sender, akraAsset.Hex(), token.Hex(), 30,
		sdkmath.NewInt(100_000), sdkmath.NewInt(100_000),
	)
	require.NoError(t, err)

	amountIn := big.NewInt(1_000)

	// Bank -> ERC20: output conversion inside the precompile.
	tokenBefore := erc20BalanceOf(t, app, ctx, token, caller)
	outPath := []common.Address{akraAsset, token}
	outInput, err := ammprecompile.ABI.Pack(
		"swapExactIn", outPath, []uint64{}, amountIn, big.NewInt(1), common.Address{}, common.Address{}, big.NewInt(0),
	)
	require.NoError(t, err)

	stateDB := statedb.New(ctx, app.EVMKeeper, statedb.NewEmptyTxConfig())
	res, err := app.EVMKeeper.CallEVMWithData(ctx, stateDB, caller, &ammprecompile.Address, outInput, true, false, nil)
	require.NoError(t, err)
	require.False(t, res.Failed(), res.VmError)

	out, err := ammprecompile.ABI.Unpack("swapExactIn", res.Ret)
	require.NoError(t, err)
	amountOut := out[0].(*big.Int)
	require.True(t, amountOut.Sign() > 0)
	require.Equal(t, tokenBefore.Add(sdkmath.NewIntFromBigInt(amountOut)), erc20BalanceOf(t, app, ctx, token, caller))

	// ERC20 -> bank: input conversion inside the precompile.
	akraBefore := app.BankKeeper.GetBalance(ctx, sender, karsaNativeDenom()).Amount
	inPath := []common.Address{token, akraAsset}
	inInput, err := ammprecompile.ABI.Pack(
		"swapExactIn", inPath, []uint64{}, amountIn, big.NewInt(1), common.Address{}, common.Address{}, big.NewInt(0),
	)
	require.NoError(t, err)

	stateDB = statedb.New(ctx, app.EVMKeeper, statedb.NewEmptyTxConfig())
	res, err = app.EVMKeeper.CallEVMWithData(ctx, stateDB, caller, &ammprecompile.Address, inInput, true, false, nil)
	require.NoError(t, err)
	require.False(t, res.Failed(), res.VmError)

	out, err = ammprecompile.ABI.Unpack("swapExactIn", res.Ret)
	require.NoError(t, err)
	akraOut := out[0].(*big.Int)
	require.True(t, akraOut.Sign() > 0)
	require.Equal(t, akraBefore.Add(sdkmath.NewIntFromBigInt(akraOut)),
		app.BankKeeper.GetBalance(ctx, sender, karsaNativeDenom()).Amount)
}

// TestMultiPoolRouting exercises several fee-tier pools for the same pair.
func TestMultiPoolRouting(t *testing.T) {
	app, ctx := newTestApp(t)
	registerTestUSDCPair(t, app, ctx)

	sender := sdk.AccAddress(common.HexToAddress("0x00000000000000000000000000000000000000D5").Bytes())
	fundTestDenoms(t, app, ctx, sender, sdkmath.NewIntWithDecimal(1_000, 18))

	akraAsset := common.HexToAddress(testconstants.WEVMOSContractMainnet)
	deposit := sdkmath.NewInt(1_000_000)

	pool5, _, err := app.AmmKeeper.CreatePool(
		ctx, sender, akraAsset.Hex(), testUSDCPair.Hex(), 5, deposit, deposit,
	)
	require.NoError(t, err)
	pool10, _, err := app.AmmKeeper.CreatePool(
		ctx, sender, akraAsset.Hex(), testUSDCPair.Hex(), 10, deposit, deposit,
	)
	require.NoError(t, err)
	pool30, _, err := app.AmmKeeper.CreatePool(
		ctx, sender, akraAsset.Hex(), testUSDCPair.Hex(), 30, deposit, deposit,
	)
	require.NoError(t, err)

	require.Equal(t, uint32(3), app.AmmKeeper.CountPoolsForAssets(ctx, akraAsset.Hex(), testUSDCPair.Hex()))
	require.ElementsMatch(t,
		[]uint64{pool5, pool10, pool30},
		app.AmmKeeper.GetPoolIDsByAssets(ctx, akraAsset.Hex(), testUSDCPair.Hex()),
	)

	// The same (pair, type, fee) cannot be created twice.
	_, _, err = app.AmmKeeper.CreatePool(
		ctx, sender, akraAsset.Hex(), testUSDCPair.Hex(), 10, deposit, deposit,
	)
	require.ErrorIs(t, err, ammtypes.ErrPoolExists)

	path := []string{akraAsset.Hex(), testUSDCPair.Hex()}
	amountIn := sdkmath.NewInt(10_000)

	quoted, err := app.AmmKeeper.QuoteWithPools(ctx, path, []uint64{pool5}, amountIn)
	require.NoError(t, err)
	require.True(t, quoted.IsPositive())

	// The precompile accepts the same explicit pool id.
	quoteInput, err := ammprecompile.ABI.Pack(
		"quote", []common.Address{akraAsset, testUSDCPair}, []uint64{pool5}, amountIn.BigInt(),
	)
	require.NoError(t, err)
	quoteStateDB := statedb.New(ctx, app.EVMKeeper, statedb.NewEmptyTxConfig())
	quoteRes, err := app.EVMKeeper.CallEVMWithData(
		ctx, quoteStateDB, common.BytesToAddress(sender.Bytes()), &ammprecompile.Address, quoteInput, false, false, nil,
	)
	require.NoError(t, err)
	require.False(t, quoteRes.Failed(), quoteRes.VmError)
	quoteOut, err := ammprecompile.ABI.Unpack("quote", quoteRes.Ret)
	require.NoError(t, err)
	require.Equal(t, quoted.BigInt(), quoteOut[0].(*big.Int))

	// Empty poolIds auto-selects the best single pool in the precompile too.
	autoInput, err := ammprecompile.ABI.Pack(
		"quote", []common.Address{akraAsset, testUSDCPair}, []uint64{}, amountIn.BigInt(),
	)
	require.NoError(t, err)
	autoStateDB := statedb.New(ctx, app.EVMKeeper, statedb.NewEmptyTxConfig())
	autoRes, err := app.EVMKeeper.CallEVMWithData(
		ctx, autoStateDB, common.BytesToAddress(sender.Bytes()), &ammprecompile.Address, autoInput, false, false, nil,
	)
	require.NoError(t, err)
	require.False(t, autoRes.Failed(), autoRes.VmError)
	autoOut, err := ammprecompile.ABI.Unpack("quote", autoRes.Ret)
	require.NoError(t, err)
	require.Equal(t, quoted.BigInt(), autoOut[0].(*big.Int))

	// Discovery: getPools lists all fee tiers, getPoolById returns one pool.
	poolsInput, err := ammprecompile.ABI.Pack("getPools", akraAsset, testUSDCPair)
	require.NoError(t, err)
	poolsStateDB := statedb.New(ctx, app.EVMKeeper, statedb.NewEmptyTxConfig())
	poolsRes, err := app.EVMKeeper.CallEVMWithData(
		ctx, poolsStateDB, common.BytesToAddress(sender.Bytes()), &ammprecompile.Address, poolsInput, false, false, nil,
	)
	require.NoError(t, err)
	require.False(t, poolsRes.Failed(), poolsRes.VmError)
	poolsOut, err := ammprecompile.ABI.Unpack("getPools", poolsRes.Ret)
	require.NoError(t, err)
	require.ElementsMatch(t, []uint64{pool5, pool10, pool30}, poolsOut[0].([]uint64))

	byIDInput, err := ammprecompile.ABI.Pack("getPoolById", pool5)
	require.NoError(t, err)
	byIDStateDB := statedb.New(ctx, app.EVMKeeper, statedb.NewEmptyTxConfig())
	byIDRes, err := app.EVMKeeper.CallEVMWithData(
		ctx, byIDStateDB, common.BytesToAddress(sender.Bytes()), &ammprecompile.Address, byIDInput, false, false, nil,
	)
	require.NoError(t, err)
	require.False(t, byIDRes.Failed(), byIDRes.VmError)
	byIDOut, err := ammprecompile.ABI.Unpack("getPoolById", byIDRes.Ret)
	require.NoError(t, err)
	require.Len(t, byIDOut, 10)
	require.Equal(t, pool5, byIDOut[0].(uint64))
	require.Equal(t, uint8(ammtypes.PoolStatus_ACTIVE), byIDOut[9].(uint8))

	// Ambiguous route without pool ids is resolved by auto-best selection.
	autoQuoted, err := app.AmmKeeper.Quote(ctx, path, amountIn)
	require.NoError(t, err)
	require.Equal(t, quoted, autoQuoted)

	exactOut := sdkmath.NewInt(5_000)
	autoExactIn, err := app.AmmKeeper.QuoteExactOut(ctx, path, exactOut)
	require.NoError(t, err)
	explicitExactIn, err := app.AmmKeeper.QuoteExactOutWithPools(ctx, path, []uint64{pool5}, exactOut)
	require.NoError(t, err)
	require.Equal(t, explicitExactIn, autoExactIn)

	before5, found := app.AmmKeeper.GetPool(ctx, pool5)
	require.True(t, found)
	before10, found := app.AmmKeeper.GetPool(ctx, pool10)
	require.True(t, found)
	before30, found := app.AmmKeeper.GetPool(ctx, pool30)
	require.True(t, found)

	_, _, err = app.AmmKeeper.Swap(
		ctx, sender, sender, path, amountIn, sdkmath.NewInt(1), nil, 0,
	)
	require.NoError(t, err)

	after10, found := app.AmmKeeper.GetPool(ctx, pool10)
	require.True(t, found)
	after30, found := app.AmmKeeper.GetPool(ctx, pool30)
	require.True(t, found)
	require.Equal(t, before10.ReserveA, after10.ReserveA)
	require.Equal(t, before10.ReserveB, after10.ReserveB)
	require.Equal(t, before30.ReserveA, after30.ReserveA)
	require.Equal(t, before30.ReserveB, after30.ReserveB)

	after5, found := app.AmmKeeper.GetPool(ctx, pool5)
	require.True(t, found)
	require.NotEqual(t, before5.ReserveA, after5.ReserveA)
}

// TestPoolStatusTransitions checks ACTIVE / WITHDRAW_ONLY behavior.
func TestPoolStatusTransitions(t *testing.T) {
	app, ctx := newTestApp(t)
	registerTestUSDCPair(t, app, ctx)

	sender := sdk.AccAddress(common.HexToAddress("0x00000000000000000000000000000000000000D6").Bytes())
	fundTestDenoms(t, app, ctx, sender, sdkmath.NewIntWithDecimal(1_000, 18))

	akraAsset := common.HexToAddress(testconstants.WEVMOSContractMainnet)
	deposit := sdkmath.NewInt(1_000_000)
	poolID, shares, err := app.AmmKeeper.CreatePool(
		ctx, sender, akraAsset.Hex(), testUSDCPair.Hex(), 30, deposit, deposit,
	)
	require.NoError(t, err)

	path := []string{akraAsset.Hex(), testUSDCPair.Hex()}

	msgSrv := ammkeeper.NewMsgServerImpl(app.AmmKeeper)
	_, err = msgSrv.SetPoolStatus(ctx, &ammtypes.MsgSetPoolStatus{
		Authority: sender.String(), PoolId: poolID, Status: ammtypes.PoolStatus_WITHDRAW_ONLY,
	})
	require.ErrorIs(t, err, ammtypes.ErrUnauthorized)

	_, err = msgSrv.SetPoolStatus(ctx, &ammtypes.MsgSetPoolStatus{
		Authority: app.AmmKeeper.Authority(), PoolId: poolID, Status: ammtypes.PoolStatus_WITHDRAW_ONLY,
	})
	require.NoError(t, err)

	_, _, err = app.AmmKeeper.Swap(
		ctx, sender, sender, path, sdkmath.NewInt(10_000), sdkmath.NewInt(1), nil, 0,
	)
	require.ErrorIs(t, err, ammtypes.ErrPoolInactive)

	_, err = app.AmmKeeper.AddLiquidity(ctx, sender, poolID, sdkmath.NewInt(1_000), sdkmath.NewInt(1_000), sdkmath.NewInt(1))
	require.ErrorIs(t, err, ammtypes.ErrPoolInactive)

	// Withdrawals stay available in WITHDRAW_ONLY.
	_, _, err = app.AmmKeeper.RemoveLiquidity(ctx, sender, poolID, shares, sdkmath.ZeroInt(), sdkmath.ZeroInt())
	require.NoError(t, err)

	// There is no CLOSED state; governance can reactivate the pool.
	require.NoError(t, app.AmmKeeper.SetPoolStatus(ctx, poolID, ammtypes.PoolStatus_ACTIVE))
	require.ErrorIs(t,
		app.AmmKeeper.SetPoolStatus(ctx, poolID, ammtypes.PoolStatus(99)),
		ammtypes.ErrInvalidParams,
	)
}

// TestSyncPoolStatuses checks that disabling an external token pair downgrades
// the pool to WITHDRAW_ONLY automatically.
func TestSyncPoolStatuses(t *testing.T) {
	app, ctx := newTestApp(t)

	deployer := common.HexToAddress("0x00000000000000000000000000000000000000D7")
	nativeCoins := sdk.NewCoins(sdk.NewCoin(karsaNativeDenom(), sdkmath.NewIntWithDecimal(1_000, 18)))
	require.NoError(t, app.BankKeeper.MintCoins(ctx, ammtypes.ModuleName, nativeCoins))
	require.NoError(t, app.BankKeeper.SendCoinsFromModuleToAccount(
		ctx, ammtypes.ModuleName, sdk.AccAddress(deployer.Bytes()), nativeCoins,
	))

	token := deployTestERC20(t, app, ctx, deployer, "Momo", "MOMO", 18)
	mintTestERC20(t, app, ctx, token, deployer, sdkmath.NewInt(1_000_000))

	denom := "erc20:" + strings.ToLower(token.Hex())
	require.NoError(t, app.Erc20Keeper.SetToken(ctx, erc20types.NewTokenPair(
		token, denom, erc20types.OWNER_EXTERNAL,
	)))

	akraAsset := common.HexToAddress(testconstants.WEVMOSContractMainnet)
	sender := sdk.AccAddress(deployer.Bytes())
	poolID, _, err := app.AmmKeeper.CreatePool(
		ctx, sender, akraAsset.Hex(), token.Hex(), 30,
		sdkmath.NewInt(100_000), sdkmath.NewInt(100_000),
	)
	require.NoError(t, err)

	params := app.Erc20Keeper.GetParams(ctx)
	params.EnableErc20 = false
	require.NoError(t, app.Erc20Keeper.SetParams(ctx, params))

	app.AmmKeeper.SyncPoolStatuses(ctx)

	pool, found := app.AmmKeeper.GetPool(ctx, poolID)
	require.True(t, found)
	require.Equal(t, ammtypes.PoolStatus_WITHDRAW_ONLY, pool.Status)

	require.ErrorIs(t, app.AmmKeeper.SetPoolStatus(ctx, poolID, ammtypes.PoolStatus_ACTIVE), ammtypes.ErrPoolInactive)
	_, _, err = app.AmmKeeper.Swap(
		ctx, sender, sender, []string{akraAsset.Hex(), token.Hex()},
		sdkmath.NewInt(1_000), sdkmath.NewInt(1), nil, 0,
	)
	require.ErrorIs(t, err, ammtypes.ErrPoolInactive)
}

// TestExternalERC20Pool exercises bank-backed custody: the pool holds the
// erc20:0x… bank denom while x/erc20 escrows the contract tokens.
func TestExternalERC20Pool(t *testing.T) {
	app, ctx := newTestApp(t)

	deployer := common.HexToAddress("0x00000000000000000000000000000000000000EE")

	// Fund the deployer with the native denom for the other pool side.
	nativeCoins := sdk.NewCoins(sdk.NewCoin(karsaNativeDenom(), sdkmath.NewIntWithDecimal(1_000, 18)))
	require.NoError(t, app.BankKeeper.MintCoins(ctx, ammtypes.ModuleName, nativeCoins))
	require.NoError(t, app.BankKeeper.SendCoinsFromModuleToAccount(
		ctx, ammtypes.ModuleName, sdk.AccAddress(deployer.Bytes()), nativeCoins,
	))

	token := deployTestERC20(t, app, ctx, deployer, "Momo", "MOMO", 18)
	mintTestERC20(t, app, ctx, token, deployer, sdkmath.NewInt(1_000_000))

	denom := "erc20:" + strings.ToLower(token.Hex())
	require.NoError(t, app.Erc20Keeper.SetToken(ctx, erc20types.NewTokenPair(
		token, denom, erc20types.OWNER_EXTERNAL,
	)))

	akraAsset := common.HexToAddress(testconstants.WEVMOSContractMainnet)
	sender := sdk.AccAddress(deployer.Bytes())

	poolID, shares, err := app.AmmKeeper.CreatePool(
		ctx, sender, akraAsset.Hex(), token.Hex(), 30,
		sdkmath.NewInt(100_000), sdkmath.NewInt(100_000),
	)
	require.NoError(t, err)
	require.Equal(t, uint64(1), poolID)
	require.True(t, shares.IsPositive())

	// The pool must hold the bank denom; x/erc20 escrows the contract tokens.
	moduleAddr := app.AmmKeeper.ModuleAddress()
	ammModule := sdk.AccAddress(moduleAddr.Bytes())
	require.Equal(t, sdkmath.NewInt(100_000), app.BankKeeper.GetBalance(ctx, ammModule, denom).Amount)
	require.Equal(t, sdkmath.NewInt(100_000), erc20BalanceOf(t, app, ctx, token, erc20types.ModuleAddress))
	require.Equal(t, sdkmath.NewInt(900_000), erc20BalanceOf(t, app, ctx, token, deployer))

	// Swap native -> ERC20: bank denom is burned and the ERC20 is released.
	path := []string{akraAsset.Hex(), token.Hex()}
	before := erc20BalanceOf(t, app, ctx, token, deployer)

	amountOut, _, err := app.AmmKeeper.Swap(
		ctx, sender, sender, path, sdkmath.NewInt(1_000), sdkmath.NewInt(1), nil, 0,
	)
	require.NoError(t, err)

	after := erc20BalanceOf(t, app, ctx, token, deployer)
	require.Equal(t, before.Add(amountOut), after)
	require.Equal(t, sdkmath.NewInt(100_000).Sub(amountOut), app.BankKeeper.GetBalance(ctx, ammModule, denom).Amount)
	require.Equal(t, sdkmath.NewInt(100_000).Sub(amountOut), erc20BalanceOf(t, app, ctx, token, erc20types.ModuleAddress))
}

// TestExternalIntegratorFee checks that an integrator fee on an external ERC20
// input is paid directly in the contract token, before conversion to bank denom.
func TestExternalIntegratorFee(t *testing.T) {
	app, ctx := newTestApp(t)

	deployer := common.HexToAddress("0x00000000000000000000000000000000000000E2")
	integrator := common.HexToAddress("0x00000000000000000000000000000000000000E3")

	nativeCoins := sdk.NewCoins(sdk.NewCoin(karsaNativeDenom(), sdkmath.NewIntWithDecimal(1_000, 18)))
	require.NoError(t, app.BankKeeper.MintCoins(ctx, ammtypes.ModuleName, nativeCoins))
	require.NoError(t, app.BankKeeper.SendCoinsFromModuleToAccount(
		ctx, ammtypes.ModuleName, sdk.AccAddress(deployer.Bytes()), nativeCoins,
	))

	token := deployTestERC20(t, app, ctx, deployer, "Momo", "MOMO", 18)
	mintTestERC20(t, app, ctx, token, deployer, sdkmath.NewInt(1_000_000))

	denom := "erc20:" + strings.ToLower(token.Hex())
	require.NoError(t, app.Erc20Keeper.SetToken(ctx, erc20types.NewTokenPair(
		token, denom, erc20types.OWNER_EXTERNAL,
	)))

	akraAsset := common.HexToAddress(testconstants.WEVMOSContractMainnet)
	sender := sdk.AccAddress(deployer.Bytes())
	_, _, err := app.AmmKeeper.CreatePool(
		ctx, sender, akraAsset.Hex(), token.Hex(), 30,
		sdkmath.NewInt(100_000), sdkmath.NewInt(100_000),
	)
	require.NoError(t, err)

	path := []string{token.Hex(), akraAsset.Hex()}
	amountIn := sdkmath.NewInt(10_000)
	feeBps := uint32(20)
	expectedFee := amountIn.MulRaw(int64(feeBps)).QuoRaw(10_000)

	_, integratorFee, err := app.AmmKeeper.Swap(
		ctx, sender, sender, path, amountIn, sdkmath.NewInt(1),
		sdk.AccAddress(integrator.Bytes()), feeBps,
	)
	require.NoError(t, err)
	require.Equal(t, expectedFee, integratorFee)
	require.Equal(t, expectedFee, erc20BalanceOf(t, app, ctx, token, integrator))

	// The net amount is converted, not the gross input.
	ammModule := sdk.AccAddress(app.AmmKeeper.ModuleAddress().Bytes())
	require.Equal(t, sdkmath.NewInt(100_000).Add(amountIn.Sub(expectedFee)),
		app.BankKeeper.GetBalance(ctx, ammModule, denom).Amount)
}

// TestExternalExactOutAndRemove covers exact-out with an external input plus
// integrator fee, then removes liquidity through the conversion boundary.
func TestExternalExactOutAndRemove(t *testing.T) {
	app, ctx := newTestApp(t)

	deployer := common.HexToAddress("0x00000000000000000000000000000000000000E5")
	integrator := common.HexToAddress("0x00000000000000000000000000000000000000E6")

	nativeCoins := sdk.NewCoins(sdk.NewCoin(karsaNativeDenom(), sdkmath.NewIntWithDecimal(1_000, 18)))
	require.NoError(t, app.BankKeeper.MintCoins(ctx, ammtypes.ModuleName, nativeCoins))
	require.NoError(t, app.BankKeeper.SendCoinsFromModuleToAccount(
		ctx, ammtypes.ModuleName, sdk.AccAddress(deployer.Bytes()), nativeCoins,
	))

	token := deployTestERC20(t, app, ctx, deployer, "Momo", "MOMO", 18)
	mintTestERC20(t, app, ctx, token, deployer, sdkmath.NewInt(1_000_000))

	denom := "erc20:" + strings.ToLower(token.Hex())
	require.NoError(t, app.Erc20Keeper.SetToken(ctx, erc20types.NewTokenPair(
		token, denom, erc20types.OWNER_EXTERNAL,
	)))

	akraAsset := common.HexToAddress(testconstants.WEVMOSContractMainnet)
	sender := sdk.AccAddress(deployer.Bytes())
	poolID, shares, err := app.AmmKeeper.CreatePool(
		ctx, sender, akraAsset.Hex(), token.Hex(), 30,
		sdkmath.NewInt(100_000), sdkmath.NewInt(100_000),
	)
	require.NoError(t, err)

	path := []string{token.Hex(), akraAsset.Hex()}
	amountOut := sdkmath.NewInt(5_000)
	quotedIn, err := app.AmmKeeper.QuoteExactOut(ctx, path, amountOut)
	require.NoError(t, err)

	feeBps := uint32(20)
	expectedFee := quotedIn.MulRaw(int64(feeBps)).AddRaw(9_980 - 1).QuoRaw(9_980)
	totalIn := quotedIn.Add(expectedFee)

	akraBefore := app.BankKeeper.GetBalance(ctx, sender, karsaNativeDenom()).Amount
	amountIn, integratorFee, err := app.AmmKeeper.SwapExactOut(
		ctx, sender, sender, path, amountOut, totalIn,
		sdk.AccAddress(integrator.Bytes()), feeBps,
	)
	require.NoError(t, err)
	require.Equal(t, totalIn, amountIn)
	require.Equal(t, expectedFee, integratorFee)
	require.Equal(t, expectedFee, erc20BalanceOf(t, app, ctx, token, integrator))
	require.Equal(t, akraBefore.Add(amountOut), app.BankKeeper.GetBalance(ctx, sender, karsaNativeDenom()).Amount)

	// Removing all redeemable shares releases the ERC20 side through conversion.
	tokenBefore := erc20BalanceOf(t, app, ctx, token, deployer)
	_, _, err = app.AmmKeeper.RemoveLiquidity(ctx, sender, poolID, shares, sdkmath.ZeroInt(), sdkmath.ZeroInt())
	require.NoError(t, err)
	require.True(t, erc20BalanceOf(t, app, ctx, token, deployer).GT(tokenBefore))
}

// TestStableSwapExternalERC20 checks that a stableswap pool can resolve the
// decimals of an external ERC20 contract through the on-chain decimals() call.
func TestStableSwapExternalERC20(t *testing.T) {
	app, ctx := newTestApp(t)

	deployer := common.HexToAddress("0x00000000000000000000000000000000000000E1")
	nativeCoins := sdk.NewCoins(sdk.NewCoin(karsaNativeDenom(), sdkmath.NewIntWithDecimal(1_000, 18)))
	require.NoError(t, app.BankKeeper.MintCoins(ctx, ammtypes.ModuleName, nativeCoins))
	require.NoError(t, app.BankKeeper.SendCoinsFromModuleToAccount(
		ctx, ammtypes.ModuleName, sdk.AccAddress(deployer.Bytes()), nativeCoins,
	))

	token := deployTestERC20(t, app, ctx, deployer, "Momo", "MOMO", 18)
	mintTestERC20(t, app, ctx, token, deployer, sdkmath.NewInt(1_000_000))

	denom := "erc20:" + strings.ToLower(token.Hex())
	require.NoError(t, app.Erc20Keeper.SetToken(ctx, erc20types.NewTokenPair(
		token, denom, erc20types.OWNER_EXTERNAL,
	)))

	akraAsset := common.HexToAddress(testconstants.WEVMOSContractMainnet)
	sender := sdk.AccAddress(deployer.Bytes())

	poolID, _, err := app.AmmKeeper.CreatePoolWithType(
		ctx, sender, akraAsset.Hex(), token.Hex(), 3,
		sdkmath.NewInt(100_000), sdkmath.NewInt(100_000),
		ammtypes.PoolType_POOL_TYPE_STABLESWAP, 100,
	)
	require.NoError(t, err)

	pool, found := app.AmmKeeper.GetPool(ctx, poolID)
	require.True(t, found)
	// Both assets have 18 decimals, so no scaling is needed.
	require.ElementsMatch(t, []uint64{1, 1}, []uint64{pool.ScalingFactorA, pool.ScalingFactorB})

	path := []string{akraAsset.Hex(), token.Hex()}
	before := erc20BalanceOf(t, app, ctx, token, deployer)

	amountOut, _, err := app.AmmKeeper.Swap(
		ctx, sender, sender, path, sdkmath.NewInt(1_000), sdkmath.NewInt(1), nil, 0,
	)
	require.NoError(t, err)
	require.True(t, amountOut.GT(sdkmath.NewInt(990)), "amountOut = %s", amountOut)
	require.True(t, amountOut.LT(sdkmath.NewInt(1_000)), "amountOut = %s", amountOut)

	after := erc20BalanceOf(t, app, ctx, token, deployer)
	require.Equal(t, before.Add(amountOut), after)
}
