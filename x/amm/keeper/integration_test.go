//go:build test

package keeper_test

import (
	"math/big"
	"strings"
	"testing"
	"time"

	karsa "github.com/karsahq/karsa"
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
		ctx, stateDB, contracts.ERC20MinterBurnerDecimalsContract.ABI, account, token, false, false, nil,
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

// TestTwap checks the time-weighted price over a controlled window.
func TestTwap(t *testing.T) {
	app, ctx := newTestApp(t)
	registerTestUSDCPair(t, app, ctx)

	ctx = ctx.WithBlockTime(time.Unix(1_000, 0))

	sender := sdk.AccAddress(common.HexToAddress("0x00000000000000000000000000000000000000AB").Bytes())
	fundTestDenoms(t, app, ctx, sender, sdkmath.NewInt(1_000_000_000))

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
	initial := sdkmath.NewInt(1_000_000_000)
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
	quoteInput, err := ammprecompile.ABI.Pack("quote", path, amountIn)
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
		"swapExactIn", path, amountIn, big.NewInt(1), common.Address{}, common.Address{}, big.NewInt(0),
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

// TestExternalERC20Pool exercises direct custody: the module holds the ERC20
// contract tokens itself and moves them with EVM transfers.
func TestExternalERC20Pool(t *testing.T) {
	app, ctx := newTestApp(t)

	deployer := common.HexToAddress("0x00000000000000000000000000000000000000EE")

	// Fund the deployer with the native denom for the other pool side.
	nativeCoins := sdk.NewCoins(sdk.NewCoin(karsaNativeDenom(), sdkmath.NewInt(1_000_000_000)))
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

	// The module must hold the ERC20 reserves itself.
	moduleAddr := app.AmmKeeper.ModuleAddress()
	require.Equal(t, sdkmath.NewInt(100_000), erc20BalanceOf(t, app, ctx, token, moduleAddr))
	require.Equal(t, sdkmath.NewInt(900_000), erc20BalanceOf(t, app, ctx, token, deployer))

	// Swap native -> ERC20: output is transferred out of module custody.
	path := []string{akraAsset.Hex(), token.Hex()}
	before := erc20BalanceOf(t, app, ctx, token, deployer)

	amountOut, _, err := app.AmmKeeper.Swap(
		ctx, sender, sender, path, sdkmath.NewInt(1_000), sdkmath.NewInt(1), nil, 0,
	)
	require.NoError(t, err)

	after := erc20BalanceOf(t, app, ctx, token, deployer)
	require.Equal(t, before.Add(amountOut), after)
	require.Equal(t, sdkmath.NewInt(100_000).Sub(amountOut), erc20BalanceOf(t, app, ctx, token, moduleAddr))
}
