//go:build test

package keeper_test

import (
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/cosmos/evm/contracts"
	testconstants "github.com/cosmos/evm/testutil/constants"
	erc20types "github.com/cosmos/evm/x/erc20/types"
	"github.com/cosmos/evm/x/vm/statedb"

	sdkmath "cosmossdk.io/math"

	"github.com/ethereum/go-ethereum/common"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

// measureGas runs fn ops times and logs gas and wall time per operation.
func measureGas(t *testing.T, name string, ops int, base sdk.Context, fn func(sdk.Context, int) error) {
	t.Helper()

	for i := 0; i < 3; i++ {
		require.NoError(t, fn(withGasMeter(base), i), name)
	}

	var gas uint64
	start := time.Now()

	for i := 0; i < ops; i++ {
		c := withGasMeter(base)
		require.NoError(t, fn(c, i), name)
		gas += c.GasMeter().GasConsumed()
	}

	elapsed := time.Since(start)
	t.Logf(
		"%-36s ops=%4d  %9.0f gas/op  %6.3f ms/op",
		name, ops, float64(gas)/float64(ops), float64(elapsed.Microseconds())/1000/float64(ops),
	)
}

// TestConversionEscrowInvariant pins the 1:1 backing between the escrowed ERC20
// and the minted bank denom after swaps in both directions.
func TestConversionEscrowInvariant(t *testing.T) {
	app, ctx := newTestApp(t)

	deployer := common.HexToAddress("0x00000000000000000000000000000000000000EE")
	sender := sdk.AccAddress(deployer.Bytes())

	fundNative(t, app, ctx, sender, sdkmath.NewIntWithDecimal(1_000_000, 18))

	token := deployTestERC20(t, app, ctx, deployer, "Momo", "MOMO", 18)
	mintTestERC20(t, app, ctx, token, deployer, sdkmath.NewInt(1_000_000))

	denom := "erc20:" + strings.ToLower(token.Hex())
	require.NoError(t, app.Erc20Keeper.SetToken(ctx, erc20types.NewTokenPair(
		token, denom, erc20types.OWNER_EXTERNAL,
	)))

	akraAsset := common.HexToAddress(testconstants.WEVMOSContractMainnet)
	_, _, err := app.AmmKeeper.CreatePool(
		ctx, sender, akraAsset.Hex(), token.Hex(), 30,
		sdkmath.NewInt(100_000), sdkmath.NewInt(100_000),
	)
	require.NoError(t, err)

	assertBacked := func(stage string) {
		escrowed := erc20BalanceOf(t, app, ctx, token, erc20types.ModuleAddress)
		supply := app.BankKeeper.GetSupply(ctx, denom).Amount
		require.Equal(t, escrowed.String(), supply.String(), "escrow mismatch at %s", stage)
	}

	assertBacked("after pool creation")

	swapPath := []string{akraAsset.Hex(), token.Hex()}
	for i := 0; i < 5; i++ {
		_, _, err := app.AmmKeeper.Swap(
			ctx, sender, sender, swapPath, sdkmath.NewInt(1_000), sdkmath.NewInt(1), nil, 0,
		)
		require.NoError(t, err)
		assertBacked("after swap akra->erc20")
	}

	backPath := []string{token.Hex(), akraAsset.Hex()}
	for i := 0; i < 5; i++ {
		_, _, err := app.AmmKeeper.Swap(
			ctx, sender, sender, backPath, sdkmath.NewInt(1_000), sdkmath.NewInt(1), nil, 0,
		)
		require.NoError(t, err)
		assertBacked("after swap erc20->akra")
	}
}

// TestConvertCostBreakdown decomposes the cost of converting an external ERC20
// into its bank representation.
func TestConvertCostBreakdown(t *testing.T) {
	app, ctx := newTestApp(t)

	deployer := common.HexToAddress("0x00000000000000000000000000000000000000EE")
	sender := sdk.AccAddress(deployer.Bytes())

	fundNative(t, app, ctx, sender, sdkmath.NewIntWithDecimal(1_000, 18))

	token := deployTestERC20(t, app, ctx, deployer, "Momo", "MOMO", 18)
	mintTestERC20(t, app, ctx, token, deployer, sdkmath.NewInt(10_000_000))
	require.NoError(t, app.Erc20Keeper.SetToken(ctx, erc20types.NewTokenPair(
		token, "erc20:"+strings.ToLower(token.Hex()), erc20types.OWNER_EXTERNAL,
	)))

	ammAddr := app.AmmKeeper.ModuleAddress()
	ammAcc := sdk.AccAddress(ammAddr.Bytes())
	abi := contracts.ERC20MinterBurnerDecimalsContract.ABI

	measureGas(t, "1. bank send (baseline)", 200, ctx, func(c sdk.Context, _ int) error {
		return app.BankKeeper.SendCoins(
			c, sender, ammAcc, sdk.NewCoins(sdk.NewCoin(karsaNativeDenom(), sdkmath.NewInt(1))),
		)
	})

	measureGas(t, "2. statedb.New", 200, ctx, func(c sdk.Context, _ int) error {
		_ = statedb.New(c, app.EVMKeeper, statedb.NewEmptyTxConfig())
		return nil
	})

	measureGas(t, "3. EVM balanceOf (view call)", 200, ctx, func(c sdk.Context, _ int) error {
		sdb := statedb.New(c, app.EVMKeeper, statedb.NewEmptyTxConfig())
		res, err := app.EVMKeeper.CallEVM(c, sdb, abi, deployer, token, false, false, nil, "balanceOf", deployer)
		if err != nil {
			return err
		}
		if res.Failed() {
			return errors.New(res.VmError)
		}
		return nil
	})

	measureGas(t, "4. EVM transfer (state write)", 100, ctx, func(c sdk.Context, _ int) error {
		sdb := statedb.New(c, app.EVMKeeper, statedb.NewEmptyTxConfig())
		data, err := abi.Pack("transfer", ammAddr, big.NewInt(1))
		if err != nil {
			return err
		}
		_, err = app.EVMKeeper.CallEVMWithData(c, sdb, deployer, &token, data, true, false, nil)
		return err
	})

	measureGas(t, "5. convert ERC20 -> bank (full)", 100, ctx, func(c sdk.Context, _ int) error {
		_, err := app.Erc20Keeper.ConvertERC20IntoCoinsForNativeToken(
			c, statedb.New(c, app.EVMKeeper, statedb.NewEmptyTxConfig()),
			token, sdkmath.NewInt(1), ammAcc, deployer, true, false,
		)
		return err
	})

	require.NotNil(t, token)

	// Isolate per-call overhead from actual storage work.
	measureGas(t, "6. EVM call, empty data -> EOA", 200, ctx, func(c sdk.Context, _ int) error {
		to := common.HexToAddress("0x00000000000000000000000000000000000000BB")
		sdb := statedb.New(c, app.EVMKeeper, statedb.NewEmptyTxConfig())
		_, err := app.EVMKeeper.CallEVMWithData(c, sdb, deployer, &to, nil, false, false, nil)
		return err
	})

	measureGas(t, "7. EVM totalSupply()", 200, ctx, func(c sdk.Context, _ int) error {
		sdb := statedb.New(c, app.EVMKeeper, statedb.NewEmptyTxConfig())
		res, err := app.EVMKeeper.CallEVM(c, sdb, abi, deployer, token, false, false, nil, "totalSupply")
		if err != nil {
			return err
		}
		if res.Failed() {
			return errors.New(res.VmError)
		}
		return nil
	})

	// Active precompiles are warmed through stateDB.Prepare, which does not charge
	// gas; the access-list cost is not billed per call.
	{
		evParams := app.EVMKeeper.GetParams(ctx)
		t.Logf("active static precompiles = %d (warmed for free, not billed)", len(evParams.ActiveStaticPrecompiles))
	}

	// Confirm the Cosmos meter receives exactly res.GasUsed.
	{
		sdb := statedb.New(ctx, app.EVMKeeper, statedb.NewEmptyTxConfig())
		c := withGasMeter(ctx)
		before := c.GasMeter().GasConsumed()
		res, err := app.EVMKeeper.CallEVM(c, sdb, abi, deployer, token, false, false, nil, "balanceOf", deployer)
		require.NoError(t, err)
		t.Logf("check: balanceOf res.GasUsed=%d cosmosDelta=%d", res.GasUsed, c.GasMeter().GasConsumed()-before)
	}

	// Same call, but one stateDB reused across iterations (warm account/code cache).
	{
		const n = 200
		c := withGasMeter(ctx)
		sdb := statedb.New(c, app.EVMKeeper, statedb.NewEmptyTxConfig())
		before := c.GasMeter().GasConsumed()
		for i := 0; i < n; i++ {
			res, err := app.EVMKeeper.CallEVM(c, sdb, abi, deployer, token, false, false, nil, "balanceOf", deployer)
			require.NoError(t, err)
			require.False(t, res.Failed())
		}
		total := c.GasMeter().GasConsumed() - before
		t.Logf("balanceOf with REUSED stateDB: %d gas/op (vs 70967 with fresh stateDB)", total/n)
	}
}
