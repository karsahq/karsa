//go:build test

package keeper_test

import (
	"errors"
	"math/big"
	"testing"

	ammtypes "github.com/karsahq/karsa/x/amm/types"

	"github.com/cosmos/evm/contracts"
	"github.com/cosmos/evm/x/vm/statedb"

	sdkmath "cosmossdk.io/math"

	"github.com/ethereum/go-ethereum/common"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

// TestDirectCustodyCost measures the custody layer of a direct-custody swap:
// one transferFrom pulling the input token in and one transfer pushing the
// output token out, with no bank conversion in between.
func TestDirectCustodyCost(t *testing.T) {
	app, ctx := newTestApp(t)

	deployer := common.HexToAddress("0x00000000000000000000000000000000000000EE")
	fundNative(t, app, ctx, sdk.AccAddress(deployer.Bytes()), sdkmath.NewIntWithDecimal(1_000, 18))
	custody := app.AmmKeeper.ModuleAddress()

	tokenIn := deployTestERC20(t, app, ctx, deployer, "Momo", "MOMO", 18)
	tokenOut := deployTestERC20(t, app, ctx, deployer, "Mimi", "MIMI", 18)
	mintTestERC20(t, app, ctx, tokenIn, deployer, sdkmath.NewInt(10_000_000))
	mintTestERC20(t, app, ctx, tokenOut, deployer, sdkmath.NewInt(10_000_000))

	abi := contracts.ERC20MinterBurnerDecimalsContract.ABI
	maxUint := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))

	// One-time max approval plus a custody seed, the common steady state.
	sdb := statedb.New(ctx, app.EVMKeeper, statedb.NewEmptyTxConfig())
	_, err := app.EVMKeeper.CallEVM(
		ctx, sdb, abi, deployer, tokenIn, true, false, nil, "approve", custody, maxUint,
	)
	require.NoError(t, err)
	_, err = app.EVMKeeper.CallEVM(
		ctx, sdb, abi, deployer, tokenOut, true, false, nil,
		"transfer", custody, big.NewInt(5_000_000),
	)
	require.NoError(t, err)

	one := big.NewInt(1)

	// --- custody layer, isolated ------------------------------------------
	measureGas(t, "transfer (fresh stateDB)", 100, ctx, func(c sdk.Context, _ int) error {
		s := statedb.New(c, app.EVMKeeper, statedb.NewEmptyTxConfig())
		res, err := app.EVMKeeper.CallEVM(c, s, abi, custody, tokenOut, true, false, nil, "transfer", deployer, one)
		if err != nil {
			return err
		}
		if res.Failed() {
			return errors.New(res.VmError)
		}
		return nil
	})

	measureGas(t, "transferFrom (fresh stateDB)", 100, ctx, func(c sdk.Context, _ int) error {
		s := statedb.New(c, app.EVMKeeper, statedb.NewEmptyTxConfig())
		res, err := app.EVMKeeper.CallEVM(
			c, s, abi, custody, tokenIn, true, false, nil, "transferFrom", deployer, custody, one,
		)
		if err != nil {
			return err
		}
		if res.Failed() {
			return errors.New(res.VmError)
		}
		return nil
	})

	// --- full custody layer of one swap -----------------------------------
	measureGas(t, "pair: shared stateDB", 100, ctx, func(c sdk.Context, _ int) error {
		s := statedb.New(c, app.EVMKeeper, statedb.NewEmptyTxConfig())

		res, err := app.EVMKeeper.CallEVM(
			c, s, abi, custody, tokenIn, true, false, nil, "transferFrom", deployer, custody, one,
		)
		if err != nil {
			return err
		}
		if res.Failed() {
			return errors.New(res.VmError)
		}

		res, err = app.EVMKeeper.CallEVM(c, s, abi, custody, tokenOut, true, false, nil, "transfer", deployer, one)
		if err != nil {
			return err
		}
		if res.Failed() {
			return errors.New(res.VmError)
		}
		return nil
	})

	measureGas(t, "pair: fresh stateDB each call", 100, ctx, func(c sdk.Context, _ int) error {
		s := statedb.New(c, app.EVMKeeper, statedb.NewEmptyTxConfig())
		res, err := app.EVMKeeper.CallEVM(
			c, s, abi, custody, tokenIn, true, false, nil, "transferFrom", deployer, custody, one,
		)
		if err != nil {
			return err
		}
		if res.Failed() {
			return errors.New(res.VmError)
		}

		s = statedb.New(c, app.EVMKeeper, statedb.NewEmptyTxConfig())
		res, err = app.EVMKeeper.CallEVM(c, s, abi, custody, tokenOut, true, false, nil, "transfer", deployer, one)
		if err != nil {
			return err
		}
		if res.Failed() {
			return errors.New(res.VmError)
		}
		return nil
	})

	// Deferred commit: one stateDB, and only the last call flushes. This should
	// keep the single cold read of the shared variant without paying for a second
	// commit of the first call's dirties.
	measureGas(t, "pair: shared stateDB, single commit", 100, ctx, func(c sdk.Context, _ int) error {
		s := statedb.New(c, app.EVMKeeper, statedb.NewEmptyTxConfig())

		res, err := app.EVMKeeper.CallEVM(
			c, s, abi, custody, tokenIn, false, false, nil, "transferFrom", deployer, custody, one,
		)
		if err != nil {
			return err
		}
		if res.Failed() {
			return errors.New(res.VmError)
		}

		res, err = app.EVMKeeper.CallEVM(c, s, abi, custody, tokenOut, true, false, nil, "transfer", deployer, one)
		if err != nil {
			return err
		}
		if res.Failed() {
			return errors.New(res.VmError)
		}
		return nil
	})

	// --- what direct custody removes: the bank legs ------------------------
	coins := sdk.NewCoins(sdk.NewCoin(karsaNativeDenom(), sdkmath.NewInt(1)))
	moduleAcc := sdk.AccAddress(custody.Bytes())

	measureGas(t, "bank mint + send", 100, ctx, func(c sdk.Context, _ int) error {
		if err := app.BankKeeper.MintCoins(c, ammtypes.ModuleName, coins); err != nil {
			return err
		}
		return app.BankKeeper.SendCoinsFromModuleToAccount(c, ammtypes.ModuleName, moduleAcc, coins)
	})

	measureGas(t, "bank send + burn", 100, ctx, func(c sdk.Context, _ int) error {
		if err := app.BankKeeper.SendCoinsFromAccountToModule(c, moduleAcc, ammtypes.ModuleName, coins); err != nil {
			return err
		}
		return app.BankKeeper.BurnCoins(c, ammtypes.ModuleName, coins)
	})
}
