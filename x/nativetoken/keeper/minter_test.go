//go:build test

package keeper_test

import (
	"math/big"
	"testing"

	nativetokenminter "github.com/karsahq/karsa/x/nativetoken/precompile/minter"

	"github.com/cosmos/evm/x/vm/statedb"

	sdkmath "cosmossdk.io/math"

	"github.com/ethereum/go-ethereum/common"

	"github.com/stretchr/testify/require"
)

func TestMinterControllerCanMint(t *testing.T) {
	app, ctx := newTestApp(t)
	creator, controller := newContractCreator(t, app, ctx)
	creatorAddr := common.BytesToAddress(creator.Bytes())

	supply := sdkmath.NewIntWithDecimal(1_000, 18)
	token, err := app.NativeTokenKeeper.CreateNativeToken(
		ctx, creator, "Momo", "Momo", supply, controller.Hex(),
	)
	require.NoError(t, err)

	input, err := nativetokenminter.ABI.Pack(
		"mint", common.HexToAddress(token.Address), creatorAddr, big.NewInt(100),
	)
	require.NoError(t, err)

	stateDB := statedb.New(ctx, app.EVMKeeper, statedb.NewEmptyTxConfig())
	res, err := app.EVMKeeper.CallEVMWithData(
		ctx, stateDB, controller, &nativetokenminter.Address, input, true, false, nil,
	)
	require.NoError(t, err)
	require.False(t, res.Failed(), res.VmError)

	require.Equal(t, supply.AddRaw(100), app.BankKeeper.GetSupply(ctx, token.Denom).Amount)
	require.Equal(t, supply.AddRaw(100), app.BankKeeper.GetBalance(ctx, creator, token.Denom).Amount)
}

func TestMinterRejectsNonController(t *testing.T) {
	app, ctx := newTestApp(t)
	creator, controller := newContractCreator(t, app, ctx)
	creatorAddr := common.BytesToAddress(creator.Bytes())

	token, err := app.NativeTokenKeeper.CreateNativeToken(
		ctx, creator, "Momo", "Momo", sdkmath.NewInt(1_000), controller.Hex(),
	)
	require.NoError(t, err)

	// A different contract is not the controller.
	other := deployTestERC20(t, app, ctx, common.HexToAddress("0x00000000000000000000000000000000000000CC"))

	input, err := nativetokenminter.ABI.Pack(
		"mint", common.HexToAddress(token.Address), creatorAddr, big.NewInt(1),
	)
	require.NoError(t, err)

	stateDB := statedb.New(ctx, app.EVMKeeper, statedb.NewEmptyTxConfig())
	_, err = app.EVMKeeper.CallEVMWithData(
		ctx, stateDB, other, &nativetokenminter.Address, input, true, false, nil,
	)
	require.Error(t, err, "only the registered controller may mint")
}

func TestMinterRejectsImmutableToken(t *testing.T) {
	app, ctx := newTestApp(t)
	creator, controller := newContractCreator(t, app, ctx)
	creatorAddr := common.BytesToAddress(creator.Bytes())

	// No controller: supply is locked forever.
	token, err := app.NativeTokenKeeper.CreateNativeToken(
		ctx, creator, "Momo", "Momo", sdkmath.NewInt(1_000), "",
	)
	require.NoError(t, err)

	input, err := nativetokenminter.ABI.Pack(
		"mint", common.HexToAddress(token.Address), creatorAddr, big.NewInt(1),
	)
	require.NoError(t, err)

	stateDB := statedb.New(ctx, app.EVMKeeper, statedb.NewEmptyTxConfig())
	_, err = app.EVMKeeper.CallEVMWithData(
		ctx, stateDB, controller, &nativetokenminter.Address, input, true, false, nil,
	)
	require.Error(t, err, "an immutable token must not be mintable")
}

func TestMinterBurnFromControllerBalance(t *testing.T) {
	app, ctx := newTestApp(t)
	creator, controller := newContractCreator(t, app, ctx)

	supply := sdkmath.NewIntWithDecimal(1_000, 18)
	token, err := app.NativeTokenKeeper.CreateNativeToken(
		ctx, creator, "Momo", "Momo", supply, controller.Hex(),
	)
	require.NoError(t, err)

	input, err := nativetokenminter.ABI.Pack("burn", common.HexToAddress(token.Address), big.NewInt(200))
	require.NoError(t, err)

	stateDB := statedb.New(ctx, app.EVMKeeper, statedb.NewEmptyTxConfig())
	res, err := app.EVMKeeper.CallEVMWithData(
		ctx, stateDB, controller, &nativetokenminter.Address, input, true, false, nil,
	)
	require.NoError(t, err)
	require.False(t, res.Failed(), res.VmError)

	require.Equal(t, supply.SubRaw(200), app.BankKeeper.GetSupply(ctx, token.Denom).Amount)
	require.Equal(t, supply.SubRaw(200), app.BankKeeper.GetBalance(ctx, creator, token.Denom).Amount)
}
