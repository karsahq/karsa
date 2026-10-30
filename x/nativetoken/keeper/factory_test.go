//go:build test

package keeper_test

import (
	"math/big"
	"strings"
	"testing"

	nativetokenfactory "github.com/karsahq/karsa/x/nativetoken/precompile/factory"
	nativetokentypes "github.com/karsahq/karsa/x/nativetoken/types"

	"github.com/cosmos/evm/x/vm/statedb"

	sdkmath "cosmossdk.io/math"

	"github.com/ethereum/go-ethereum/common"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

func TestFactoryPrecompileCreatesToken(t *testing.T) {
	app, ctx := newTestApp(t)

	creator, creatorContract := newContractCreator(t, app, ctx)
	supply := sdkmath.NewIntWithDecimal(1_000, 18)

	input, err := nativetokenfactory.ABI.Pack(
		"createToken", "Momo", "Momo", supply.BigInt(), common.Address{},
	)
	require.NoError(t, err)

	stateDB := statedb.New(ctx, app.EVMKeeper, statedb.NewEmptyTxConfig())
	res, err := app.EVMKeeper.CallEVMWithData(
		ctx, stateDB, creatorContract, &nativetokenfactory.Address, input, true, false, nil,
	)
	require.NoError(t, err)
	require.False(t, res.Failed(), res.VmError)

	out, err := nativetokenfactory.ABI.Unpack("createToken", res.Ret)
	require.NoError(t, err)
	require.Len(t, out, 1)

	tokenAddress, ok := out[0].(common.Address)
	require.True(t, ok)

	// The creation is visible to an EVM explorer without reading Cosmos events.
	require.Len(t, res.Logs, 1)
	require.Equal(t, nativetokentypes.TokenCreatedEventID().Hex(), res.Logs[0].Topics[0])

	token, found := app.NativeTokenKeeper.GetTokenByAddress(ctx, strings.ToLower(tokenAddress.Hex()))
	require.True(t, found)

	// The caller becomes the creator, and the supply lands on it.
	require.Equal(t, strings.ToLower(creatorContract.Hex()), token.Creator)
	require.Equal(t, supply, app.BankKeeper.GetBalance(ctx, creator, token.Denom).Amount)
}

func TestFactoryPrecompileRejectsEOACaller(t *testing.T) {
	app, ctx := newTestApp(t)

	eoa := common.HexToAddress("0x00000000000000000000000000000000000000AA")
	fundAccount(t, app, ctx, sdk.AccAddress(eoa.Bytes()), sdkmath.NewIntWithDecimal(1_000, 18))

	input, err := nativetokenfactory.ABI.Pack("createToken", "Momo", "Momo", big.NewInt(1), common.Address{})
	require.NoError(t, err)

	stateDB := statedb.New(ctx, app.EVMKeeper, statedb.NewEmptyTxConfig())
	_, err = app.EVMKeeper.CallEVMWithData(
		ctx, stateDB, eoa, &nativetokenfactory.Address, input, true, false, nil,
	)
	require.Error(t, err, "an EOA caller must not be able to create a token")
}
