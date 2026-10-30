//go:build test

package keeper_test

import (
	"strings"
	"testing"

	karsa "github.com/karsahq/karsa"
	nativetokenkeeper "github.com/karsahq/karsa/x/nativetoken/keeper"
	nativetokentypes "github.com/karsahq/karsa/x/nativetoken/types"

	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	contracts "github.com/cosmos/evm/contracts"
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
)

func newTestApp(t *testing.T) (*karsa.App, sdk.Context) {
	t.Helper()

	evmtypes.NewEVMConfigurator().ResetTestConfig()
	app := karsa.Setup(t, testChainID, testEVMChainID)
	ctx := app.NewContextLegacy(false, cmtproto.Header{Height: 1, ChainID: testChainID})

	return app, ctx
}

// deployTestERC20 deploys the example ERC20 so it can act as a controller.
func deployTestERC20(t *testing.T, app *karsa.App, ctx sdk.Context, deployer common.Address) common.Address {
	t.Helper()

	nonce, err := app.AccountKeeper.GetSequence(ctx, deployer.Bytes())
	require.NoError(t, err)
	expected := crypto.CreateAddress(deployer, nonce)

	ctorArgs, err := contracts.ERC20MinterBurnerDecimalsContract.ABI.Pack("", "Controller", "CTRL", uint8(18))
	require.NoError(t, err)

	initCode := append(append([]byte{}, contracts.ERC20MinterBurnerDecimalsContract.Bin...), ctorArgs...)

	stateDB := statedb.New(ctx, app.EVMKeeper, statedb.NewEmptyTxConfig())
	_, err = app.EVMKeeper.CallEVMWithData(ctx, stateDB, deployer, nil, initCode, true, false, nil)
	require.NoError(t, err)
	require.True(t, app.EVMKeeper.IsContract(ctx, expected))

	return expected
}

func fundAccount(t *testing.T, app *karsa.App, ctx sdk.Context, addr sdk.AccAddress, amount sdkmath.Int) {
	t.Helper()

	coins := sdk.NewCoins(sdk.NewCoin("akra", amount))
	require.NoError(t, app.BankKeeper.MintCoins(ctx, nativetokentypes.ModuleName, coins))
	require.NoError(t, app.BankKeeper.SendCoinsFromModuleToAccount(ctx, nativetokentypes.ModuleName, addr, coins))
}

func TestCreateNativeToken(t *testing.T) {
	app, ctx := newTestApp(t)

	creator := sdk.AccAddress(common.HexToAddress("0x00000000000000000000000000000000000000AA").Bytes())
	supply := sdkmath.NewIntWithDecimal(1_000_000, 18)

	token, err := app.NativeTokenKeeper.CreateNativeToken(ctx, creator, "Momo", "Momo Token", supply, "")
	require.NoError(t, err)

	// Identity: the denom is derived from the address, and the address from the
	// creator plus the sequence.
	require.Equal(t, nativetokentypes.DenomFor(common.HexToAddress(token.Address)), token.Denom)
	require.True(t, strings.HasPrefix(token.Denom, "n:0x"))
	require.Len(t, token.Denom, nativetokentypes.DenomLen)
	require.Equal(t, token.Denom, strings.ToLower(token.Denom))

	// Creator is immutable and stored as lowercase hex.
	require.Equal(t, "0x00000000000000000000000000000000000000aa", token.Creator)
	require.Empty(t, token.Controller, "no controller means immutable supply")
	require.False(t, token.Verified)

	// The registry is readable by denom and by address.
	stored, found := app.NativeTokenKeeper.GetToken(ctx, token.Denom)
	require.True(t, found)
	require.Equal(t, token, stored)

	byAddress, found := app.NativeTokenKeeper.GetTokenByAddress(ctx, token.Address)
	require.True(t, found)
	require.Equal(t, token.Denom, byAddress.Denom)

	// The whole supply went to the creator.
	require.Equal(t, supply, app.BankKeeper.GetBalance(ctx, creator, token.Denom).Amount)

	// Bank metadata and the ERC20 pair are registered so wallets and the EVM can
	// see the token.
	metadata, found := app.BankKeeper.GetDenomMetaData(ctx, token.Denom)
	require.True(t, found)
	require.Equal(t, "Momo Token", metadata.Name)
	require.Equal(t, "Momo", metadata.Symbol)
	require.True(t, app.Erc20Keeper.IsERC20Registered(ctx, common.HexToAddress(token.Address)))

	// The creator's sequence advanced, so the next token gets a new address.
	require.Equal(t, uint64(1), app.NativeTokenKeeper.GetSequence(ctx, token.Creator))
}

func TestCreateNativeTokenSequenceIsUnique(t *testing.T) {
	app, ctx := newTestApp(t)
	creator := sdk.AccAddress(common.HexToAddress("0x00000000000000000000000000000000000000AA").Bytes())
	supply := sdkmath.NewInt(1_000)

	first, err := app.NativeTokenKeeper.CreateNativeToken(ctx, creator, "Momo", "Momo", supply, "")
	require.NoError(t, err)

	// A second token may reuse the symbol: names carry no exclusivity.
	second, err := app.NativeTokenKeeper.CreateNativeToken(ctx, creator, "Momo", "Momo", supply, "")
	require.NoError(t, err)

	require.NotEqual(t, first.Address, second.Address)
	require.NotEqual(t, first.Denom, second.Denom)
	require.Equal(t, uint64(2), app.NativeTokenKeeper.GetSequence(ctx, first.Creator))
}

func TestCreateNativeTokenControllerMustBeContract(t *testing.T) {
	app, ctx := newTestApp(t)
	creator := sdk.AccAddress(common.HexToAddress("0x00000000000000000000000000000000000000AA").Bytes())

	// An EOA must be rejected: control may only live in code.
	eoa := "0x00000000000000000000000000000000000000bb"
	_, err := app.NativeTokenKeeper.CreateNativeToken(ctx, creator, "Momo", "Momo", sdkmath.NewInt(1), eoa)
	require.ErrorIs(t, err, nativetokentypes.ErrControllerNotContract)

	// A deployed contract is accepted.
	fundAccount(t, app, ctx, sdk.AccAddress(common.HexToAddress("0x00000000000000000000000000000000000000CC").Bytes()), sdkmath.NewIntWithDecimal(1_000, 18))
	controller := deployTestERC20(t, app, ctx, common.HexToAddress("0x00000000000000000000000000000000000000CC"))

	token, err := app.NativeTokenKeeper.CreateNativeToken(
		ctx, creator, "Momo", "Momo", sdkmath.NewInt(1), controller.Hex(),
	)
	require.NoError(t, err)
	require.Equal(t, strings.ToLower(controller.Hex()), token.Controller)
}

func TestCreateNativeTokenValidation(t *testing.T) {
	app, ctx := newTestApp(t)
	creator := sdk.AccAddress(common.HexToAddress("0x00000000000000000000000000000000000000AA").Bytes())

	cases := []struct {
		name    string
		symbol  string
		tokenNm string
		supply  sdkmath.Int
		wantErr error
	}{
		{"symbol too short", "ab", "Momo", sdkmath.NewInt(1), nativetokentypes.ErrInvalidSymbol},
		{"symbol too long", "abcdefghijklm", "Momo", sdkmath.NewInt(1), nativetokentypes.ErrInvalidSymbol},
		{"symbol has separators", "momo-x", "Momo", sdkmath.NewInt(1), nativetokentypes.ErrInvalidSymbol},
		{"empty name", "momo", "", sdkmath.NewInt(1), nativetokentypes.ErrInvalidName},
		{"zero supply", "momo", "Momo", sdkmath.ZeroInt(), nativetokentypes.ErrInvalidSupply},
		{"negative supply", "momo", "Momo", sdkmath.NewInt(-1), nativetokentypes.ErrInvalidSupply},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := app.NativeTokenKeeper.CreateNativeToken(ctx, creator, tc.symbol, tc.tokenNm, tc.supply, "")
			require.ErrorIs(t, err, tc.wantErr)
		})
	}
}

func TestCreateNativeTokenMessageIsClosedByDefault(t *testing.T) {
	app, ctx := newTestApp(t)
	creator := sdk.AccAddress(common.HexToAddress("0x00000000000000000000000000000000000000AA").Bytes())
	msgServer := nativetokenkeeper.NewMsgServerImpl(app.NativeTokenKeeper)

	msg := &nativetokentypes.MsgCreateNativeToken{
		Creator:       creator.String(),
		Symbol:        "Momo",
		Name:          "Momo",
		InitialSupply: sdkmath.NewInt(1),
	}

	// Default: only the factory precompile may create, so every token traces
	// back to a contract.
	_, err := msgServer.CreateNativeToken(ctx, msg)
	require.ErrorIs(t, err, nativetokentypes.ErrUnauthorized)

	// Governance can reopen the message path without an upgrade.
	params := app.NativeTokenKeeper.GetParams(ctx)
	params.OpenCreation = true
	require.NoError(t, app.NativeTokenKeeper.SetParams(ctx, params))

	_, err = msgServer.CreateNativeToken(ctx, msg)
	require.NoError(t, err)
}

func TestSetTokenVerifiedRequiresAuthority(t *testing.T) {
	app, ctx := newTestApp(t)
	creator := sdk.AccAddress(common.HexToAddress("0x00000000000000000000000000000000000000AA").Bytes())

	token, err := app.NativeTokenKeeper.CreateNativeToken(ctx, creator, "Momo", "Momo", sdkmath.NewInt(1), "")
	require.NoError(t, err)
	require.False(t, token.Verified)

	msgServer := nativetokenkeeper.NewMsgServerImpl(app.NativeTokenKeeper)

	// A random account may not curate.
	_, err = msgServer.SetTokenVerified(ctx, &nativetokentypes.MsgSetTokenVerified{
		Authority: creator.String(),
		Denom:     token.Denom,
		Verified:  true,
	})
	require.ErrorIs(t, err, nativetokentypes.ErrUnauthorized)

	// Governance may.
	_, err = msgServer.SetTokenVerified(ctx, &nativetokentypes.MsgSetTokenVerified{
		Authority: app.NativeTokenKeeper.Authority(),
		Denom:     token.Denom,
		Verified:  true,
	})
	require.NoError(t, err)

	stored, found := app.NativeTokenKeeper.GetToken(ctx, token.Denom)
	require.True(t, found)
	require.True(t, stored.Verified)

	// Unknown denoms are rejected.
	_, err = msgServer.SetTokenVerified(ctx, &nativetokentypes.MsgSetTokenVerified{
		Authority: app.NativeTokenKeeper.Authority(),
		Denom:     "n:0x0000000000000000000000000000000000000001",
		Verified:  true,
	})
	require.ErrorIs(t, err, nativetokentypes.ErrTokenNotFound)
}
