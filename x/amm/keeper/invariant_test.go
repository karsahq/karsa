//go:build test

package keeper_test

import (
	"math/big"
	"strings"
	"testing"

	ammtypes "github.com/karsahq/karsa/x/amm/types"

	karsa "github.com/karsahq/karsa"

	contracts "github.com/cosmos/evm/contracts"

	testconstants "github.com/cosmos/evm/testutil/constants"
	erc20types "github.com/cosmos/evm/x/erc20/types"
	"github.com/cosmos/evm/x/vm/statedb"

	sdkmath "cosmossdk.io/math"

	"github.com/ethereum/go-ethereum/common"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

// newExternalPool deploys an ERC20, pools it against akra, and returns the pool
// id and token address.
func newExternalPool(t *testing.T) (*karsa.App, sdk.Context, uint64, common.Address, sdk.AccAddress) {
	t.Helper()

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

	return app, ctx, poolID, token, sender
}

// burnFromCustody simulates a forced burn of the pool's custody balance, which
// is what a clawback or a negative rebase would look like.
func burnFromCustody(t *testing.T, app *karsa.App, ctx sdk.Context, poolID uint64, token common.Address, amount int64) {
	t.Helper()

	custody := ammtypes.CustodyAddress(poolID)
	stateDB := statedb.New(ctx, app.EVMKeeper, statedb.NewEmptyTxConfig())
	res, err := app.EVMKeeper.CallEVM(
		ctx, stateDB, contracts.ERC20MinterBurnerDecimalsContract.ABI, custody, token,
		true, false, nil, "burn", big.NewInt(amount),
	)
	require.NoError(t, err)
	require.False(t, res.Failed(), res.VmError)
}

func TestCheckPoolDetectsShortfall(t *testing.T) {
	app, ctx, poolID, token, _ := newExternalPool(t)

	under, err := app.AmmKeeper.CheckPool(ctx, poolID)
	require.NoError(t, err)
	require.False(t, under, "a healthy pool must not be flagged")

	burnFromCustody(t, app, ctx, poolID, token, 1_000)

	under, err = app.AmmKeeper.CheckPool(ctx, poolID)
	require.NoError(t, err)
	require.True(t, under)

	pool, found := app.AmmKeeper.GetPool(ctx, poolID)
	require.True(t, found)
	require.Equal(t, ammtypes.PoolStatus_WITHDRAW_ONLY, pool.Status)
}

// An inbound swap must notice the shortfall from the balance it already reads,
// so nobody trades against a reserve the pool cannot honour.
func TestSwapDetectsShortfallInline(t *testing.T) {
	app, ctx, poolID, token, sender := newExternalPool(t)

	burnFromCustody(t, app, ctx, poolID, token, 5_000)

	// The external token is the input here, so the balance the AMM already reads
	// for the delta check is the custody balance that fell short.
	akra := common.HexToAddress(testconstants.WEVMOSContractMainnet)
	_, _, err := app.AmmKeeper.Swap(
		ctx, sender, sender, []string{token.Hex(), akra.Hex()},
		sdkmath.NewInt(1_000), sdkmath.NewInt(1), nil, 0,
	)
	require.ErrorIs(t, err, ammtypes.ErrPoolInactive)

	pool, found := app.AmmKeeper.GetPool(ctx, poolID)
	require.True(t, found)
	require.Equal(t, ammtypes.PoolStatus_WITHDRAW_ONLY, pool.Status)
}
