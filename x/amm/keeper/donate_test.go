//go:build test

package keeper_test

import (
	"math/big"
	"strings"
	"testing"

	ammtypes "github.com/karsahq/karsa/x/amm/types"

	testconstants "github.com/cosmos/evm/testutil/constants"
	erc20types "github.com/cosmos/evm/x/erc20/types"
	"github.com/cosmos/evm/x/vm/statedb"

	sdkmath "cosmossdk.io/math"

	"github.com/ethereum/go-ethereum/common"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

// DonatePool adopts an excess custody balance into the reserve without minting
// shares, so the value accrues to LPs.
func TestDonatePoolAdoptsExcess(t *testing.T) {
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

	before, found := app.AmmKeeper.GetPool(ctx, poolID)
	require.True(t, found)

	// A stray transfer lands on the custody account.
	custody := ammtypes.CustodyAddress(poolID)
	stateDB := statedb.New(ctx, app.EVMKeeper, statedb.NewEmptyTxConfig())
	res, err := app.EVMKeeper.CallEVM(
		ctx, stateDB, ammtypes.ERC20ABI, deployer, token, true, false, nil,
		"transfer", custody, big.NewInt(1_000),
	)
	require.NoError(t, err)
	require.False(t, res.Failed(), res.VmError)

	donated, err := app.AmmKeeper.DonatePool(ctx, poolID)
	require.NoError(t, err)
	require.False(t, donated.IsZero())

	after, found := app.AmmKeeper.GetPool(ctx, poolID)
	require.True(t, found)

	// No new shares: the existing LPs own the bigger pool.
	require.Equal(t, before.TotalShares, after.TotalShares)

	if strings.EqualFold(before.AssetA, token.Hex()) {
		require.Equal(t, before.ReserveA.AddRaw(1_000), after.ReserveA)
		require.Equal(t, before.ReserveB, after.ReserveB)
	} else {
		require.Equal(t, before.ReserveB.AddRaw(1_000), after.ReserveB)
		require.Equal(t, before.ReserveA, after.ReserveA)
	}

	// Donating again changes nothing once the reserve matches the balance.
	again, err := app.AmmKeeper.DonatePool(ctx, poolID)
	require.NoError(t, err)
	require.True(t, again.IsZero())
}

func TestDonatePoolUnknownPool(t *testing.T) {
	app, ctx := newTestApp(t)

	_, err := app.AmmKeeper.DonatePool(ctx, 99)
	require.ErrorIs(t, err, ammtypes.ErrPoolNotFound)
}
