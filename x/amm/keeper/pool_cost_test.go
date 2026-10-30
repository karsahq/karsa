//go:build test

package keeper_test

import (
	"strings"
	"testing"

	ammtypes "github.com/karsahq/karsa/x/amm/types"

	sdkmath "cosmossdk.io/math"

	"github.com/ethereum/go-ethereum/common"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

// TestPoolRecordCost measures how much of a swap is spent reading and writing
// the pool record, and how that scales with the record's serialized size.
func TestPoolRecordCost(t *testing.T) {
	app, ctx := newTestApp(t)
	registerTestUSDCPair(t, app, ctx)

	sender := sdk.AccAddress(common.HexToAddress("0x00000000000000000000000000000000000000AA").Bytes())
	fundTestDenoms(t, app, ctx, sender, sdkmath.NewIntWithDecimal(20_000_000, 18))

	akra := akraERC20().Hex()

	poolID, _, err := app.AmmKeeper.CreatePool(
		ctx, sender, akra, testUSDCPair.Hex(), 30,
		sdkmath.NewIntWithDecimal(10_000_000, 18), sdkmath.NewIntWithDecimal(10_000_000, 18),
	)
	require.NoError(t, err)

	normal, found := app.AmmKeeper.GetPool(ctx, poolID)
	require.True(t, found)

	// A production IBC pool: both denoms are 68-character voucher denoms.
	ibcPool := normal
	ibcPool.Id = 2
	ibcPool.DenomA = "ibc/" + strings.Repeat("A", 64)
	ibcPool.DenomB = "ibc/" + strings.Repeat("B", 64)

	// Large reserves: bigger varints, as in a pool with 1e12 units of supply.
	bigPool := normal
	bigPool.Id = 3
	bigPool.ReserveA = sdkmath.NewIntWithDecimal(1_000_000_000_000, 18)
	bigPool.ReserveB = sdkmath.NewIntWithDecimal(1_000_000_000_000, 18)
	bigPool.TotalShares = sdkmath.NewIntWithDecimal(1_000_000_000_000, 18)

	// Lower bound: only the fields a swap truly needs.
	minimal := ammtypes.Pool{
		Id:       4,
		ReserveA: sdkmath.NewIntWithDecimal(1, 18),
		ReserveB: sdkmath.NewIntWithDecimal(1, 18),
		FeeBps:   30,
	}

	variants := []struct {
		name string
		pool ammtypes.Pool
	}{
		{"normal (akra/uusdc)", normal},
		{"ibc denoms", ibcPool},
		{"large reserves", bigPool},
		{"minimal fields", minimal},
	}

	for _, v := range variants {
		app.AmmKeeper.SetPool(ctx, v.pool)

		t.Logf("%-22s %3d bytes serialized", v.name, v.pool.Size())

		measureGas(t, v.name+" get", 500, ctx, func(c sdk.Context, _ int) error {
			_, ok := app.AmmKeeper.GetPool(c, v.pool.Id)
			require.True(t, ok)
			return nil
		})
		measureGas(t, v.name+" set", 500, ctx, func(c sdk.Context, _ int) error {
			app.AmmKeeper.SetPool(c, v.pool)
			return nil
		})
		measureGas(t, v.name+" get+set", 500, ctx, func(c sdk.Context, _ int) error {
			p, ok := app.AmmKeeper.GetPool(c, v.pool.Id)
			require.True(t, ok)
			app.AmmKeeper.SetPool(c, p)
			return nil
		})
	}
}
