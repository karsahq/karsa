//go:build test

package keeper_test

import (
	"testing"

	ammtypes "github.com/karsahq/karsa/x/amm/types"

	sdkmath "cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// TestOracleUpdateCost measures what updateOracle pays on every reserve change:
// it reads the observation ring and writes the whole ring back.
func TestOracleUpdateCost(t *testing.T) {
	app, ctx := newTestApp(t)

	buildRing := func(n int) ammtypes.Observations {
		obs := ammtypes.Observations{}
		for i := 0; i < n; i++ {
			obs.Items = append(obs.Items, ammtypes.Observation{
				Timestamp:   int64(1_700_000_000 + i),
				CumulativeA: sdkmath.NewIntWithDecimal(int64(1_000_000+i), 18),
				CumulativeB: sdkmath.NewIntWithDecimal(int64(2_000_000+i), 18),
			})
		}
		return obs
	}

	for _, n := range []int{1, 32} {
		ring := buildRing(n)
		app.AmmKeeper.SetObservations(ctx, 1, ring)

		t.Logf("ring of %2d observations = %d bytes on disk", n, ring.Size())

		measureGas(t, "oracle get+set", 200, ctx, func(c sdk.Context, _ int) error {
			got := app.AmmKeeper.GetObservations(c, 1)
			app.AmmKeeper.SetObservations(c, 1, got)
			return nil
		})
	}

	// The same ring when cumulative prices are still zero, which is what the
	// swap benchmark sees because block time does not advance there.
	zeroRing := ammtypes.Observations{}
	for i := 0; i < 32; i++ {
		zeroRing.Items = append(zeroRing.Items, ammtypes.Observation{})
	}
	app.AmmKeeper.SetObservations(ctx, 2, zeroRing)
	t.Logf("ring of 32 zero observations = %d bytes on disk", zeroRing.Size())

	measureGas(t, "oracle get+set, zero-filled", 200, ctx, func(c sdk.Context, _ int) error {
		got := app.AmmKeeper.GetObservations(c, 2)
		app.AmmKeeper.SetObservations(c, 2, got)
		return nil
	})
}
