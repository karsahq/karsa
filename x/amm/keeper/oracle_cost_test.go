//go:build test

package keeper_test

import (
	"testing"
	"time"

	ammtypes "github.com/karsahq/karsa/x/amm/types"

	sdkmath "cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
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

// TestSwapCostWithRealisticOracle measures a full swap with a full observation
// ring and non-zero cumulative prices, which is what production looks like:
// block time advances and the cumulative fields are large instead of zero.
func TestSwapCostWithRealisticOracle(t *testing.T) {
	f := newOracleFixture(t)

	ring := ammtypes.Observations{}
	for i := 0; i < 32; i++ {
		ring.Items = append(ring.Items, ammtypes.Observation{
			Timestamp:   int64(1_000 + i),
			CumulativeA: sdkmath.NewIntWithDecimal(int64(1_000_000+i), 18),
			CumulativeB: sdkmath.NewIntWithDecimal(int64(2_000_000+i), 18),
		})
	}
	f.app.AmmKeeper.SetObservations(f.ctx, f.poolID, ring)

	const ops = 50
	amount := sdkmath.NewInt(100)

	measure := func(name string, blockTime func(int) int64) {
		c := withGasMeter(f.ctx)
		before := c.GasMeter().GasConsumed()

		for i := 0; i < ops; i++ {
			cc := c.WithBlockTime(time.Unix(blockTime(i), 0))
			_, _, err := f.app.AmmKeeper.Swap(
				cc, f.sender, f.sender, f.path, amount, sdkmath.NewInt(1), nil, 0,
			)
			require.NoError(t, err)
		}

		t.Logf("%-34s %8d gas/op", name, (c.GasMeter().GasConsumed()-before)/ops)
	}

	// Every swap lands in its own block, so each one writes a checkpoint.
	measure("swap, new block each swap", func(i int) int64 { return int64(3_000 + i) })

	// All swaps share one block: only the first one writes a checkpoint.
	measure("swap, same block", func(int) int64 { return 9_000 })
}
