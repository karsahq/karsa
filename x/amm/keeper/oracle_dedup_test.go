//go:build test

package keeper_test

import (
	"testing"
	"time"

	karsa "github.com/karsahq/karsa"
	ammtypes "github.com/karsahq/karsa/x/amm/types"

	sdkmath "cosmossdk.io/math"

	"github.com/ethereum/go-ethereum/common"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

// maxObservations mirrors keeper.maxObservations.
const maxObservations = 32

var priceScaleInt = sdkmath.NewInt(1_000_000_000_000_000_000)

type oracleFixture struct {
	app    *karsa.App
	ctx    sdk.Context
	poolID uint64
	sender sdk.AccAddress
	path   []string
}

func newOracleFixture(t *testing.T) oracleFixture {
	t.Helper()

	app, ctx := newTestApp(t)
	registerTestUSDCPair(t, app, ctx)

	sender := sdk.AccAddress(common.HexToAddress("0x00000000000000000000000000000000000000AA").Bytes())
	fundTestDenoms(t, app, ctx, sender, sdkmath.NewIntWithDecimal(10_000_000, 18))

	akra := akraERC20().Hex()

	poolID, _, err := app.AmmKeeper.CreatePool(
		ctx, sender, akra, testUSDCPair.Hex(), 30,
		sdkmath.NewInt(10_000_000), sdkmath.NewInt(10_000_000),
	)
	require.NoError(t, err)

	return oracleFixture{
		app:    app,
		ctx:    ctx,
		poolID: poolID,
		sender: sender,
		path:   []string{akra, testUSDCPair.Hex()},
	}
}

func (f oracleFixture) at(sec int64) oracleFixture {
	f.ctx = f.ctx.WithBlockTime(time.Unix(sec, 0))
	return f
}

func (f oracleFixture) swap(t *testing.T, amount int64) {
	t.Helper()

	_, _, err := f.app.AmmKeeper.Swap(
		f.ctx, f.sender, f.sender, f.path,
		sdkmath.NewInt(amount), sdkmath.NewInt(1), nil, 0,
	)
	require.NoError(t, err)
}

func (f oracleFixture) observations() ammtypes.Observations {
	return f.app.AmmKeeper.GetObservations(f.ctx, f.poolID)
}

// One block must not produce more than one checkpoint.
func TestOracleOneObservationPerBlock(t *testing.T) {
	f := newOracleFixture(t).at(1_000)
	start := len(f.observations().Items)

	f.swap(t, 1_000)
	afterFirst := len(f.observations().Items)
	require.Equal(t, start+1, afterFirst)

	f.swap(t, 2_000)
	f.swap(t, 3_000)

	obs := f.observations()
	require.Equal(t, afterFirst, len(obs.Items), "extra swaps in one block must not append")
	require.Equal(t, int64(1_000), obs.Items[len(obs.Items)-1].Timestamp)
}

// A swap in a later block must still append.
func TestOracleObservationPerBlock(t *testing.T) {
	f := newOracleFixture(t)
	start := len(f.observations().Items)

	for i := 0; i < 3; i++ {
		f = f.at(2_000 + int64(i)*10)
		f.swap(t, 1_000)
	}

	obs := f.observations()
	require.Equal(t, start+3, len(obs.Items))
	require.Equal(t, int64(2_020), obs.Items[len(obs.Items)-1].Timestamp)
}

// The ring stays capped and keeps the most recent distinct timestamps.
func TestOracleRingStaysCapped(t *testing.T) {
	f := newOracleFixture(t)

	const blocks = 40
	for i := 0; i < blocks; i++ {
		f = f.at(3_000 + int64(i)*10)
		f.swap(t, 100)
	}

	obs := f.observations()
	require.Len(t, obs.Items, maxObservations)
	require.Equal(t, int64(3_000+int64(blocks-1)*10), obs.Items[len(obs.Items)-1].Timestamp)
	require.Equal(t, int64(3_000+int64(blocks-maxObservations)*10), obs.Items[0].Timestamp,
		"duplicate timestamps must not evict distinct history")
}

// A second swap in the same block must not touch the recorded checkpoints.
func TestOracleSameBlockSwapKeepsCheckpoint(t *testing.T) {
	f := newOracleFixture(t).at(1_000)

	f.swap(t, 1_000)
	first := f.observations()
	firstLast := first.Items[len(first.Items)-1]

	f.swap(t, 5_000)
	second := f.observations()
	secondLast := second.Items[len(second.Items)-1]

	require.Equal(t, len(first.Items), len(second.Items))
	require.Equal(t, firstLast.Timestamp, secondLast.Timestamp)
	require.True(t, firstLast.CumulativeA.Equal(secondLast.CumulativeA))
	require.True(t, firstLast.CumulativeB.Equal(secondLast.CumulativeB))
}

// With no price change, the TWAP over a quiet window must equal the spot price.
func TestOracleTwapMatchesSpotWhenFlat(t *testing.T) {
	f := newOracleFixture(t).at(1_000)
	f.swap(t, 1_000)

	// Advance time without trading: nothing changes the price.
	f = f.at(1_100)

	pool, found := f.app.AmmKeeper.GetPool(f.ctx, f.poolID)
	require.True(t, found)

	expectedA := sdkmath.LegacyNewDecFromInt(pool.ReserveB.Mul(priceScaleInt).Quo(pool.ReserveA)).
		Quo(sdkmath.LegacyNewDecFromInt(priceScaleInt))
	expectedB := sdkmath.LegacyNewDecFromInt(pool.ReserveA.Mul(priceScaleInt).Quo(pool.ReserveB)).
		Quo(sdkmath.LegacyNewDecFromInt(priceScaleInt))

	twapA, twapB, elapsed, err := f.app.AmmKeeper.Twap(f.ctx, f.poolID, 100)
	require.NoError(t, err)
	require.Equal(t, int64(100), elapsed)
	require.True(t, twapA.Equal(expectedA), "twapA %s != spot %s", twapA, expectedA)
	require.True(t, twapB.Equal(expectedB), "twapB %s != spot %s", twapB, expectedB)
}
