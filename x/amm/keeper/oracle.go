package keeper

import (
	"encoding/binary"

	sdkmath "cosmossdk.io/math"

	"github.com/karsahq/karsa/x/amm/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

const (
	// priceScale is the fixed-point scale (1e18) used for cumulative prices.
	priceScale = int64(1_000_000_000_000_000_000)
	// maxObservations is the number of checkpoints kept per pool.
	maxObservations = 32
)

var (
	priceScaleInt = sdkmath.NewInt(priceScale)
	priceScaleDec = sdkmath.LegacyNewDec(priceScale)
)

func observationsKey(poolID uint64) []byte {
	bz := make([]byte, 8)
	binary.BigEndian.PutUint64(bz, poolID)

	return append(append([]byte{}, types.ObservationsKeyPrefix...), bz...)
}

// GetObservations returns the TWAP observation ring for a pool.
func (k Keeper) GetObservations(ctx sdk.Context, poolID uint64) types.Observations {
	bz := k.Store(ctx).Get(observationsKey(poolID))
	if bz == nil {
		return types.Observations{}
	}

	var obs types.Observations
	k.cdc.MustUnmarshal(bz, &obs)

	return obs
}

// SetObservations stores the TWAP observation ring for a pool.
func (k Keeper) SetObservations(ctx sdk.Context, poolID uint64, obs types.Observations) {
	k.Store(ctx).Set(observationsKey(poolID), k.cdc.MustMarshal(&obs))
}

// spotPrices returns (A priced in B, B priced in A) scaled by 1e18.
func spotPrices(pool types.Pool) (sdkmath.Int, sdkmath.Int) {
	if !pool.ReserveA.IsPositive() || !pool.ReserveB.IsPositive() {
		return sdkmath.ZeroInt(), sdkmath.ZeroInt()
	}

	if pool.PoolType == types.PoolType_POOL_TYPE_STABLESWAP {
		return stableSpotPrices(pool)
	}

	aToB := pool.ReserveB.Mul(priceScaleInt).Quo(pool.ReserveA)
	bToA := pool.ReserveA.Mul(priceScaleInt).Quo(pool.ReserveB)

	return aToB, bToA
}

// updateOracle appends a cumulative-price checkpoint for the pool. It must be
// called after any change to the reserves.
func (k Keeper) updateOracle(ctx sdk.Context, pool types.Pool) {
	now := ctx.BlockTime().Unix()
	obs := k.GetObservations(ctx, pool.Id)

	// One checkpoint per pool per timestamp. Within a block the elapsed time is
	// zero, so an extra observation carries no information: it only rewrites the
	// whole ring and evicts real history from it.
	if n := len(obs.Items); n > 0 && obs.Items[n-1].Timestamp == now {
		return
	}

	priceA, priceB := spotPrices(pool)

	cumA, cumB := sdkmath.ZeroInt(), sdkmath.ZeroInt()
	if len(obs.Items) > 0 {
		last := obs.Items[len(obs.Items)-1]
		elapsed := now - last.Timestamp
		if elapsed < 0 {
			elapsed = 0
		}

		cumA = last.CumulativeA.Add(priceA.MulRaw(elapsed))
		cumB = last.CumulativeB.Add(priceB.MulRaw(elapsed))
	}

	obs.Items = append(obs.Items, types.Observation{
		Timestamp:   now,
		CumulativeA: cumA,
		CumulativeB: cumB,
	})
	if len(obs.Items) > maxObservations {
		obs.Items = obs.Items[len(obs.Items)-maxObservations:]
	}

	k.SetObservations(ctx, pool.Id, obs)
}

// Twap returns the time-weighted prices of a pool over the given window, in both
// directions, plus the window actually used (which may be shorter when there is
// not enough history).
func (k Keeper) Twap(
	ctx sdk.Context, poolID uint64, windowSeconds int64,
) (sdkmath.LegacyDec, sdkmath.LegacyDec, int64, error) {
	zero := sdkmath.LegacyZeroDec()

	pool, found := k.GetPool(ctx, poolID)
	if !found {
		return zero, zero, 0, types.ErrPoolNotFound.Wrapf("pool %d", poolID)
	}
	if windowSeconds <= 0 {
		return zero, zero, 0, types.ErrInvalidAmount.Wrap("window must be positive")
	}

	obs := k.GetObservations(ctx, poolID)
	if len(obs.Items) == 0 {
		a, b := spotPrices(pool)
		return decFromScaled(a), decFromScaled(b), 0, nil
	}

	now := ctx.BlockTime().Unix()
	last := obs.Items[len(obs.Items)-1]
	if now < last.Timestamp {
		now = last.Timestamp
	}

	priceA, priceB := spotPrices(pool)
	cumANow := last.CumulativeA.Add(priceA.MulRaw(now - last.Timestamp))
	cumBNow := last.CumulativeB.Add(priceB.MulRaw(now - last.Timestamp))

	target := now - windowSeconds
	past := obs.Items[0]
	for i := len(obs.Items) - 1; i >= 0; i-- {
		if obs.Items[i].Timestamp <= target {
			past = obs.Items[i]
			break
		}
	}

	elapsed := now - past.Timestamp
	if elapsed <= 0 {
		return decFromScaled(priceA), decFromScaled(priceB), 0, nil
	}

	twapA := cumANow.Sub(past.CumulativeA).QuoRaw(elapsed)
	twapB := cumBNow.Sub(past.CumulativeB).QuoRaw(elapsed)

	return decFromScaled(twapA), decFromScaled(twapB), elapsed, nil
}

// decFromScaled converts a 1e18-scaled integer price into a decimal.
func decFromScaled(value sdkmath.Int) sdkmath.LegacyDec {
	return sdkmath.LegacyNewDecFromInt(value).Quo(priceScaleDec)
}
