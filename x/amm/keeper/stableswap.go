package keeper

import (
	sdkmath "cosmossdk.io/math"

	"github.com/karsahq/karsa/x/amm/types"
)

// maxStableIterations bounds the Newton iterations used by the stableswap
// invariant. Curve uses the same limit.
const maxStableIterations = 255

// scalingFactorInt converts the stored scaling factor to an integer. A zero
// value means 1 (assets that are already 18-decimal normalised).
func scalingFactorInt(sf uint64) sdkmath.Int {
	if sf == 0 {
		return sdkmath.OneInt()
	}
	return sdkmath.NewIntFromUint64(sf)
}

// stableInvariant computes D for the two-asset stableswap invariant:
//
//	Ann*S + D = Ann*D + D^3/(4xy),  Ann = 2A
//
// It returns zero when the inputs are invalid or the iteration does not converge.
func stableInvariant(x, y sdkmath.Int, amp uint64) sdkmath.Int {
	zero := sdkmath.ZeroInt()
	if !x.IsPositive() || !y.IsPositive() || amp == 0 {
		return zero
	}

	s := x.Add(y)
	ann := sdkmath.NewIntFromUint64(2 * amp)
	d := s
	one := sdkmath.OneInt()

	for i := 0; i < maxStableIterations; i++ {
		// dP = D^3 / (4xy)
		dp := d.Mul(d).Mul(d).Quo(x.Mul(y).MulRaw(4))

		// D = (Ann*S + 2*D_P) * D / ((Ann-1)*D + 3*D_P)
		num := ann.Mul(s).Add(dp.MulRaw(2)).Mul(d)
		den := ann.SubRaw(1).Mul(d).Add(dp.MulRaw(3))
		if !den.IsPositive() {
			return zero
		}

		next := num.Quo(den)
		if !next.IsPositive() {
			return zero
		}

		diff := next.Sub(d)
		if diff.IsNegative() {
			diff = diff.Neg()
		}
		d = next

		if diff.LTE(one) {
			return d
		}
	}

	return zero
}

// stableSolveOther returns the smallest integer Y that satisfies the invariant
// for the given X and D. Rounding up keeps the pool on the safe side.
func stableSolveOther(known, d sdkmath.Int, amp uint64) (sdkmath.Int, bool) {
	zero := sdkmath.ZeroInt()
	if !known.IsPositive() || !d.IsPositive() || amp == 0 {
		return zero, false
	}

	ann := sdkmath.NewIntFromUint64(2 * amp)

	// Quadratic y^2 + (known - D + D/Ann) y - D^3/(4*known*Ann) = 0,
	// solved with Newton's method.
	b := known.Add(d.Quo(ann))
	c := d.Mul(d).Mul(d).Quo(known.Mul(ann).MulRaw(4))

	y := d
	one := sdkmath.OneInt()
	converged := false

	for i := 0; i < maxStableIterations; i++ {
		den := y.MulRaw(2).Add(b).Sub(d)
		if !den.IsPositive() {
			return zero, false
		}

		next := y.Mul(y).Add(c).Quo(den)
		if !next.IsPositive() {
			return zero, false
		}

		diff := next.Sub(y)
		if diff.IsNegative() {
			diff = diff.Neg()
		}
		y = next

		if diff.LTE(one) {
			converged = true
			break
		}
	}

	if !converged {
		return zero, false
	}

	return stableRoundUp(known, y, d, amp)
}

// stableRoundUp increments y until the invariant polynomial is non-negative, so
// the returned value is an upper bound of the exact root.
func stableRoundUp(known, y, d sdkmath.Int, amp uint64) (sdkmath.Int, bool) {
	eightA := sdkmath.NewIntFromUint64(8 * amp)
	x2 := known.Mul(known)
	b := eightA.Mul(x2).Sub(
		sdkmath.NewIntFromUint64(4 * (2*amp - 1)).Mul(d).Mul(known),
	)
	d3 := d.Mul(d).Mul(d)

	for i := 0; i < 8; i++ {
		// f(y) = 8A*x*y^2 + (8A*x^2 - 4(2A-1)Dx)*y - D^3
		f := eightA.Mul(known).Mul(y).Mul(y).Add(b.Mul(y)).Sub(d3)
		if !f.IsNegative() {
			return y, true
		}
		y = y.AddRaw(1)
	}

	return sdkmath.ZeroInt(), false
}

// stableAmountOut returns the raw output for an exact input against a
// stableswap pool. Input and output scaling factors normalise the reserves to
// 18 decimals.
func stableAmountOut(
	reserveIn, reserveOut sdkmath.Int,
	sfIn, sfOut uint64,
	amp uint64,
	feeBps uint32,
	amountIn sdkmath.Int,
) sdkmath.Int {
	zero := sdkmath.ZeroInt()
	if !amountIn.IsPositive() {
		return zero
	}

	inScale := scalingFactorInt(sfIn)
	outScale := scalingFactorInt(sfOut)

	x := reserveIn.Mul(inScale)
	y := reserveOut.Mul(outScale)

	d := stableInvariant(x, y, amp)
	if !d.IsPositive() {
		return zero
	}

	// The fee is retained by the pool: price with the net input, but accounting
	// later adds the full input to the reserve.
	netIn := amountIn.MulRaw(int64(10_000 - feeBps)).QuoRaw(10_000)
	if !netIn.IsPositive() {
		return zero
	}

	yNew, ok := stableSolveOther(x.Add(netIn.Mul(inScale)), d, amp)
	if !ok || !yNew.LT(y) {
		return zero
	}

	out := y.Sub(yNew).Quo(outScale)
	if !out.IsPositive() || out.GTE(reserveOut) {
		return zero
	}

	return out
}

// stableAmountIn returns the raw input (including the pool fee) required for an
// exact output from a stableswap pool.
func stableAmountIn(
	reserveIn, reserveOut sdkmath.Int,
	sfIn, sfOut uint64,
	amp uint64,
	feeBps uint32,
	amountOut sdkmath.Int,
) sdkmath.Int {
	zero := sdkmath.ZeroInt()
	if !amountOut.IsPositive() || feeBps >= 10_000 {
		return zero
	}

	inScale := scalingFactorInt(sfIn)
	outScale := scalingFactorInt(sfOut)

	x := reserveIn.Mul(inScale)
	y := reserveOut.Mul(outScale)

	d := stableInvariant(x, y, amp)
	if !d.IsPositive() {
		return zero
	}

	outNorm := amountOut.Mul(outScale)
	if outNorm.GTE(y) {
		return zero
	}

	xNew, ok := stableSolveOther(y.Sub(outNorm), d, amp)
	if !ok || !xNew.GT(x) {
		return zero
	}

	dxRaw := ceilDiv(xNew.Sub(x), inScale)
	if !dxRaw.IsPositive() {
		return zero
	}

	return ceilDiv(dxRaw.MulRaw(10_000), sdkmath.NewIntFromUint64(uint64(10_000-feeBps)))
}

// stableSpotPrices returns the marginal prices of a stableswap pool, scaled by
// priceScale. The derivative is evaluated on the normalised reserves.
func stableSpotPrices(pool types.Pool) (sdkmath.Int, sdkmath.Int) {
	zero := sdkmath.ZeroInt()
	if !pool.ReserveA.IsPositive() || !pool.ReserveB.IsPositive() || pool.Amplification == 0 {
		return zero, zero
	}

	x := pool.ReserveA.Mul(scalingFactorInt(pool.ScalingFactorA))
	y := pool.ReserveB.Mul(scalingFactorInt(pool.ScalingFactorB))

	d := stableInvariant(x, y, pool.Amplification)
	if !d.IsPositive() {
		return zero, zero
	}

	// T = D^3/(4xy)
	t := d.Mul(d).Mul(d).Quo(x.Mul(y).MulRaw(4))
	twoA := sdkmath.NewIntFromUint64(2 * pool.Amplification)

	// price of A in B = (2A*x + T)*y / ((2A*y + T)*x)
	numA := twoA.Mul(x).Add(t).Mul(y).Mul(priceScaleInt)
	denA := twoA.Mul(y).Add(t).Mul(x)
	if !denA.IsPositive() {
		return zero, zero
	}

	numB := twoA.Mul(y).Add(t).Mul(x).Mul(priceScaleInt)
	denB := twoA.Mul(x).Add(t).Mul(y)
	if !denB.IsPositive() {
		return zero, zero
	}

	return numA.Quo(denA), numB.Quo(denB)
}

// poolAmountOut prices an exact input against a pool, dispatching on its curve.
func (k Keeper) poolAmountOut(pool types.Pool, aToB bool, amountIn sdkmath.Int) sdkmath.Int {
	if pool.PoolType == types.PoolType_POOL_TYPE_STABLESWAP {
		if aToB {
			return stableAmountOut(
				pool.ReserveA, pool.ReserveB,
				pool.ScalingFactorA, pool.ScalingFactorB,
				pool.Amplification, pool.FeeBps, amountIn,
			)
		}
		return stableAmountOut(
			pool.ReserveB, pool.ReserveA,
			pool.ScalingFactorB, pool.ScalingFactorA,
			pool.Amplification, pool.FeeBps, amountIn,
		)
	}

	var reserveIn, reserveOut sdkmath.Int
	if aToB {
		reserveIn, reserveOut = pool.ReserveA, pool.ReserveB
	} else {
		reserveIn, reserveOut = pool.ReserveB, pool.ReserveA
	}

	return calcAmountOut(amountIn, reserveIn, reserveOut, pool.FeeBps)
}

// poolAmountIn prices an exact output against a pool, dispatching on its curve.
func (k Keeper) poolAmountIn(pool types.Pool, aToB bool, amountOut sdkmath.Int) sdkmath.Int {
	if pool.PoolType == types.PoolType_POOL_TYPE_STABLESWAP {
		if aToB {
			return stableAmountIn(
				pool.ReserveA, pool.ReserveB,
				pool.ScalingFactorA, pool.ScalingFactorB,
				pool.Amplification, pool.FeeBps, amountOut,
			)
		}
		return stableAmountIn(
			pool.ReserveB, pool.ReserveA,
			pool.ScalingFactorB, pool.ScalingFactorA,
			pool.Amplification, pool.FeeBps, amountOut,
		)
	}

	var reserveIn, reserveOut sdkmath.Int
	if aToB {
		reserveIn, reserveOut = pool.ReserveA, pool.ReserveB
	} else {
		reserveIn, reserveOut = pool.ReserveB, pool.ReserveA
	}

	return calcAmountInExactOut(amountOut, reserveIn, reserveOut, pool.FeeBps)
}
