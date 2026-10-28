package keeper

import (
	"testing"

	sdkmath "cosmossdk.io/math"

	"github.com/karsahq/karsa/x/amm/types"
)

func poolWithReserves(a, b sdkmath.Int) types.Pool {
	return types.Pool{
		ReserveA:       a,
		ReserveB:       b,
		PoolType:       types.PoolType_POOL_TYPE_STABLESWAP,
		Amplification:  100,
		ScalingFactorA: 1,
		ScalingFactorB: 1,
	}
}

func TestScalingFactor(t *testing.T) {
	tests := []struct {
		decimals uint8
		want     uint64
	}{
		{18, 1},
		{6, 1_000_000_000_000},
		{0, 1_000_000_000_000_000_000},
	}

	for _, tc := range tests {
		got, err := scalingFactor(tc.decimals)
		if err != nil {
			t.Fatalf("scalingFactor(%d) error: %s", tc.decimals, err)
		}
		if got != tc.want {
			t.Fatalf("scalingFactor(%d) = %d, want %d", tc.decimals, got, tc.want)
		}
	}

	if _, err := scalingFactor(19); err == nil {
		t.Fatal("scalingFactor(19) should fail")
	}
}

func TestStableInvariantBalanced(t *testing.T) {
	reserve := sdkmath.NewIntWithDecimal(1, 6)

	for _, amp := range []uint64{1, 10, 100, 1_000} {
		d := stableInvariant(reserve, reserve, amp)
		want := reserve.MulRaw(2)
		if d.Sub(want).Abs().GT(sdkmath.NewInt(2)) {
			t.Fatalf("A=%d: D = %s, want ~%s", amp, d, want)
		}
	}
}

func TestStableInvariantHomogeneous(t *testing.T) {
	x := sdkmath.NewIntWithDecimal(3, 6)
	y := sdkmath.NewIntWithDecimal(1, 6)
	amp := uint64(100)

	d1 := stableInvariant(x, y, amp)
	d2 := stableInvariant(x.MulRaw(10), y.MulRaw(10), amp)

	if !d2.Equal(d1.MulRaw(10)) {
		// Allow rounding drift of a few units.
		if d2.Sub(d1.MulRaw(10)).Abs().GT(sdkmath.NewInt(100)) {
			t.Fatalf("D is not homogeneous: %s vs %s", d1.MulRaw(10), d2)
		}
	}
}

func TestStableAmountOutNearPeg(t *testing.T) {
	reserve := sdkmath.NewIntWithDecimal(1, 6)
	amountIn := sdkmath.NewInt(10_000)

	out := stableAmountOut(reserve, reserve, 1, 1, 100, 30, amountIn)
	if !out.IsPositive() {
		t.Fatal("expected a positive output")
	}
	// A constant-product pool would return ~9_871; stableswap should be much
	// closer to the input.
	if out.LT(sdkmath.NewInt(9_900)) {
		t.Fatalf("stableswap output too low: %s", out)
	}
	if out.GT(amountIn) {
		t.Fatalf("output %s exceeds input %s", out, amountIn)
	}
}

func TestStableAmountOutAndInRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		x       int64
		y       int64
		amount  int64
		amp     uint64
		feeBps  uint32
		maxLoss int64
	}{
		{name: "balanced 30bps", x: 1_000_000, y: 1_000_000, amount: 10_000, amp: 100, feeBps: 30, maxLoss: 2},
		{name: "balanced zero fee", x: 1_000_000, y: 1_000_000, amount: 10_000, amp: 100, feeBps: 0, maxLoss: 1},
		{name: "large trade", x: 1_000_000, y: 1_000_000, amount: 300_000, amp: 100, feeBps: 30, maxLoss: 2},
		{name: "low amplification", x: 1_000_000, y: 1_000_000, amount: 50_000, amp: 1, feeBps: 30, maxLoss: 2},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			x := sdkmath.NewInt(tc.x)
			y := sdkmath.NewInt(tc.y)
			amountIn := sdkmath.NewInt(tc.amount)

			out := stableAmountOut(x, y, 1, 1, tc.amp, tc.feeBps, amountIn)
			if !out.IsPositive() {
				t.Fatal("expected a positive output")
			}

			inBack := stableAmountIn(x, y, 1, 1, tc.amp, tc.feeBps, out)
			if !inBack.IsPositive() {
				t.Fatal("expected a positive round-trip input")
			}
			if inBack.GT(amountIn) {
				t.Fatalf("round trip requires more input: %s > %s", inBack, amountIn)
			}
			if amountIn.Sub(inBack).GT(sdkmath.NewInt(tc.maxLoss)) {
				t.Fatalf("round-trip drift too large: in=%s back=%s", amountIn, inBack)
			}
		})
	}
}

func TestStableAmountInDeliversAtLeastRequested(t *testing.T) {
	x := sdkmath.NewIntWithDecimal(2, 6)
	y := sdkmath.NewIntWithDecimal(1, 6)

	for _, amountOut := range []int64{1, 1_000, 50_000, 400_000} {
		out := sdkmath.NewInt(amountOut)
		in := stableAmountIn(x, y, 1, 1, 100, 30, out)
		if !in.IsPositive() {
			t.Fatalf("amountOut=%d: no input found", amountOut)
		}

		got := stableAmountOut(x, y, 1, 1, 100, 30, in)
		if got.LT(out) {
			t.Fatalf("amountOut=%d: input %s delivers only %s", amountOut, in, got)
		}
		if got.Sub(out).GT(sdkmath.NewInt(2)) {
			t.Fatalf("amountOut=%d: overshoot %s", amountOut, got.Sub(out))
		}
	}
}

func TestStableAmountOutExceedsReserve(t *testing.T) {
	x := sdkmath.NewInt(1_000_000)
	y := sdkmath.NewInt(1_000_000)

	if got := stableAmountIn(x, y, 1, 1, 100, 30, y); !got.IsZero() {
		t.Fatalf("expected zero for output equal to reserve, got %s", got)
	}
	if got := stableAmountIn(x, y, 1, 1, 100, 30, y.AddRaw(1)); !got.IsZero() {
		t.Fatalf("expected zero for output above reserve, got %s", got)
	}
}

func TestStableSpotPrices(t *testing.T) {
	one := sdkmath.NewIntWithDecimal(1, 6)

	aToB, bToA := stableSpotPrices(poolWithReserves(one, one))
	if !aToB.Equal(priceScaleInt) || !bToA.Equal(priceScaleInt) {
		t.Fatalf("balanced prices = %s/%s, want 1", aToB, bToA)
	}

	// A is abundant, so A must be cheaper than B.
	aToB, bToA = stableSpotPrices(poolWithReserves(sdkmath.NewInt(1_200_000), sdkmath.NewInt(800_000)))
	if !aToB.LT(priceScaleInt) {
		t.Fatalf("price of abundant A = %s, want < 1", aToB)
	}
	if !bToA.GT(priceScaleInt) {
		t.Fatalf("price of scarce B = %s, want > 1", bToA)
	}
}
