package keeper

import (
	"testing"

	sdkmath "cosmossdk.io/math"

	"github.com/karsahq/karsa/x/amm/types"
)

func TestCalcAmountOut(t *testing.T) {
	tests := []struct {
		name       string
		amountIn   int64
		reserveIn  int64
		reserveOut int64
		feeBps     uint32
		want       int64
	}{
		{
			name:       "zero fee, balanced pool",
			amountIn:   10_000,
			reserveIn:  1_000_000,
			reserveOut: 1_000_000,
			feeBps:     0,
			// out = 10_000 * 1_000_000 / (1_000_000 + 10_000) = 9900.99 -> 9900
			want: 9_900,
		},
		{
			name:       "30 bps fee, balanced pool",
			amountIn:   10_000,
			reserveIn:  1_000_000,
			reserveOut: 1_000_000,
			feeBps:     30,
			// inAfterFee = 99_700_000
			// out = 99_700_000 * 1_000_000 / (1_000_000*10_000 + 99_700_000) = 9871.57 -> 9871
			want: 9_871,
		},
		{
			name:       "zero input",
			amountIn:   0,
			reserveIn:  1_000_000,
			reserveOut: 1_000_000,
			feeBps:     30,
			want:       0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := calcAmountOut(
				sdkmath.NewInt(tc.amountIn),
				sdkmath.NewInt(tc.reserveIn),
				sdkmath.NewInt(tc.reserveOut),
				tc.feeBps,
			)
			if !got.Equal(sdkmath.NewInt(tc.want)) {
				t.Fatalf("calcAmountOut() = %s, want %d", got, tc.want)
			}
		})
	}
}

func TestCalcAmountOutDoesNotDecreaseK(t *testing.T) {
	reserveIn := sdkmath.NewInt(1_000_000)
	reserveOut := sdkmath.NewInt(1_000_000)
	amountIn := sdkmath.NewInt(10_000)

	out := calcAmountOut(amountIn, reserveIn, reserveOut, 30)

	kBefore := reserveIn.Mul(reserveOut)
	kAfter := reserveIn.Add(amountIn).Mul(reserveOut.Sub(out))

	if kAfter.LT(kBefore) {
		t.Fatalf("invariant broken: k_before=%s k_after=%s", kBefore, kAfter)
	}
}

func TestCeilDiv(t *testing.T) {
	tests := []struct{ x, y, want int64 }{
		{10, 3, 4},
		{9, 3, 3},
		{1, 3, 1},
		{0, 3, 0},
	}

	for _, tc := range tests {
		got := ceilDiv(sdkmath.NewInt(tc.x), sdkmath.NewInt(tc.y))
		if !got.Equal(sdkmath.NewInt(tc.want)) {
			t.Fatalf("ceilDiv(%d,%d) = %s, want %d", tc.x, tc.y, got, tc.want)
		}
	}
}

func TestLPDenom(t *testing.T) {
	if got := types.LPDenom(1); got != "amm/pool/1" {
		t.Fatalf("unexpected lp denom %q", got)
	}
}
