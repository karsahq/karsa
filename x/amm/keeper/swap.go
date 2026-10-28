package keeper

import (
	"strings"

	"github.com/karsahq/karsa/x/amm/types"

	sdkmath "cosmossdk.io/math"

	"github.com/ethereum/go-ethereum/common"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// validatePath checks basic swap path constraints.
func (k Keeper) validatePath(ctx sdk.Context, path []string) error {
	params := k.GetParams(ctx)

	if len(path) < 2 {
		return types.ErrInvalidPath.Wrap("path must contain at least 2 assets")
	}
	if uint32(len(path)-1) > params.MaxHops {
		return types.ErrInvalidPath.Wrapf("path has %d hops, max is %d", len(path)-1, params.MaxHops)
	}

	for i, asset := range path {
		if !common.IsHexAddress(asset) {
			return types.ErrInvalidPath.Wrapf("path[%d] %q is not an ERC20 address", i, asset)
		}
		if i > 0 && strings.EqualFold(path[i-1], asset) {
			return types.ErrInvalidPath.Wrap("path contains duplicate assets")
		}
	}

	return nil
}

// poolForHop returns the pool connecting assetIn and assetOut and whether
// assetIn is the pool's asset A.
func (k Keeper) poolForHop(ctx sdk.Context, assetIn, assetOut string) (types.Pool, bool, error) {
	in := strings.ToLower(assetIn)
	out := strings.ToLower(assetOut)
	if in == out {
		return types.Pool{}, false, types.ErrInvalidPath.Wrap("duplicate asset in path")
	}

	keyA, keyB := in, out
	if keyA > keyB {
		keyA, keyB = keyB, keyA
	}

	id, found := k.GetPoolIDByAssets(ctx, keyA, keyB)
	if !found {
		return types.Pool{}, false, types.ErrPoolNotFound.Wrapf("no pool for %s/%s", keyA, keyB)
	}

	pool, found := k.GetPool(ctx, id)
	if !found {
		return types.Pool{}, false, types.ErrPoolNotFound.Wrapf("pool %d", id)
	}

	return pool, in == pool.AssetA, nil
}

// calcAmountOut applies the constant-product formula with a fee.
func calcAmountOut(amountIn, reserveIn, reserveOut sdkmath.Int, feeBps uint32) sdkmath.Int {
	if !amountIn.IsPositive() || !reserveIn.IsPositive() || !reserveOut.IsPositive() {
		return sdkmath.ZeroInt()
	}

	feeFactor := sdkmath.NewInt(int64(10_000 - feeBps))
	inAfterFee := amountIn.Mul(feeFactor)
	denominator := reserveIn.MulRaw(10_000).Add(inAfterFee)

	return inAfterFee.Mul(reserveOut).Quo(denominator)
}

// Quote computes the output amount for a swap path without changing state.
func (k Keeper) Quote(ctx sdk.Context, path []string, amountIn sdkmath.Int) (sdkmath.Int, error) {
	if err := k.validatePath(ctx, path); err != nil {
		return sdkmath.Int{}, err
	}
	if !amountIn.IsPositive() {
		return sdkmath.Int{}, types.ErrInvalidAmount.Wrap("amount_in must be positive")
	}

	amount := amountIn
	for i := 0; i < len(path)-1; i++ {
		pool, aIsA, err := k.poolForHop(ctx, path[i], path[i+1])
		if err != nil {
			return sdkmath.Int{}, err
		}

		var reserveIn, reserveOut sdkmath.Int
		if aIsA {
			reserveIn, reserveOut = pool.ReserveA, pool.ReserveB
		} else {
			reserveIn, reserveOut = pool.ReserveB, pool.ReserveA
		}

		amount = calcAmountOut(amount, reserveIn, reserveOut, pool.FeeBps)
		if !amount.IsPositive() {
			return sdkmath.Int{}, types.ErrInvalidAmount.Wrapf("hop %d produced no output", i)
		}
	}

	return amount, nil
}

// Swap executes an exact-input swap over the given path.
//
// An optional integrator fee is taken from the input token, once, before the
// pool math. The remainder is swapped through the pools and the output is sent
// to the receiver.
func (k Keeper) Swap(
	ctx sdk.Context,
	sender, receiver sdk.AccAddress,
	path []string,
	amountIn, minOut sdkmath.Int,
	integrator sdk.AccAddress,
	integratorFeeBps uint32,
) (sdkmath.Int, sdkmath.Int, error) {
	if err := k.validatePath(ctx, path); err != nil {
		return sdkmath.Int{}, sdkmath.Int{}, err
	}
	if !amountIn.IsPositive() {
		return sdkmath.Int{}, sdkmath.Int{}, types.ErrInvalidAmount.Wrap("amount_in must be positive")
	}

	params := k.GetParams(ctx)
	if integratorFeeBps > params.MaxIntegratorFeeBps {
		return sdkmath.Int{}, sdkmath.Int{}, types.ErrInvalidFee.Wrapf(
			"integrator fee %d bps exceeds max %d bps", integratorFeeBps, params.MaxIntegratorFeeBps,
		)
	}

	first, err := k.resolveAsset(ctx, path[0])
	if err != nil {
		return sdkmath.Int{}, sdkmath.Int{}, err
	}
	last, err := k.resolveAsset(ctx, path[len(path)-1])
	if err != nil {
		return sdkmath.Int{}, sdkmath.Int{}, err
	}

	integratorFee := sdkmath.ZeroInt()
	if integrator != nil && integratorFeeBps > 0 {
		integratorFee = amountIn.MulRaw(int64(integratorFeeBps)).QuoRaw(10_000)
	}

	// Pull the full input into the module account.
	if err := k.moveIn(ctx, first, common.BytesToAddress(sender.Bytes()), amountIn); err != nil {
		return sdkmath.Int{}, sdkmath.Int{}, types.ErrInsufficientFunds.Wrap(err.Error())
	}

	if integratorFee.IsPositive() {
		if err := k.moveOut(ctx, first, common.BytesToAddress(integrator.Bytes()), integratorFee); err != nil {
			return sdkmath.Int{}, sdkmath.Int{}, err
		}
	}

	amount := amountIn.Sub(integratorFee)
	for i := 0; i < len(path)-1; i++ {
		pool, aIsA, err := k.poolForHop(ctx, path[i], path[i+1])
		if err != nil {
			return sdkmath.Int{}, sdkmath.Int{}, err
		}

		var reserveIn, reserveOut sdkmath.Int
		if aIsA {
			reserveIn, reserveOut = pool.ReserveA, pool.ReserveB
		} else {
			reserveIn, reserveOut = pool.ReserveB, pool.ReserveA
		}

		out := calcAmountOut(amount, reserveIn, reserveOut, pool.FeeBps)
		if !out.IsPositive() {
			return sdkmath.Int{}, sdkmath.Int{}, types.ErrInvalidAmount.Wrapf("hop %d produced no output", i)
		}
		if out.GTE(reserveOut) {
			return sdkmath.Int{}, sdkmath.Int{}, types.ErrInvalidAmount.Wrap("output exceeds reserve")
		}

		if aIsA {
			pool.ReserveA = pool.ReserveA.Add(amount)
			pool.ReserveB = pool.ReserveB.Sub(out)
		} else {
			pool.ReserveB = pool.ReserveB.Add(amount)
			pool.ReserveA = pool.ReserveA.Sub(out)
		}
		k.SetPool(ctx, pool)

		amount = out
	}

	if amount.LT(minOut) {
		return sdkmath.Int{}, sdkmath.Int{}, types.ErrSlippageExceeded.Wrapf(
			"amount_out %s below min_out %s", amount, minOut,
		)
	}

	if err := k.moveOut(ctx, last, common.BytesToAddress(receiver.Bytes()), amount); err != nil {
		return sdkmath.Int{}, sdkmath.Int{}, err
	}

	ctx.EventManager().EmitEvent(sdk.NewEvent(
		types.EventTypeSwap,
		sdk.NewAttribute(types.AttributeKeySender, sender.String()),
		sdk.NewAttribute(types.AttributeKeyReceiver, receiver.String()),
		sdk.NewAttribute(types.AttributeKeyAmountIn, amountIn.String()),
		sdk.NewAttribute(types.AttributeKeyAmountOut, amount.String()),
		sdk.NewAttribute(types.AttributeKeyIntegratorFee, integratorFee.String()),
	))

	return amount, integratorFee, nil
}
