package keeper

import (
	"strings"

	"github.com/karsahq/karsa/x/amm/types"

	sdkmath "cosmossdk.io/math"

	"github.com/ethereum/go-ethereum/common"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/evm/x/vm/statedb"
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

// calcAmountInExactOut returns the input required to receive exactly amountOut.
// It returns zero when the request cannot be satisfied by the pool.
func calcAmountInExactOut(amountOut, reserveIn, reserveOut sdkmath.Int, feeBps uint32) sdkmath.Int {
	if !amountOut.IsPositive() || !reserveIn.IsPositive() || !reserveOut.IsPositive() {
		return sdkmath.ZeroInt()
	}
	if amountOut.GTE(reserveOut) {
		return sdkmath.ZeroInt()
	}

	feeFactor := sdkmath.NewInt(int64(10_000 - feeBps))

	// inAfterFee = amountOut * reserveIn * 1e4 / (reserveOut - amountOut)
	numerator := amountOut.Mul(reserveIn).MulRaw(10_000)
	denominator := reserveOut.Sub(amountOut)
	inAfterFee := ceilDiv(numerator, denominator)

	// in = inAfterFee / feeFactor, rounded up. inAfterFee is already scaled by
	// (10_000 - feeBps) by the constant-product definition of calcAmountOut.
	return ceilDiv(inAfterFee, feeFactor)
}

// QuoteExactOut computes the input required to receive exactly amountOut.
func (k Keeper) QuoteExactOut(ctx sdk.Context, path []string, amountOut sdkmath.Int) (sdkmath.Int, error) {
	if err := k.validatePath(ctx, path); err != nil {
		return sdkmath.Int{}, err
	}
	if !amountOut.IsPositive() {
		return sdkmath.Int{}, types.ErrInvalidAmount.Wrap("amount_out must be positive")
	}

	need := amountOut
	for i := len(path) - 1; i > 0; i-- {
		pool, aIsA, err := k.poolForHop(ctx, path[i-1], path[i])
		if err != nil {
			return sdkmath.Int{}, err
		}

		need = k.poolAmountIn(pool, aIsA, need)
		if !need.IsPositive() {
			return sdkmath.Int{}, types.ErrInvalidAmount.Wrapf(
				"insufficient liquidity for the requested output at hop %d", i-1,
			)
		}
	}

	return need, nil
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

		amount = k.poolAmountOut(pool, aIsA, amount)
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
	return k.swapExec(ctx, nil, false, sender, receiver, path, amountIn, minOut, integrator, integratorFeeBps)
}

// SwapFromPrecompile executes a swap on behalf of an EVM caller, reusing the
// current EVM stateDB so nested ERC20 transfers are applied atomically.
func (k Keeper) SwapFromPrecompile(
	ctx sdk.Context,
	stateDB *statedb.StateDB,
	caller, receiver common.Address,
	path []string,
	amountIn, minOut sdkmath.Int,
	integrator common.Address,
	integratorFeeBps uint32,
) (sdkmath.Int, sdkmath.Int, error) {
	sender := sdk.AccAddress(caller.Bytes())
	recv := sdk.AccAddress(receiver.Bytes())

	var integratorAcc sdk.AccAddress
	if integrator != (common.Address{}) {
		integratorAcc = sdk.AccAddress(integrator.Bytes())
	}

	return k.swapExec(ctx, stateDB, true, sender, recv, path, amountIn, minOut, integratorAcc, integratorFeeBps)
}

func (k Keeper) swapExec(
	ctx sdk.Context,
	stateDB *statedb.StateDB,
	fromPrecompile bool,
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
	if err := k.moveInWith(ctx, stateDB, fromPrecompile, first, common.BytesToAddress(sender.Bytes()), amountIn); err != nil {
		return sdkmath.Int{}, sdkmath.Int{}, types.ErrInsufficientFunds.Wrap(err.Error())
	}

	if integratorFee.IsPositive() {
		if err := k.moveOutWith(ctx, stateDB, fromPrecompile, first, common.BytesToAddress(integrator.Bytes()), integratorFee); err != nil {
			return sdkmath.Int{}, sdkmath.Int{}, err
		}
	}

	amount := amountIn.Sub(integratorFee)
	for i := 0; i < len(path)-1; i++ {
		pool, aIsA, err := k.poolForHop(ctx, path[i], path[i+1])
		if err != nil {
			return sdkmath.Int{}, sdkmath.Int{}, err
		}

		out := k.poolAmountOut(pool, aIsA, amount)
		if !out.IsPositive() {
			return sdkmath.Int{}, sdkmath.Int{}, types.ErrInvalidAmount.Wrapf("hop %d produced no output", i)
		}

		reserveOut := pool.ReserveB
		if !aIsA {
			reserveOut = pool.ReserveA
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
		k.updateOracle(ctx, pool)

		amount = out
	}

	if amount.LT(minOut) {
		return sdkmath.Int{}, sdkmath.Int{}, types.ErrSlippageExceeded.Wrapf(
			"amount_out %s below min_out %s", amount, minOut,
		)
	}

	if err := k.moveOutWith(ctx, stateDB, fromPrecompile, last, common.BytesToAddress(receiver.Bytes()), amount); err != nil {
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

// SwapExactOut executes a swap for an exact output amount, bounded by maxAmountIn.
func (k Keeper) SwapExactOut(
	ctx sdk.Context,
	sender, receiver sdk.AccAddress,
	path []string,
	amountOut, maxAmountIn sdkmath.Int,
	integrator sdk.AccAddress,
	integratorFeeBps uint32,
) (sdkmath.Int, sdkmath.Int, error) {
	if err := k.validatePath(ctx, path); err != nil {
		return sdkmath.Int{}, sdkmath.Int{}, err
	}
	if !amountOut.IsPositive() || !maxAmountIn.IsPositive() {
		return sdkmath.Int{}, sdkmath.Int{}, types.ErrInvalidAmount.Wrap("amounts must be positive")
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

	type hop struct {
		pool      types.Pool
		aIsA      bool
		amountIn  sdkmath.Int
		amountOut sdkmath.Int
	}

	hops := make([]hop, 0, len(path)-1)
	need := amountOut

	// Walk the path backwards to find the input required at each hop.
	for i := len(path) - 1; i > 0; i-- {
		pool, aIsA, err := k.poolForHop(ctx, path[i-1], path[i])
		if err != nil {
			return sdkmath.Int{}, sdkmath.Int{}, err
		}

		in := k.poolAmountIn(pool, aIsA, need)
		if !in.IsPositive() {
			return sdkmath.Int{}, sdkmath.Int{}, types.ErrInvalidAmount.Wrapf(
				"insufficient liquidity for the requested output at hop %d", i-1,
			)
		}

		hops = append(hops, hop{pool: pool, aIsA: aIsA, amountIn: in, amountOut: need})
		need = in
	}

	// The hops were collected in reverse order.
	for i, j := 0, len(hops)-1; i < j; i, j = i+1, j-1 {
		hops[i], hops[j] = hops[j], hops[i]
	}

	integratorFee := sdkmath.ZeroInt()
	if integrator != nil && integratorFeeBps > 0 {
		// Fee is bps of the total amount paid, so it is grossed up.
		feeFactor := sdkmath.NewInt(int64(10_000 - integratorFeeBps))
		integratorFee = ceilDiv(need.MulRaw(int64(integratorFeeBps)), feeFactor)
	}

	totalIn := need.Add(integratorFee)
	if totalIn.GT(maxAmountIn) {
		return sdkmath.Int{}, sdkmath.Int{}, types.ErrSlippageExceeded.Wrapf(
			"required input %s exceeds max_amount_in %s", totalIn, maxAmountIn,
		)
	}

	if err := k.moveIn(ctx, first, common.BytesToAddress(sender.Bytes()), totalIn); err != nil {
		return sdkmath.Int{}, sdkmath.Int{}, types.ErrInsufficientFunds.Wrap(err.Error())
	}

	if integratorFee.IsPositive() {
		if err := k.moveOut(ctx, first, common.BytesToAddress(integrator.Bytes()), integratorFee); err != nil {
			return sdkmath.Int{}, sdkmath.Int{}, err
		}
	}

	for _, h := range hops {
		pool := h.pool
		if h.aIsA {
			if h.amountOut.GTE(pool.ReserveB) {
				return sdkmath.Int{}, sdkmath.Int{}, types.ErrInvalidAmount.Wrap("output exceeds reserve")
			}
			pool.ReserveA = pool.ReserveA.Add(h.amountIn)
			pool.ReserveB = pool.ReserveB.Sub(h.amountOut)
		} else {
			if h.amountOut.GTE(pool.ReserveA) {
				return sdkmath.Int{}, sdkmath.Int{}, types.ErrInvalidAmount.Wrap("output exceeds reserve")
			}
			pool.ReserveB = pool.ReserveB.Add(h.amountIn)
			pool.ReserveA = pool.ReserveA.Sub(h.amountOut)
		}

		k.SetPool(ctx, pool)
		k.updateOracle(ctx, pool)
	}

	if err := k.moveOut(ctx, last, common.BytesToAddress(receiver.Bytes()), amountOut); err != nil {
		return sdkmath.Int{}, sdkmath.Int{}, err
	}

	ctx.EventManager().EmitEvent(sdk.NewEvent(
		types.EventTypeSwap,
		sdk.NewAttribute(types.AttributeKeySender, sender.String()),
		sdk.NewAttribute(types.AttributeKeyReceiver, receiver.String()),
		sdk.NewAttribute(types.AttributeKeyAmountIn, totalIn.String()),
		sdk.NewAttribute(types.AttributeKeyAmountOut, amountOut.String()),
		sdk.NewAttribute(types.AttributeKeyIntegratorFee, integratorFee.String()),
	))

	return totalIn, integratorFee, nil
}
