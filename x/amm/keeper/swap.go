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

// validatePoolIDs checks that an optional pool-id list has one entry per hop.
func validatePoolIDs(path []string, poolIDs []uint64) error {
	if len(poolIDs) == 0 {
		return nil
	}
	if len(poolIDs) != len(path)-1 {
		return types.ErrInvalidPath.Wrapf(
			"pool_ids has %d entries, path needs %d", len(poolIDs), len(path)-1,
		)
	}
	return nil
}

// poolForHop returns the pool connecting assetIn and assetOut and whether
// assetIn is the pool's asset A. A zero poolID means the pair must have exactly
// one pool; otherwise the caller must disambiguate by pool id.
func (k Keeper) poolForHop(
	ctx sdk.Context, assetIn, assetOut string, poolID uint64,
) (types.Pool, bool, error) {
	in := strings.ToLower(assetIn)
	out := strings.ToLower(assetOut)
	if in == out {
		return types.Pool{}, false, types.ErrInvalidPath.Wrap("duplicate asset in path")
	}

	keyA, keyB := in, out
	if keyA > keyB {
		keyA, keyB = keyB, keyA
	}

	var pool types.Pool
	var found bool

	if poolID != 0 {
		pool, found = k.GetPool(ctx, poolID)
		if !found {
			return types.Pool{}, false, types.ErrPoolNotFound.Wrapf("pool %d", poolID)
		}
		if (pool.AssetA != keyA || pool.AssetB != keyB) && (pool.AssetA != keyB || pool.AssetB != keyA) {
			return types.Pool{}, false, types.ErrInvalidPath.Wrapf(
				"pool %d does not connect %s/%s", poolID, keyA, keyB,
			)
		}
	} else {
		ids := k.GetPoolIDsByAssets(ctx, keyA, keyB)
		if len(ids) == 0 {
			return types.Pool{}, false, types.ErrPoolNotFound.Wrapf("no pool for %s/%s", keyA, keyB)
		}
		if len(ids) > 1 {
			return types.Pool{}, false, types.ErrInvalidPath.Wrapf(
				"multiple pools for %s/%s; specify pool_id", keyA, keyB,
			)
		}
		pool, found = k.GetPool(ctx, ids[0])
		if !found {
			return types.Pool{}, false, types.ErrPoolNotFound.Wrapf("pool %d", ids[0])
		}
	}

	if pool.Status != types.PoolStatus_ACTIVE {
		return types.Pool{}, false, types.ErrPoolInactive.Wrapf("pool %d status is %s", pool.Id, pool.Status)
	}

	return pool, in == pool.AssetA, nil
}

// poolCandidate is a candidate pool for one hop.
type poolCandidate struct {
	pool types.Pool
	aIsA bool
}

// candidatePools returns all active pools for a pair.
func (k Keeper) candidatePools(ctx sdk.Context, assetIn, assetOut string) ([]poolCandidate, error) {
	in := strings.ToLower(assetIn)
	out := strings.ToLower(assetOut)
	if in == out {
		return nil, types.ErrInvalidPath.Wrap("duplicate asset in path")
	}

	keyA, keyB := in, out
	if keyA > keyB {
		keyA, keyB = keyB, keyA
	}

	ids := k.GetPoolIDsByAssets(ctx, keyA, keyB)
	if len(ids) == 0 {
		return nil, types.ErrPoolNotFound.Wrapf("no pool for %s/%s", keyA, keyB)
	}

	candidates := make([]poolCandidate, 0, len(ids))
	foundPool := false
	for _, id := range ids {
		pool, found := k.GetPool(ctx, id)
		if !found {
			continue
		}
		foundPool = true
		if pool.Status != types.PoolStatus_ACTIVE {
			continue
		}
		if (pool.AssetA != keyA || pool.AssetB != keyB) && (pool.AssetA != keyB || pool.AssetB != keyA) {
			continue
		}
		candidates = append(candidates, poolCandidate{pool: pool, aIsA: in == pool.AssetA})
	}

	if len(candidates) == 0 {
		if foundPool {
			return nil, types.ErrPoolInactive.Wrapf("no active pool for %s/%s", keyA, keyB)
		}
		return nil, types.ErrPoolNotFound.Wrapf("no pool for %s/%s", keyA, keyB)
	}

	return candidates, nil
}

// bestPoolForExactIn selects the pool with the largest output for amountIn.
// A non-zero poolID forces a specific pool.
func (k Keeper) bestPoolForExactIn(
	ctx sdk.Context, assetIn, assetOut string, amountIn sdkmath.Int, poolID uint64,
) (types.Pool, bool, error) {
	if poolID != 0 {
		return k.poolForHop(ctx, assetIn, assetOut, poolID)
	}

	candidates, err := k.candidatePools(ctx, assetIn, assetOut)
	if err != nil {
		return types.Pool{}, false, err
	}

	var best types.Pool
	var bestA bool
	bestOut := sdkmath.ZeroInt()

	for _, candidate := range candidates {
		out := k.poolAmountOut(candidate.pool, candidate.aIsA, amountIn)
		if out.GT(bestOut) {
			best = candidate.pool
			bestA = candidate.aIsA
			bestOut = out
		}
	}

	if !bestOut.IsPositive() {
		return types.Pool{}, false, types.ErrInvalidAmount.Wrap("no pool can satisfy the input")
	}

	return best, bestA, nil
}

// bestPoolForExactOut selects the pool with the smallest required input.
// A non-zero poolID forces a specific pool.
func (k Keeper) bestPoolForExactOut(
	ctx sdk.Context, assetIn, assetOut string, amountOut sdkmath.Int, poolID uint64,
) (types.Pool, bool, error) {
	if poolID != 0 {
		return k.poolForHop(ctx, assetIn, assetOut, poolID)
	}

	candidates, err := k.candidatePools(ctx, assetIn, assetOut)
	if err != nil {
		return types.Pool{}, false, err
	}

	var best types.Pool
	var bestA bool
	bestIn := sdkmath.ZeroInt()

	for _, candidate := range candidates {
		in := k.poolAmountIn(candidate.pool, candidate.aIsA, amountOut)
		if !in.IsPositive() {
			continue
		}
		if !bestIn.IsPositive() || in.LT(bestIn) {
			best = candidate.pool
			bestA = candidate.aIsA
			bestIn = in
		}
	}

	if !bestIn.IsPositive() {
		return types.Pool{}, false, types.ErrInvalidAmount.Wrap("no pool can satisfy the output")
	}

	return best, bestA, nil
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
	return k.QuoteExactOutWithPools(ctx, path, nil, amountOut)
}

// QuoteExactOutWithPools is QuoteExactOut with optional explicit pool ids.
func (k Keeper) QuoteExactOutWithPools(
	ctx sdk.Context, path []string, poolIDs []uint64, amountOut sdkmath.Int,
) (sdkmath.Int, error) {
	if err := k.validatePath(ctx, path); err != nil {
		return sdkmath.Int{}, err
	}
	if err := validatePoolIDs(path, poolIDs); err != nil {
		return sdkmath.Int{}, err
	}
	if !amountOut.IsPositive() {
		return sdkmath.Int{}, types.ErrInvalidAmount.Wrap("amount_out must be positive")
	}

	need := amountOut
	for i := len(path) - 1; i > 0; i-- {
		poolID := uint64(0)
		if len(poolIDs) > 0 {
			poolID = poolIDs[i-1]
		}
		pool, aIsA, err := k.bestPoolForExactOut(ctx, path[i-1], path[i], need, poolID)
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
	return k.QuoteWithPools(ctx, path, nil, amountIn)
}

// QuoteWithPools is Quote with optional explicit pool ids.
func (k Keeper) QuoteWithPools(
	ctx sdk.Context, path []string, poolIDs []uint64, amountIn sdkmath.Int,
) (sdkmath.Int, error) {
	if err := k.validatePath(ctx, path); err != nil {
		return sdkmath.Int{}, err
	}
	if err := validatePoolIDs(path, poolIDs); err != nil {
		return sdkmath.Int{}, err
	}
	if !amountIn.IsPositive() {
		return sdkmath.Int{}, types.ErrInvalidAmount.Wrap("amount_in must be positive")
	}

	amount := amountIn
	for i := 0; i < len(path)-1; i++ {
		poolID := uint64(0)
		if len(poolIDs) > 0 {
			poolID = poolIDs[i]
		}
		pool, aIsA, err := k.bestPoolForExactIn(ctx, path[i], path[i+1], amount, poolID)
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
	return k.SwapWithPools(
		ctx, nil, sender, receiver, path, amountIn, minOut, integrator, integratorFeeBps,
	)
}

// SwapWithPools executes an exact-input swap with optional explicit pool ids.
func (k Keeper) SwapWithPools(
	ctx sdk.Context,
	poolIDs []uint64,
	sender, receiver sdk.AccAddress,
	path []string,
	amountIn, minOut sdkmath.Int,
	integrator sdk.AccAddress,
	integratorFeeBps uint32,
) (sdkmath.Int, sdkmath.Int, error) {
	return k.swapExec(
		ctx, nil, false, poolIDs, sender, receiver, path, amountIn, minOut, integrator, integratorFeeBps,
	)
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
	return k.SwapFromPrecompileWithPools(
		ctx, stateDB, caller, receiver, path, nil, amountIn, minOut, integrator, integratorFeeBps,
	)
}

// SwapFromPrecompileWithPools is SwapFromPrecompile with explicit pool ids.
func (k Keeper) SwapFromPrecompileWithPools(
	ctx sdk.Context,
	stateDB *statedb.StateDB,
	caller, receiver common.Address,
	path []string,
	poolIDs []uint64,
	amountIn, minOut sdkmath.Int,
	integrator common.Address,
	integratorFeeBps uint32,
) (sdkmath.Int, sdkmath.Int, error) {
	if err := k.acquireLock(ctx); err != nil {
		return sdkmath.Int{}, sdkmath.Int{}, err
	}
	defer k.releaseLock(ctx)

	sender := sdk.AccAddress(caller.Bytes())
	recv := sdk.AccAddress(receiver.Bytes())

	var integratorAcc sdk.AccAddress
	if integrator != (common.Address{}) {
		integratorAcc = sdk.AccAddress(integrator.Bytes())
	}

	return k.swapExec(
		ctx, stateDB, true, poolIDs, sender, recv, path, amountIn, minOut, integratorAcc, integratorFeeBps,
	)
}

func (k Keeper) swapExec(
	ctx sdk.Context,
	stateDB *statedb.StateDB,
	fromPrecompile bool,
	poolIDs []uint64,
	sender, receiver sdk.AccAddress,
	path []string,
	amountIn, minOut sdkmath.Int,
	integrator sdk.AccAddress,
	integratorFeeBps uint32,
) (sdkmath.Int, sdkmath.Int, error) {
	if err := k.validatePath(ctx, path); err != nil {
		return sdkmath.Int{}, sdkmath.Int{}, err
	}
	if err := validatePoolIDs(path, poolIDs); err != nil {
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
	if integrator != nil && !integrator.Equals(sender) && integratorFeeBps > 0 {
		integratorFee = amountIn.MulRaw(int64(integratorFeeBps)).QuoRaw(10_000)
	}

	if err := k.payIntegratorFee(ctx, stateDB, fromPrecompile, first, sender, integrator, integratorFee); err != nil {
		return sdkmath.Int{}, sdkmath.Int{}, err
	}

	amount := amountIn.Sub(integratorFee)
	if !amount.IsPositive() {
		return sdkmath.Int{}, sdkmath.Int{}, types.ErrInvalidAmount.Wrap("integrator fee consumes the full input")
	}

	// Resolve the first hop before moving the input in: with direct custody the
	// input has to land on the first pool's custody account.
	firstPoolID := uint64(0)
	if len(poolIDs) > 0 {
		firstPoolID = poolIDs[0]
	}
	firstPool, firstAIsA, err := k.bestPoolForExactIn(ctx, path[0], path[1], amount, firstPoolID)
	if err != nil {
		return sdkmath.Int{}, sdkmath.Int{}, err
	}

	// Pull the pool input into custody.
	if err := k.moveInWith(ctx, firstPool.Id, stateDB, fromPrecompile, first, common.BytesToAddress(sender.Bytes()), amount); err != nil {
		return sdkmath.Int{}, sdkmath.Int{}, err
	}

	lastPoolID := firstPool.Id
	for i := 0; i < len(path)-1; i++ {
		var (
			pool types.Pool
			aIsA bool
		)
		if i == 0 {
			pool, aIsA = firstPool, firstAIsA
		} else {
			poolID := uint64(0)
			if len(poolIDs) > 0 {
				poolID = poolIDs[i]
			}
			pool, aIsA, err = k.bestPoolForExactIn(ctx, path[i], path[i+1], amount, poolID)
			if err != nil {
				return sdkmath.Int{}, sdkmath.Int{}, err
			}
		}
		lastPoolID = pool.Id

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

		if stateDB != nil {
			if err := types.EmitSwapLog(
				stateDB, common.BytesToAddress(sender.Bytes()), pool.Id,
				common.HexToAddress(path[i]), amount,
				common.HexToAddress(path[i+1]), out,
			); err != nil {
				return sdkmath.Int{}, sdkmath.Int{}, err
			}
		}

		amount = out
	}

	if amount.LT(minOut) {
		return sdkmath.Int{}, sdkmath.Int{}, types.ErrSlippageExceeded.Wrapf(
			"amount_out %s below min_out %s", amount, minOut,
		)
	}

	if err := k.moveOutWith(ctx, lastPoolID, stateDB, fromPrecompile, last, common.BytesToAddress(receiver.Bytes()), amount); err != nil {
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

// payIntegratorFee pays the integrator in the input token before conversion.
// For bank assets this is a bank send; for external ERC20 it is a direct
// contract transfer, so the fee is never converted to bank denom.
func (k Keeper) payIntegratorFee(
	ctx sdk.Context,
	stateDB *statedb.StateDB,
	fromPrecompile bool,
	asset resolvedAsset,
	sender, integrator sdk.AccAddress,
	amount sdkmath.Int,
) error {
	if !amount.IsPositive() || integrator == nil || sender.Equals(integrator) {
		return nil
	}

	from := common.BytesToAddress(sender.Bytes())
	to := common.BytesToAddress(integrator.Bytes())

	if asset.ConvertContract != (common.Address{}) {
		return k.evmTransferWith(ctx, stateDB, fromPrecompile, asset.ConvertContract, from, to, amount)
	}

	coins := sdk.NewCoins(sdk.NewCoin(asset.Denom, amount))
	return k.bankKeeper.SendCoins(ctx, sender, integrator, coins)
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
	return k.SwapExactOutWithPools(
		ctx, nil, sender, receiver, path, amountOut, maxAmountIn, integrator, integratorFeeBps,
	)
}

// SwapExactOutWithPools is SwapExactOut with optional explicit pool ids.
func (k Keeper) SwapExactOutWithPools(
	ctx sdk.Context,
	poolIDs []uint64,
	sender, receiver sdk.AccAddress,
	path []string,
	amountOut, maxAmountIn sdkmath.Int,
	integrator sdk.AccAddress,
	integratorFeeBps uint32,
) (sdkmath.Int, sdkmath.Int, error) {
	if err := k.validatePath(ctx, path); err != nil {
		return sdkmath.Int{}, sdkmath.Int{}, err
	}
	if err := validatePoolIDs(path, poolIDs); err != nil {
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
		poolID := uint64(0)
		if len(poolIDs) > 0 {
			poolID = poolIDs[i-1]
		}
		pool, aIsA, err := k.bestPoolForExactOut(ctx, path[i-1], path[i], need, poolID)
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
	if integrator != nil && !integrator.Equals(sender) && integratorFeeBps > 0 {
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

	if err := k.payIntegratorFee(ctx, nil, false, first, sender, integrator, integratorFee); err != nil {
		return sdkmath.Int{}, sdkmath.Int{}, err
	}

	if len(hops) == 0 {
		return sdkmath.Int{}, sdkmath.Int{}, types.ErrInvalidPath.Wrap("no hops")
	}

	firstHopPoolID := hops[0].pool.Id
	if err := k.moveIn(ctx, firstHopPoolID, first, common.BytesToAddress(sender.Bytes()), need); err != nil {
		return sdkmath.Int{}, sdkmath.Int{}, err
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

	lastHopPoolID := hops[len(hops)-1].pool.Id
	if err := k.moveOut(ctx, lastHopPoolID, last, common.BytesToAddress(receiver.Bytes()), amountOut); err != nil {
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
