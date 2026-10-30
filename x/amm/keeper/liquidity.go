package keeper

import (
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/karsahq/karsa/x/amm/types"

	sdkmath "cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// ceilDiv returns ceil(x / y) for positive y.
func ceilDiv(x, y sdkmath.Int) sdkmath.Int {
	return x.Add(y).SubRaw(1).Quo(y)
}

// AddLiquidity deposits both assets proportionally and mints LP shares.
func (k Keeper) AddLiquidity(
	ctx sdk.Context,
	sender sdk.AccAddress,
	poolID uint64,
	amountA, amountB, minShares sdkmath.Int,
) (sdkmath.Int, error) {
	pool, found := k.GetPool(ctx, poolID)
	if !found {
		return sdkmath.Int{}, types.ErrPoolNotFound.Wrapf("pool %d", poolID)
	}
	if pool.Status != types.PoolStatus_ACTIVE {
		return sdkmath.Int{}, types.ErrPoolInactive.Wrapf("pool %d status is %s", poolID, pool.Status)
	}
	if !amountA.IsPositive() || !amountB.IsPositive() {
		return sdkmath.Int{}, types.ErrInvalidAmount.Wrap("amounts must be positive")
	}
	if !pool.TotalShares.IsPositive() || !pool.ReserveA.IsPositive() || !pool.ReserveB.IsPositive() {
		return sdkmath.Int{}, types.ErrInsufficientInitLiquidity.Wrap("pool has no liquidity")
	}

	sharesA := amountA.Mul(pool.TotalShares).Quo(pool.ReserveA)
	sharesB := amountB.Mul(pool.TotalShares).Quo(pool.ReserveB)
	shares := sdkmath.MinInt(sharesA, sharesB)
	if !shares.IsPositive() {
		return sdkmath.Int{}, types.ErrInvalidAmount.Wrap("deposit too small to mint shares")
	}
	if shares.LT(minShares) {
		return sdkmath.Int{}, types.ErrSlippageExceeded.Wrapf("shares %s below min %s", shares, minShares)
	}

	// Pull exactly the amounts matching the minted shares (round up).
	usedA := ceilDiv(shares.Mul(pool.ReserveA), pool.TotalShares)
	usedB := ceilDiv(shares.Mul(pool.ReserveB), pool.TotalShares)
	if usedA.GT(amountA) || usedB.GT(amountB) {
		return sdkmath.Int{}, types.ErrInvalidAmount.Wrap("deposit does not match pool ratio")
	}

	depositA, err := k.resolveAsset(ctx, pool.AssetA)
	if err != nil {
		return sdkmath.Int{}, err
	}
	depositB, err := k.resolveAsset(ctx, pool.AssetB)
	if err != nil {
		return sdkmath.Int{}, err
	}

	senderAddr := common.BytesToAddress(sender.Bytes())
	if err := k.moveIn(ctx, pool.Id, depositA, senderAddr, usedA); err != nil {
		return sdkmath.Int{}, types.ErrInsufficientFunds.Wrapf("deposit %s: %s", pool.AssetA, err)
	}
	if err := k.moveIn(ctx, pool.Id, depositB, senderAddr, usedB); err != nil {
		return sdkmath.Int{}, types.ErrInsufficientFunds.Wrapf("deposit %s: %s", pool.AssetB, err)
	}

	coins := sdk.NewCoins(sdk.NewCoin(pool.LpDenom, shares))
	if err := k.bankKeeper.MintCoins(ctx, types.ModuleName, coins); err != nil {
		return sdkmath.Int{}, err
	}
	if err := k.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, sender, coins); err != nil {
		return sdkmath.Int{}, err
	}

	pool.ReserveA = pool.ReserveA.Add(usedA)
	pool.ReserveB = pool.ReserveB.Add(usedB)
	pool.TotalShares = pool.TotalShares.Add(shares)
	k.SetPool(ctx, pool)
	k.updateOracle(ctx, pool)

	ctx.EventManager().EmitEvent(sdk.NewEvent(
		types.EventTypeAddLiquidity,
		sdk.NewAttribute(types.AttributeKeyPoolID, strconv.FormatUint(poolID, 10)),
		sdk.NewAttribute(types.AttributeKeyAmountA, usedA.String()),
		sdk.NewAttribute(types.AttributeKeyAmountB, usedB.String()),
		sdk.NewAttribute(types.AttributeKeyShares, shares.String()),
	))

	return shares, nil
}

// RemoveLiquidity burns LP shares and returns the proportional reserves.
func (k Keeper) RemoveLiquidity(
	ctx sdk.Context,
	sender sdk.AccAddress,
	poolID uint64,
	shares, minA, minB sdkmath.Int,
) (sdkmath.Int, sdkmath.Int, error) {
	pool, found := k.GetPool(ctx, poolID)
	if !found {
		return sdkmath.Int{}, sdkmath.Int{}, types.ErrPoolNotFound.Wrapf("pool %d", poolID)
	}
	if !shares.IsPositive() {
		return sdkmath.Int{}, sdkmath.Int{}, types.ErrInvalidAmount.Wrap("shares must be positive")
	}

	redeemable := pool.TotalShares.Sub(pool.LockedShares)
	if shares.GT(redeemable) {
		return sdkmath.Int{}, sdkmath.Int{}, types.ErrInvalidAmount.Wrap("shares exceed redeemable supply")
	}

	balance := k.bankKeeper.SpendableCoins(ctx, sender).AmountOf(pool.LpDenom)
	if balance.LT(shares) {
		return sdkmath.Int{}, sdkmath.Int{}, types.ErrInsufficientFunds.Wrapf(
			"lp balance %s below requested %s", balance, shares,
		)
	}

	outA := shares.Mul(pool.ReserveA).Quo(pool.TotalShares)
	outB := shares.Mul(pool.ReserveB).Quo(pool.TotalShares)
	if !outA.IsPositive() || !outB.IsPositive() {
		return sdkmath.Int{}, sdkmath.Int{}, types.ErrInvalidAmount.Wrap("withdrawal too small")
	}
	if outA.LT(minA) || outB.LT(minB) {
		return sdkmath.Int{}, sdkmath.Int{}, types.ErrSlippageExceeded.Wrap("output below minimum")
	}

	assetOutA, err := k.resolveAsset(ctx, pool.AssetA)
	if err != nil {
		return sdkmath.Int{}, sdkmath.Int{}, err
	}
	assetOutB, err := k.resolveAsset(ctx, pool.AssetB)
	if err != nil {
		return sdkmath.Int{}, sdkmath.Int{}, err
	}

	// Burn LP shares first so the withdrawal cannot be replayed.
	coins := sdk.NewCoins(sdk.NewCoin(pool.LpDenom, shares))
	if err := k.bankKeeper.SendCoinsFromAccountToModule(ctx, sender, types.ModuleName, coins); err != nil {
		return sdkmath.Int{}, sdkmath.Int{}, types.ErrInsufficientFunds.Wrap(err.Error())
	}
	if err := k.bankKeeper.BurnCoins(ctx, types.ModuleName, coins); err != nil {
		return sdkmath.Int{}, sdkmath.Int{}, err
	}

	senderAddr := common.BytesToAddress(sender.Bytes())
	if err := k.moveOut(ctx, pool.Id, assetOutA, senderAddr, outA); err != nil {
		return sdkmath.Int{}, sdkmath.Int{}, err
	}
	if err := k.moveOut(ctx, pool.Id, assetOutB, senderAddr, outB); err != nil {
		return sdkmath.Int{}, sdkmath.Int{}, err
	}

	pool.ReserveA = pool.ReserveA.Sub(outA)
	pool.ReserveB = pool.ReserveB.Sub(outB)
	pool.TotalShares = pool.TotalShares.Sub(shares)
	k.SetPool(ctx, pool)
	k.updateOracle(ctx, pool)

	ctx.EventManager().EmitEvent(sdk.NewEvent(
		types.EventTypeRemoveLiquidity,
		sdk.NewAttribute(types.AttributeKeyPoolID, strconv.FormatUint(poolID, 10)),
		sdk.NewAttribute(types.AttributeKeyAmountA, outA.String()),
		sdk.NewAttribute(types.AttributeKeyAmountB, outB.String()),
		sdk.NewAttribute(types.AttributeKeyShares, shares.String()),
	))

	return outA, outB, nil
}
