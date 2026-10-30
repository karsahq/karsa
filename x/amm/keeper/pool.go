package keeper

import (
	"encoding/binary"
	"math/big"
	"strconv"
	"strings"

	"github.com/karsahq/karsa/x/amm/types"

	sdkmath "cosmossdk.io/math"

	"github.com/ethereum/go-ethereum/common"

	erc20types "github.com/cosmos/evm/x/erc20/types"

	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"

	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// GetNextPoolID returns the id that will be assigned to the next pool.
func (k Keeper) GetNextPoolID(ctx sdk.Context) uint64 {
	bz := k.Store(ctx).Get(types.NextPoolIDKey)
	if bz == nil {
		return 1
	}

	return binary.BigEndian.Uint64(bz)
}

// SetNextPoolID stores the next pool id.
func (k Keeper) SetNextPoolID(ctx sdk.Context, id uint64) {
	bz := make([]byte, 8)
	binary.BigEndian.PutUint64(bz, id)
	k.Store(ctx).Set(types.NextPoolIDKey, bz)
}

// GetPool returns the pool with the given id.
func (k Keeper) GetPool(ctx sdk.Context, id uint64) (types.Pool, bool) {
	bz := k.Store(ctx).Get(types.PoolKey(id))
	if bz == nil {
		return types.Pool{}, false
	}

	var pool types.Pool
	k.cdc.MustUnmarshal(bz, &pool)
	return pool, true
}

// SetPool stores a pool.
func (k Keeper) SetPool(ctx sdk.Context, pool types.Pool) {
	k.Store(ctx).Set(types.PoolKey(pool.Id), k.cdc.MustMarshal(&pool))
}

// GetPoolIDsByAssets returns all pool ids for an unordered asset pair.
func (k Keeper) GetPoolIDsByAssets(ctx sdk.Context, assetA, assetB string) []uint64 {
	a := strings.ToLower(assetA)
	b := strings.ToLower(assetB)
	if a > b {
		a, b = b, a
	}

	bz := k.Store(ctx).Get(types.PoolByAssetsKey(a, b))
	if bz == nil {
		return nil
	}

	return decodePoolIDs(bz)
}

// GetPoolIDByAssets returns the first pool id for an unordered asset pair.
// Callers that need to disambiguate multiple fee-tier pools must use
// GetPoolIDsByAssets or GetPoolIDByKey.
func (k Keeper) GetPoolIDByAssets(ctx sdk.Context, assetA, assetB string) (uint64, bool) {
	ids := k.GetPoolIDsByAssets(ctx, assetA, assetB)
	if len(ids) == 0 {
		return 0, false
	}
	return ids[0], true
}

// AddPoolIDByAssets appends a pool id to the pair index.
func (k Keeper) AddPoolIDByAssets(ctx sdk.Context, assetA, assetB string, id uint64) {
	a := strings.ToLower(assetA)
	b := strings.ToLower(assetB)
	if a > b {
		a, b = b, a
	}

	ids := k.GetPoolIDsByAssets(ctx, a, b)
	for _, existing := range ids {
		if existing == id {
			return
		}
	}
	k.Store(ctx).Set(types.PoolByAssetsKey(a, b), encodePoolIDs(append(ids, id)))
}

// GetPoolIDByKey returns the pool id for a specific (pair, type, fee) tuple.
func (k Keeper) GetPoolIDByKey(
	ctx sdk.Context, assetA, assetB string, poolType types.PoolType, feeBps uint32,
) (uint64, bool) {
	a := strings.ToLower(assetA)
	b := strings.ToLower(assetB)
	if a > b {
		a, b = b, a
	}

	bz := k.Store(ctx).Get(types.PoolKeyByParamsKey(a, b, poolType, feeBps))
	if bz == nil {
		return 0, false
	}

	return binary.BigEndian.Uint64(bz), true
}

// SetPoolIDByKey indexes a pool by its uniqueness key.
func (k Keeper) SetPoolIDByKey(
	ctx sdk.Context, assetA, assetB string, poolType types.PoolType, feeBps uint32, id uint64,
) {
	a := strings.ToLower(assetA)
	b := strings.ToLower(assetB)
	if a > b {
		a, b = b, a
	}

	bz := make([]byte, 8)
	binary.BigEndian.PutUint64(bz, id)
	k.Store(ctx).Set(types.PoolKeyByParamsKey(a, b, poolType, feeBps), bz)
}

// IteratePools iterates over all pools. Returning true from cb stops the iteration.
func (k Keeper) IteratePools(ctx sdk.Context, cb func(types.Pool) bool) {
	iterator := storetypes.KVStorePrefixIterator(k.Store(ctx), types.PoolKeyPrefix)
	defer iterator.Close()

	for ; iterator.Valid(); iterator.Next() {
		var pool types.Pool
		k.cdc.MustUnmarshal(iterator.Value(), &pool)
		if cb(pool) {
			return
		}
	}
}

// CountPoolsForAssets returns the number of pools for an unordered asset pair.
func (k Keeper) CountPoolsForAssets(ctx sdk.Context, assetA, assetB string) uint32 {
	return uint32(len(k.GetPoolIDsByAssets(ctx, assetA, assetB)))
}

func encodePoolIDs(ids []uint64) []byte {
	bz := make([]byte, 8*len(ids))
	for i, id := range ids {
		binary.BigEndian.PutUint64(bz[i*8:], id)
	}
	return bz
}

func decodePoolIDs(bz []byte) []uint64 {
	if len(bz)%8 != 0 {
		return nil
	}
	ids := make([]uint64, len(bz)/8)
	for i := range ids {
		ids[i] = binary.BigEndian.Uint64(bz[i*8:])
	}
	return ids
}

// CreatePool creates a constant-product pool. It is a convenience wrapper
// around CreatePoolWithType.
func (k Keeper) CreatePool(
	ctx sdk.Context,
	sender sdk.AccAddress,
	assetA, assetB string,
	feeBps uint32,
	amountA, amountB sdkmath.Int,
) (uint64, sdkmath.Int, error) {
	return k.CreatePoolWithType(
		ctx, sender, assetA, assetB, feeBps, amountA, amountB,
		types.PoolType_POOL_TYPE_CONSTANT_PRODUCT, 0,
	)
}

// CreatePoolWithType creates a new pool of the requested type, pulls the initial
// liquidity and mints LP shares.
func (k Keeper) CreatePoolWithType(
	ctx sdk.Context,
	sender sdk.AccAddress,
	assetA, assetB string,
	feeBps uint32,
	amountA, amountB sdkmath.Int,
	poolType types.PoolType,
	amplification uint64,
) (uint64, sdkmath.Int, error) {
	params := k.GetParams(ctx)

	switch poolType {
	case types.PoolType_POOL_TYPE_CONSTANT_PRODUCT:
		amplification = 0
	case types.PoolType_POOL_TYPE_STABLESWAP:
		if amplification < types.MinAmplification || amplification > types.MaxAmplification {
			return 0, sdkmath.Int{}, types.ErrInvalidParams.Wrapf(
				"amplification must be in [%d,%d], got %d",
				types.MinAmplification, types.MaxAmplification, amplification,
			)
		}
	default:
		return 0, sdkmath.Int{}, types.ErrInvalidParams.Wrapf("unknown pool type %d", poolType)
	}

	if feeBps == 0 {
		feeBps = params.DefaultFeeBps
	}
	if !params.IsAllowedFeeBps(poolType, feeBps) {
		return 0, sdkmath.Int{}, types.ErrInvalidFee.Wrapf(
			"fee %d bps is not an allowed tier for %s (allowed: %v)",
			feeBps, poolType, params.FeeTiers(poolType),
		)
	}
	if !amountA.IsPositive() || !amountB.IsPositive() {
		return 0, sdkmath.Int{}, types.ErrInvalidAmount.Wrap("initial amounts must be positive")
	}

	a, err := k.resolveAsset(ctx, assetA)
	if err != nil {
		return 0, sdkmath.Int{}, err
	}
	b, err := k.resolveAsset(ctx, assetB)
	if err != nil {
		return 0, sdkmath.Int{}, err
	}
	if a.Address == b.Address {
		return 0, sdkmath.Int{}, types.ErrInvalidAsset.Wrap("assets must differ")
	}
	if a.Address > b.Address {
		a, b = b, a
		amountA, amountB = amountB, amountA
	}
	if a.Denom == b.Denom {
		return 0, sdkmath.Int{}, types.ErrInvalidAsset.Wrap("assets resolve to the same denom")
	}
	if _, found := k.GetPoolIDByKey(ctx, a.Address, b.Address, poolType, feeBps); found {
		return 0, sdkmath.Int{}, types.ErrPoolExists.Wrapf(
			"pool %s/%s type=%d fee=%d already exists", a.Address, b.Address, poolType, feeBps,
		)
	}
	if k.CountPoolsForAssets(ctx, a.Address, b.Address) >= params.MaxPoolsPerPair {
		return 0, sdkmath.Int{}, types.ErrPoolExists.Wrapf(
			"pair %s/%s already has the maximum of %d pools",
			a.Address, b.Address, params.MaxPoolsPerPair,
		)
	}

	var scalingA, scalingB uint64
	if poolType == types.PoolType_POOL_TYPE_STABLESWAP {
		decimalsA, err := k.assetDecimals(ctx, a)
		if err != nil {
			return 0, sdkmath.Int{}, err
		}
		decimalsB, err := k.assetDecimals(ctx, b)
		if err != nil {
			return 0, sdkmath.Int{}, err
		}

		scalingA, err = scalingFactor(decimalsA)
		if err != nil {
			return 0, sdkmath.Int{}, err
		}
		scalingB, err = scalingFactor(decimalsB)
		if err != nil {
			return 0, sdkmath.Int{}, err
		}

		x := amountA.Mul(scalingFactorInt(scalingA))
		y := amountB.Mul(scalingFactorInt(scalingB))
		if !stableInvariant(x, y, amplification).IsPositive() {
			return 0, sdkmath.Int{}, types.ErrInvalidAmount.Wrap("invalid stableswap initial reserves")
		}
	}

	totalShares := sdkmath.NewIntFromBigInt(sqrt(amountA.BigInt(), amountB.BigInt()))
	if totalShares.LTE(params.MinLockedShares) || totalShares.LT(params.MinInitialLiquidity) {
		return 0, sdkmath.Int{}, types.ErrInsufficientInitLiquidity.Wrapf(
			"initial shares %s below minimum (%s locked, %s required)",
			totalShares, params.MinLockedShares, params.MinInitialLiquidity,
		)
	}

	if !params.CreationFee.IsZero() {
		burnCoins, poolCoins := splitFee(params.CreationFee, params.FeeBurnBps)

		if !burnCoins.IsZero() {
			if err := k.bankKeeper.SendCoinsFromAccountToModule(ctx, sender, types.ModuleName, burnCoins); err != nil {
				return 0, sdkmath.Int{}, types.ErrInsufficientFunds.Wrapf("creation fee: %s", err)
			}
			if err := k.bankKeeper.BurnCoins(ctx, types.ModuleName, burnCoins); err != nil {
				return 0, sdkmath.Int{}, err
			}
		}

		if !poolCoins.IsZero() {
			if err := k.distrKeeper.FundCommunityPool(ctx, poolCoins, sender); err != nil {
				return 0, sdkmath.Int{}, types.ErrInsufficientFunds.Wrapf("creation fee: %s", err)
			}
		}
	}

	id := k.GetNextPoolID(ctx)

	// A pool that holds an external ERC20 directly needs a base account for its
	// custody address; without it CallEVM cannot act on the address's behalf.
	if a.DirectCustody || b.DirectCustody {
		if err := k.ensureCustodyAccount(ctx, id); err != nil {
			return 0, sdkmath.Int{}, err
		}
	}

	if err := k.moveIn(ctx, id, a, common.BytesToAddress(sender.Bytes()), amountA); err != nil {
		return 0, sdkmath.Int{}, types.ErrInsufficientFunds.Wrapf("initial liquidity %s: %s", a.Address, err)
	}
	if err := k.moveIn(ctx, id, b, common.BytesToAddress(sender.Bytes()), amountB); err != nil {
		return 0, sdkmath.Int{}, types.ErrInsufficientFunds.Wrapf("initial liquidity %s: %s", b.Address, err)
	}

	lpDenom := types.LPDenom(id)
	if err := k.bankKeeper.MintCoins(ctx, types.ModuleName, sdk.NewCoins(sdk.NewCoin(lpDenom, totalShares))); err != nil {
		return 0, sdkmath.Int{}, err
	}

	providerShares := totalShares.Sub(params.MinLockedShares)
	if err := k.bankKeeper.SendCoinsFromModuleToAccount(
		ctx, types.ModuleName, sender, sdk.NewCoins(sdk.NewCoin(lpDenom, providerShares)),
	); err != nil {
		return 0, sdkmath.Int{}, err
	}

	// Register the LP share as an ERC20 precompile so EVM contracts can hold it.
	lpAssetID, err := k.registerLPAsset(ctx, id, lpDenom)
	if err != nil {
		return 0, sdkmath.Int{}, err
	}

	pool := types.Pool{
		Id:             id,
		AssetA:         a.Address,
		AssetB:         b.Address,
		DenomA:         a.Denom,
		DenomB:         b.Denom,
		ReserveA:       amountA,
		ReserveB:       amountB,
		TotalShares:    totalShares,
		LockedShares:   params.MinLockedShares,
		FeeBps:         feeBps,
		LpDenom:        lpDenom,
		LpAssetId:      lpAssetID,
		PoolType:       poolType,
		Amplification:  amplification,
		ScalingFactorA: scalingA,
		ScalingFactorB: scalingB,
		Status:         types.PoolStatus_ACTIVE,
	}
	k.SetPool(ctx, pool)
	k.updateOracle(ctx, pool)
	k.AddPoolIDByAssets(ctx, a.Address, b.Address, id)
	k.SetPoolIDByKey(ctx, a.Address, b.Address, poolType, feeBps, id)
	k.SetNextPoolID(ctx, id+1)

	ctx.EventManager().EmitEvent(sdk.NewEvent(
		types.EventTypeCreatePool,
		sdk.NewAttribute(types.AttributeKeyPoolID, strconv.FormatUint(id, 10)),
		sdk.NewAttribute(types.AttributeKeyAssetA, a.Address),
		sdk.NewAttribute(types.AttributeKeyAssetB, b.Address),
		sdk.NewAttribute(types.AttributeKeyAmountA, amountA.String()),
		sdk.NewAttribute(types.AttributeKeyAmountB, amountB.String()),
		sdk.NewAttribute(types.AttributeKeyShares, providerShares.String()),
	))

	return id, providerShares, nil
}

// sqrt returns floor(sqrt(a*b)).
func sqrt(a, b *big.Int) *big.Int {
	product := new(big.Int).Mul(a, b)
	return new(big.Int).Sqrt(product)
}

// splitFee splits the creation fee into a burned part and a community-pool part.
func splitFee(fee sdk.Coins, burnBps uint32) (burn, pool sdk.Coins) {
	if burnBps >= 10_000 {
		return fee, sdk.NewCoins()
	}
	if burnBps == 0 {
		return sdk.NewCoins(), fee
	}

	burn = sdk.NewCoins()
	pool = sdk.NewCoins()

	for _, coin := range fee {
		burned := coin.Amount.MulRaw(int64(burnBps)).QuoRaw(10_000)
		if burned.IsPositive() {
			burn = burn.Add(sdk.NewCoin(coin.Denom, burned))
		}
		remainder := coin.Amount.Sub(burned)
		if remainder.IsPositive() {
			pool = pool.Add(sdk.NewCoin(coin.Denom, remainder))
		}
	}

	return burn, pool
}

// registerLPAsset creates bank metadata for the LP denom and registers it as a
// module-owned ERC20 precompile. Returns the lowercase hex ERC20 address.
func (k Keeper) registerLPAsset(ctx sdk.Context, poolID uint64, lpDenom string) (string, error) {
	addr := types.LPAssetAddress(lpDenom)
	if k.erc20Keeper.IsDenomRegistered(ctx, lpDenom) {
		return "", types.ErrInvalidAsset.Wrapf("denom %s is already registered", lpDenom)
	}
	if k.erc20Keeper.IsERC20Registered(ctx, addr) {
		return "", types.ErrInvalidAsset.Wrapf("erc20 address %s is already registered", addr.Hex())
	}

	symbol := "KLP-" + strconv.FormatUint(poolID, 10)
	display := "klp-" + strconv.FormatUint(poolID, 10)

	metadata := banktypes.Metadata{
		Description: "Karsa AMM pool share",
		DenomUnits: []*banktypes.DenomUnit{
			{Denom: lpDenom, Exponent: 0},
			{Denom: display, Exponent: 18},
		},
		Base:    lpDenom,
		Display: display,
		Name:    symbol,
		Symbol:  symbol,
	}
	if err := metadata.Validate(); err != nil {
		return "", types.ErrInvalidAsset.Wrapf("invalid lp metadata: %s", err)
	}
	k.bankKeeper.SetDenomMetaData(ctx, metadata)

	pair := erc20types.NewTokenPair(addr, lpDenom, erc20types.OWNER_MODULE)
	if err := k.erc20Keeper.SetToken(ctx, pair); err != nil {
		return "", err
	}
	if err := k.erc20Keeper.EnableDynamicPrecompile(ctx, addr); err != nil {
		return "", err
	}

	return strings.ToLower(addr.Hex()), nil
}
