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

// resolvedAsset is an ERC20 address mapped to its bank denom.
type resolvedAsset struct {
	Address string // lowercase hex
	Denom   string
}

// resolveAsset validates that the given ERC20 address has an enabled,
// bank-backed token pair and returns its normalized address and denom.
//
// NOTE: pools for external (contract-owned) ERC20 tokens are not supported yet;
// transferring those requires executing EVM calls, which is a later phase.
func (k Keeper) resolveAsset(ctx sdk.Context, asset string) (resolvedAsset, error) {
	if !common.IsHexAddress(asset) {
		return resolvedAsset{}, types.ErrInvalidAsset.Wrapf("asset %q is not an ERC20 address", asset)
	}

	addr := common.HexToAddress(asset)
	pairID := k.erc20Keeper.GetTokenPairID(ctx, addr.Hex())
	if len(pairID) == 0 {
		return resolvedAsset{}, types.ErrInvalidAsset.Wrapf("asset %s has no registered token pair", asset)
	}

	pair, found := k.erc20Keeper.GetTokenPair(ctx, pairID)
	if !found {
		return resolvedAsset{}, types.ErrInvalidAsset.Wrapf("token pair not found for asset %s", asset)
	}
	if !pair.Enabled {
		return resolvedAsset{}, types.ErrInvalidAsset.Wrapf("token pair for asset %s is disabled", asset)
	}
	if !pair.IsNativeCoin() {
		return resolvedAsset{}, types.ErrUnsupportedAsset.Wrapf(
			"asset %s is an external ERC20; only bank-backed token pairs are poolable for now", asset,
		)
	}

	return resolvedAsset{Address: strings.ToLower(addr.Hex()), Denom: pair.Denom}, nil
}

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

// GetPoolIDByAssets returns the pool id for an unordered asset pair.
func (k Keeper) GetPoolIDByAssets(ctx sdk.Context, assetA, assetB string) (uint64, bool) {
	bz := k.Store(ctx).Get(types.PoolByAssetsKey(assetA, assetB))
	if bz == nil {
		return 0, false
	}

	return binary.BigEndian.Uint64(bz), true
}

// SetPoolIDByAssets indexes a pool by its unordered asset pair.
func (k Keeper) SetPoolIDByAssets(ctx sdk.Context, assetA, assetB string, id uint64) {
	bz := make([]byte, 8)
	binary.BigEndian.PutUint64(bz, id)
	k.Store(ctx).Set(types.PoolByAssetsKey(assetA, assetB), bz)
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

// CreatePool creates a new pool, pulls the initial liquidity and mints LP shares.
func (k Keeper) CreatePool(
	ctx sdk.Context,
	sender sdk.AccAddress,
	assetA, assetB string,
	feeBps uint32,
	amountA, amountB sdkmath.Int,
) (uint64, sdkmath.Int, error) {
	params := k.GetParams(ctx)

	if feeBps == 0 {
		feeBps = params.DefaultFeeBps
	}
	if feeBps > 1_000 {
		return 0, sdkmath.Int{}, types.ErrInvalidFee.Wrapf("fee_bps must be <= 1000, got %d", feeBps)
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
	if _, found := k.GetPoolIDByAssets(ctx, a.Address, b.Address); found {
		return 0, sdkmath.Int{}, types.ErrPoolExists.Wrapf("pool %s/%s already exists", a.Address, b.Address)
	}

	totalShares := sdkmath.NewIntFromBigInt(sqrt(amountA.BigInt(), amountB.BigInt()))
	if totalShares.LTE(params.MinLockedShares) || totalShares.LT(params.MinInitialLiquidity) {
		return 0, sdkmath.Int{}, types.ErrInsufficientInitLiquidity.Wrapf(
			"initial shares %s below minimum (%s locked, %s required)",
			totalShares, params.MinLockedShares, params.MinInitialLiquidity,
		)
	}

	if !params.CreationFee.IsZero() {
		if err := k.bankKeeper.SendCoinsFromAccountToModule(ctx, sender, types.ModuleName, params.CreationFee); err != nil {
			return 0, sdkmath.Int{}, types.ErrInsufficientFunds.Wrapf("creation fee: %s", err)
		}
	}

	deposit := sdk.NewCoins(sdk.NewCoin(a.Denom, amountA), sdk.NewCoin(b.Denom, amountB))
	if err := k.bankKeeper.SendCoinsFromAccountToModule(ctx, sender, types.ModuleName, deposit); err != nil {
		return 0, sdkmath.Int{}, types.ErrInsufficientFunds.Wrapf("initial liquidity: %s", err)
	}

	id := k.GetNextPoolID(ctx)
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
		Id:           id,
		AssetA:       a.Address,
		AssetB:       b.Address,
		DenomA:       a.Denom,
		DenomB:       b.Denom,
		ReserveA:     amountA,
		ReserveB:     amountB,
		TotalShares:  totalShares,
		LockedShares: params.MinLockedShares,
		FeeBps:       feeBps,
		LpDenom:      lpDenom,
		LpAssetId:    lpAssetID,
	}
	k.SetPool(ctx, pool)
	k.SetPoolIDByAssets(ctx, a.Address, b.Address, id)
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
