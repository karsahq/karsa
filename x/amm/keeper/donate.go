package keeper

import (
	"strconv"

	"github.com/karsahq/karsa/x/amm/types"

	sdkmath "cosmossdk.io/math"

	"github.com/ethereum/go-ethereum/common"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// DonatePool moves any amount held by the pool's custody accounts above the
// stored reserve into the reserve, without minting shares.
//
// Reserves are stored state rather than being derived from balances, so a stray
// transfer to a custody address would otherwise sit there unaccounted forever.
// Adding it to the reserve raises the value of each LP share pro rata; nobody can
// extract it, which is why this is preferred over letting the caller skim it.
func (k Keeper) DonatePool(ctx sdk.Context, poolID uint64) (sdk.Coins, error) {
	pool, found := k.GetPool(ctx, poolID)
	if !found {
		return nil, types.ErrPoolNotFound.Wrapf("pool %d", poolID)
	}

	reserveA, coinA, donatedA, err := k.donateSide(ctx, poolID, pool.AssetA, pool.ReserveA)
	if err != nil {
		return nil, err
	}
	reserveB, coinB, donatedB, err := k.donateSide(ctx, poolID, pool.AssetB, pool.ReserveB)
	if err != nil {
		return nil, err
	}

	if !donatedA && !donatedB {
		return sdk.Coins{}, nil
	}

	donated := sdk.Coins{}
	if donatedA {
		donated = donated.Add(coinA)
	}
	if donatedB {
		donated = donated.Add(coinB)
	}

	pool.ReserveA = reserveA
	pool.ReserveB = reserveB
	k.SetPool(ctx, pool)
	k.updateOracle(ctx, pool)

	ctx.EventManager().EmitEvent(sdk.NewEvent(
		types.EventTypeDonate,
		sdk.NewAttribute(types.AttributeKeyPoolID, strconv.FormatUint(poolID, 10)),
		sdk.NewAttribute(types.AttributeKeyAmount, donated.String()),
	))

	return donated, nil
}

// donateSide returns the reserve after adopting any excess balance, the donated
// coin, and whether anything was donated at all.
func (k Keeper) donateSide(
	ctx sdk.Context, poolID uint64, assetAddress string, reserve sdkmath.Int,
) (sdkmath.Int, sdk.Coin, bool, error) {
	asset, err := k.resolveAsset(ctx, assetAddress)
	if err != nil {
		return reserve, sdk.Coin{}, false, err
	}
	if !asset.DirectCustody {
		return reserve, sdk.Coin{}, false, nil
	}

	balance, err := k.evmBalanceWith(
		ctx, nil, common.HexToAddress(asset.Address), types.CustodyAddress(poolID),
	)
	if err != nil {
		return reserve, sdk.Coin{}, false, err
	}

	excess := balance.Sub(reserve)
	if !excess.IsPositive() {
		return reserve, sdk.Coin{}, false, nil
	}

	return balance, sdk.NewCoin(asset.Denom, excess), true, nil
}
