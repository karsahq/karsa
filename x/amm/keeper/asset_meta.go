package keeper

import (
	"math"
	"strings"

	"github.com/karsahq/karsa/x/amm/types"

	"github.com/cosmos/evm/ibc"
	"github.com/cosmos/evm/x/vm/statedb"

	"github.com/ethereum/go-ethereum/common"

	sdk "github.com/cosmos/cosmos-sdk/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
)

// assetDecimals resolves the decimals of an asset. Bank metadata wins, then the
// conventional denom prefix (u… = 6, a… = 18), then an on-chain decimals() call
// (external ERC20 contracts and IBC voucher precompiles).
func (k Keeper) assetDecimals(ctx sdk.Context, asset resolvedAsset) (uint8, error) {
	if meta, found := k.bankKeeper.GetDenomMetaData(ctx, asset.Denom); found {
		if decimals, ok := metadataDecimals(meta); ok {
			return decimals, nil
		}
	}

	if decimals, err := ibc.DeriveDecimalsFromDenom(asset.Denom); err == nil {
		return decimals, nil
	}

	return k.evmDecimals(ctx, asset)
}

// metadataDecimals returns the exponent of the display denom unit.
func metadataDecimals(meta banktypes.Metadata) (uint8, bool) {
	for i := len(meta.DenomUnits) - 1; i >= 0; i-- {
		unit := meta.DenomUnits[i]
		if unit == nil {
			continue
		}

		match := unit.Denom == meta.Display
		if strings.HasPrefix(meta.Base, "ibc/") {
			displayParts := strings.Split(meta.Display, "/")
			match = unit.Denom == displayParts[len(displayParts)-1]
		}

		if match {
			if unit.Exponent > math.MaxUint8 {
				return 0, false
			}
			return uint8(unit.Exponent), true
		}
	}

	return 0, false
}

// evmDecimals calls decimals() on the asset's ERC20 address.
func (k Keeper) evmDecimals(ctx sdk.Context, asset resolvedAsset) (uint8, error) {
	token := common.HexToAddress(asset.Address)

	stateDB := statedb.New(ctx, k.evmKeeper, statedb.NewEmptyTxConfig())
	res, err := k.evmKeeper.CallEVM(
		ctx, stateDB, types.ERC20ABI, k.moduleAddress, token, false, false, nil, "decimals",
	)
	if err != nil {
		return 0, types.ErrInvalidAsset.Wrapf("decimals() call failed for %s: %s", asset.Address, err)
	}
	if res.Failed() {
		return 0, types.ErrInvalidAsset.Wrapf("decimals() reverted for %s: %s", asset.Address, res.VmError)
	}

	out, err := types.ERC20ABI.Unpack("decimals", res.Ret)
	if err != nil || len(out) != 1 {
		return 0, types.ErrInvalidAsset.Wrapf("failed to decode decimals() for %s", asset.Address)
	}

	decimals, ok := out[0].(uint8)
	if !ok {
		return 0, types.ErrInvalidAsset.Wrapf("unexpected decimals() type for %s", asset.Address)
	}

	return decimals, nil
}

// scalingFactor converts decimals into a factor that normalises the reserve to
// 18 decimals. Stableswap cannot represent assets with more than 18 decimals.
func scalingFactor(decimals uint8) (uint64, error) {
	if decimals > 18 {
		return 0, types.ErrUnsupportedAsset.Wrapf(
			"stableswap requires at most 18 decimals, got %d", decimals,
		)
	}

	factor := uint64(1)
	for i := decimals; i < 18; i++ {
		factor *= 10
	}

	return factor, nil
}
