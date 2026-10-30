package keeper

import (
	"math/big"
	"strings"

	errorsmod "cosmossdk.io/errors"
	sdkmath "cosmossdk.io/math"

	"github.com/karsahq/karsa/x/amm/types"

	"github.com/cosmos/evm/x/vm/statedb"

	"github.com/ethereum/go-ethereum/common"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// resolvedAsset maps an ERC20 address to its bank denom and, for external
// ERC20 contracts, the conversion pair needed at the custody boundary.
type resolvedAsset struct {
	Address         string // lowercase hex
	Denom           string // bank denom ("akra", "ibc/…")
	ConvertContract common.Address
	// DirectCustody is true when the pool holds the contract token itself at
	// custody(poolID) instead of a bank denom.
	DirectCustody bool
}

// resolveAsset validates that the given ERC20 address has an enabled token pair
// and returns the bank denom used by pool reserves.
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

	resolved := resolvedAsset{
		Address: strings.ToLower(addr.Hex()),
		Denom:   pair.Denom,
	}

	if !pair.IsNativeCoin() {
		contract := pair.GetERC20Contract()
		if contract == (common.Address{}) {
			return resolvedAsset{}, types.ErrInvalidAsset.Wrapf("asset %s has no contract address", asset)
		}
		resolved.ConvertContract = contract
		resolved.DirectCustody = true
	}

	return resolved, nil
}

// evmStateDB returns the stateDB to use, creating one when the call does not
// originate from an EVM execution context.
func (k Keeper) evmStateDB(ctx sdk.Context, stateDB *statedb.StateDB) *statedb.StateDB {
	if stateDB != nil {
		return stateDB
	}

	return statedb.New(ctx, k.evmKeeper, statedb.NewEmptyTxConfig())
}

// evmBalanceWith reads balanceOf(account) on an ERC20 contract.
func (k Keeper) evmBalanceWith(
	ctx sdk.Context, stateDB *statedb.StateDB, token, account common.Address,
) (sdkmath.Int, error) {
	res, err := k.evmKeeper.CallEVM(
		ctx, k.evmStateDB(ctx, stateDB), types.ERC20ABI, k.moduleAddress, token, false, false, nil,
		"balanceOf", account,
	)
	if err != nil {
		return sdkmath.Int{}, errorsmod.Wrap(err, "balanceOf call failed")
	}
	if res.Failed() {
		return sdkmath.Int{}, types.ErrInvalidAsset.Wrapf("balanceOf reverted: %s", res.VmError)
	}

	out, err := types.ERC20ABI.Unpack("balanceOf", res.Ret)
	if err != nil || len(out) != 1 {
		return sdkmath.Int{}, types.ErrInvalidAsset.Wrap("failed to decode balanceOf result")
	}

	amount, ok := out[0].(*big.Int)
	if !ok || amount == nil {
		return sdkmath.Int{}, types.ErrInvalidAsset.Wrap("unexpected balanceOf result type")
	}

	return sdkmath.NewIntFromBigInt(amount), nil
}

// evmTransferWith moves `amount` of an ERC20 from `from` to `to` and verifies
// the balance delta, which rejects fee-on-transfer and other non-standard tokens.
func (k Keeper) evmTransferWith(
	ctx sdk.Context, stateDB *statedb.StateDB, fromPrecompile bool,
	token, from, to common.Address, amount sdkmath.Int,
) error {
	before, err := k.evmBalanceWith(ctx, stateDB, token, to)
	if err != nil {
		return err
	}

	res, err := k.evmKeeper.CallEVM(
		ctx, k.evmStateDB(ctx, stateDB), types.ERC20ABI, from, token, true, fromPrecompile, nil,
		"transfer", to, amount.BigInt(),
	)
	if err != nil {
		return types.ErrInsufficientFunds.Wrapf("transfer call failed: %s", err)
	}
	if res.Failed() {
		return types.ErrInsufficientFunds.Wrapf("transfer reverted: %s", res.VmError)
	}

	if len(res.Ret) > 0 {
		out, err := types.ERC20ABI.Unpack("transfer", res.Ret)
		if err == nil && len(out) == 1 {
			if ok, isBool := out[0].(bool); isBool && !ok {
				return types.ErrInsufficientFunds.Wrap("transfer returned false")
			}
		}
	}

	after, err := k.evmBalanceWith(ctx, stateDB, token, to)
	if err != nil {
		return err
	}
	if !after.Sub(before).Equal(amount) {
		return types.ErrInvalidAsset.Wrapf(
			"unexpected transfer balance delta: got %s, want %s", after.Sub(before), amount,
		)
	}

	return nil
}

// ensureCustodyAccount registers a base account for a pool's custody address.
// Holding an ERC20 only writes to contract storage, which does not create a
// Cosmos account; CallEVM needs one to read the sender's sequence.
func (k Keeper) ensureCustodyAccount(ctx sdk.Context, poolID uint64) error {
	addr := sdk.AccAddress(types.CustodyAddress(poolID).Bytes())
	if k.accountKeeper.GetAccount(ctx, addr) != nil {
		return nil
	}

	k.accountKeeper.SetAccount(ctx, k.accountKeeper.NewAccountWithAddress(ctx, addr))

	return nil
}

// moveIn moves funds for a pool from an account into custody.
func (k Keeper) moveIn(
	ctx sdk.Context, poolID uint64, asset resolvedAsset, from common.Address, amount sdkmath.Int,
) error {
	return k.moveInWith(ctx, poolID, nil, false, asset, from, amount)
}

// moveInWith is moveIn with an optional EVM execution context.
//
// poolID selects the custody account that will hold the asset once direct
// custody lands; the swap path still converts, so it is not used yet.
func (k Keeper) moveInWith(
	ctx sdk.Context, poolID uint64, stateDB *statedb.StateDB, fromPrecompile bool,
	asset resolvedAsset, from common.Address, amount sdkmath.Int,
) error {
	if !amount.IsPositive() {
		return types.ErrInvalidAmount.Wrap("amount must be positive")
	}

	if asset.DirectCustody {
		custody := types.CustodyAddress(poolID)

		return k.evmTransferWith(
			ctx, k.evmStateDB(ctx, stateDB), fromPrecompile,
			common.HexToAddress(asset.Address), from, custody, amount,
		)
	}

	coins := sdk.NewCoins(sdk.NewCoin(asset.Denom, amount))
	if err := k.bankKeeper.SendCoinsFromAccountToModule(
		ctx, sdk.AccAddress(from.Bytes()), types.ModuleName, coins,
	); err != nil {
		return types.ErrInsufficientFunds.Wrap(err.Error())
	}
	return nil
}

// moveOut moves funds for a pool from custody to an account.
func (k Keeper) moveOut(
	ctx sdk.Context, poolID uint64, asset resolvedAsset, to common.Address, amount sdkmath.Int,
) error {
	return k.moveOutWith(ctx, poolID, nil, false, asset, to, amount)
}

// moveOutWith is moveOut with an optional EVM execution context.
func (k Keeper) moveOutWith(
	ctx sdk.Context, poolID uint64, stateDB *statedb.StateDB, fromPrecompile bool,
	asset resolvedAsset, to common.Address, amount sdkmath.Int,
) error {
	if !amount.IsPositive() {
		return types.ErrInvalidAmount.Wrap("amount must be positive")
	}

	if asset.DirectCustody {
		custody := types.CustodyAddress(poolID)

		return k.evmTransferWith(
			ctx, k.evmStateDB(ctx, stateDB), fromPrecompile,
			common.HexToAddress(asset.Address), custody, to, amount,
		)
	}

	coins := sdk.NewCoins(sdk.NewCoin(asset.Denom, amount))
	if err := k.bankKeeper.SendCoinsFromModuleToAccount(
		ctx, types.ModuleName, sdk.AccAddress(to.Bytes()), coins,
	); err != nil {
		return err
	}
	return nil
}
