package keeper

import (
	"math/big"
	"strings"

	errorsmod "cosmossdk.io/errors"
	sdkmath "cosmossdk.io/math"

	"github.com/karsahq/karsa/x/amm/types"

	"github.com/ethereum/go-ethereum/common"

	"github.com/cosmos/evm/x/vm/statedb"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// assetKind describes how the module moves an asset's funds.
type assetKind int

const (
	// bankAsset is a bank-backed (module-owned) token pair: reserves live in the
	// x/amm module account as a bank denom.
	bankAsset assetKind = iota
	// evmAsset is an external ERC20 contract: reserves live in the token contract
	// under the module's EVM address.
	evmAsset
)

// resolvedAsset is an ERC20 address mapped to its bank denom and custody kind.
type resolvedAsset struct {
	Address  string // lowercase hex
	Denom    string // bank denom ("akra", "ibc/…", "erc20:0x…")
	Kind     assetKind
	Contract common.Address // ERC20 contract address (evmAsset only)
}

// resolveAsset validates that the given ERC20 address has an enabled token pair
// and returns how the module should custody it.
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
		Kind:    bankAsset,
	}

	if !pair.IsNativeCoin() {
		resolved.Kind = evmAsset
		resolved.Contract = pair.GetERC20Contract()
		if resolved.Contract == (common.Address{}) {
			return resolvedAsset{}, types.ErrInvalidAsset.Wrapf("asset %s has no contract address", asset)
		}
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
		ctx, k.evmStateDB(ctx, stateDB), types.ERC20ABI, account, token, false, false, nil,
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

// moveIn moves funds from an account into the module.
func (k Keeper) moveIn(ctx sdk.Context, asset resolvedAsset, from common.Address, amount sdkmath.Int) error {
	return k.moveInWith(ctx, nil, false, asset, from, amount)
}

// moveInWith is moveIn with an optional EVM execution context.
func (k Keeper) moveInWith(
	ctx sdk.Context, stateDB *statedb.StateDB, fromPrecompile bool,
	asset resolvedAsset, from common.Address, amount sdkmath.Int,
) error {
	if !amount.IsPositive() {
		return types.ErrInvalidAmount.Wrap("amount must be positive")
	}

	switch asset.Kind {
	case bankAsset:
		coins := sdk.NewCoins(sdk.NewCoin(asset.Denom, amount))
		if err := k.bankKeeper.SendCoinsFromAccountToModule(
			ctx, sdk.AccAddress(from.Bytes()), types.ModuleName, coins,
		); err != nil {
			return types.ErrInsufficientFunds.Wrap(err.Error())
		}
		return nil

	case evmAsset:
		return k.evmTransferWith(ctx, stateDB, fromPrecompile, asset.Contract, from, k.moduleAddress, amount)

	default:
		return types.ErrInvalidAsset.Wrap("unknown asset kind")
	}
}

// moveOut moves funds from the module to an account.
func (k Keeper) moveOut(ctx sdk.Context, asset resolvedAsset, to common.Address, amount sdkmath.Int) error {
	return k.moveOutWith(ctx, nil, false, asset, to, amount)
}

// moveOutWith is moveOut with an optional EVM execution context.
func (k Keeper) moveOutWith(
	ctx sdk.Context, stateDB *statedb.StateDB, fromPrecompile bool,
	asset resolvedAsset, to common.Address, amount sdkmath.Int,
) error {
	if !amount.IsPositive() {
		return types.ErrInvalidAmount.Wrap("amount must be positive")
	}

	switch asset.Kind {
	case bankAsset:
		coins := sdk.NewCoins(sdk.NewCoin(asset.Denom, amount))
		if err := k.bankKeeper.SendCoinsFromModuleToAccount(
			ctx, types.ModuleName, sdk.AccAddress(to.Bytes()), coins,
		); err != nil {
			return err
		}
		return nil

	case evmAsset:
		return k.evmTransferWith(ctx, stateDB, fromPrecompile, asset.Contract, k.moduleAddress, to, amount)

	default:
		return types.ErrInvalidAsset.Wrap("unknown asset kind")
	}
}

// assertCustody checks that the module actually holds at least the tracked
// reserves for an external asset.
func (k Keeper) assertCustody(ctx sdk.Context, asset resolvedAsset, reserve sdkmath.Int) error {
	if asset.Kind != evmAsset {
		return nil
	}

	balance, err := k.evmBalanceWith(ctx, nil, asset.Contract, k.moduleAddress)
	if err != nil {
		return err
	}
	if balance.LT(reserve) {
		return types.ErrInvalidAsset.Wrapf(
			"custody invariant broken for %s: have %s, need %s", asset.Address, balance, reserve,
		)
	}

	return nil
}
