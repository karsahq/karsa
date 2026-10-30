package keeper

import (
	"strings"

	"github.com/karsahq/karsa/x/nativetoken/types"

	"github.com/ethereum/go-ethereum/common"

	sdkmath "cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// requireController loads a token and checks that caller is its controller.
func (k Keeper) requireController(
	ctx sdk.Context, caller common.Address, denom string,
) (types.Token, error) {
	token, found := k.GetToken(ctx, denom)
	if !found {
		return types.Token{}, types.ErrTokenNotFound.Wrap(denom)
	}

	if token.Controller == "" {
		return types.Token{}, types.ErrUnauthorized.Wrap("token supply is immutable")
	}

	callerHex := strings.ToLower(caller.Hex())
	if token.Controller != callerHex {
		return types.Token{}, types.ErrUnauthorized.Wrapf(
			"%s is not the controller of %s", callerHex, denom,
		)
	}

	return token, nil
}

// MintByController mints `amount` to `to` on behalf of the token controller.
func (k Keeper) MintByController(
	ctx sdk.Context, caller common.Address, denom string, to sdk.AccAddress, amount sdkmath.Int,
) error {
	if !amount.IsPositive() {
		return types.ErrInvalidSupply.Wrap("amount must be positive")
	}

	token, err := k.requireController(ctx, caller, denom)
	if err != nil {
		return err
	}

	supply := k.bankKeeper.GetSupply(ctx, token.Denom).Amount
	if supply.Add(amount).GT(types.MaxSupply) {
		return types.ErrInvalidSupply.Wrap("total supply would exceed uint256")
	}

	coins := sdk.NewCoins(sdk.NewCoin(token.Denom, amount))
	if err := k.bankKeeper.MintCoins(ctx, types.ModuleName, coins); err != nil {
		return err
	}

	return k.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, to, coins)
}

// BurnByController burns `amount` held by `from` on behalf of the controller.
func (k Keeper) BurnByController(
	ctx sdk.Context, caller common.Address, denom string, from sdk.AccAddress, amount sdkmath.Int,
) error {
	if !amount.IsPositive() {
		return types.ErrInvalidSupply.Wrap("amount must be positive")
	}

	token, err := k.requireController(ctx, caller, denom)
	if err != nil {
		return err
	}

	coins := sdk.NewCoins(sdk.NewCoin(token.Denom, amount))
	if err := k.bankKeeper.SendCoinsFromAccountToModule(ctx, from, types.ModuleName, coins); err != nil {
		return err
	}

	return k.bankKeeper.BurnCoins(ctx, types.ModuleName, coins)
}
