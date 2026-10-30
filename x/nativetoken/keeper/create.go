package keeper

import (
	"strings"

	"github.com/karsahq/karsa/x/nativetoken/types"

	erc20types "github.com/cosmos/evm/x/erc20/types"

	"github.com/ethereum/go-ethereum/common"

	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"

	sdkmath "cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// maxAddressAttempts bounds the sequence bumping loop. A collision is
// astronomically unlikely; the bound only prevents an unbounded loop.
const maxAddressAttempts = 1024

// CreateNativeToken issues a native token: it derives a fresh address, registers
// the bank denom as a dynamic ERC20 precompile, and mints the initial supply to
// the creator.
//
// The symbol is plain metadata and carries no uniqueness guarantee. Identity is
// the address.
func (k Keeper) CreateNativeToken(
	ctx sdk.Context,
	creator sdk.AccAddress,
	symbol, name string,
	supply sdkmath.Int,
	controller string,
) (types.Token, error) {
	params := k.GetParams(ctx)

	if err := params.ValidateSymbol(symbol); err != nil {
		return types.Token{}, types.ErrInvalidSymbol.Wrap(err.Error())
	}
	if err := params.ValidateName(name); err != nil {
		return types.Token{}, types.ErrInvalidName.Wrap(err.Error())
	}
	if err := params.ValidateSupply(supply); err != nil {
		return types.Token{}, types.ErrInvalidSupply.Wrap(err.Error())
	}
	if len(creator) != common.AddressLength {
		return types.Token{}, types.ErrInvalidCreator.Wrap("creator must be a 20-byte account")
	}

	controllerHex, err := k.validateController(ctx, controller)
	if err != nil {
		return types.Token{}, err
	}

	creatorAddr := common.BytesToAddress(creator)
	creatorHex := strings.ToLower(creatorAddr.Hex())

	address, denom, sequence, err := k.deriveAddress(ctx, creatorAddr, k.GetSequence(ctx, creatorHex))
	if err != nil {
		return types.Token{}, err
	}

	if err := k.chargeCreationFee(ctx, creator, params); err != nil {
		return types.Token{}, err
	}

	token := types.Token{
		Denom:      denom,
		Address:    strings.ToLower(address.Hex()),
		Creator:    creatorHex,
		Controller: controllerHex,
		Name:       name,
		Symbol:     symbol,
		Verified:   false,
		CreatedAt:  ctx.BlockTime().Unix(),
	}

	metadata := bankMetadata(token)
	if err := metadata.Validate(); err != nil {
		return types.Token{}, types.ErrInvalidName.Wrapf("invalid denom metadata: %s", err)
	}

	k.SetToken(ctx, token)
	k.SetSequence(ctx, creatorHex, sequence+1)

	// Register the denom as a module-owned ERC20 pair and expose it through a
	// dynamic precompile, so the EVM sees an ERC20 at the derived address.
	if err := k.erc20Keeper.SetToken(ctx, erc20types.NewTokenPair(
		address, denom, erc20types.OWNER_MODULE,
	)); err != nil {
		return types.Token{}, err
	}
	if err := k.erc20Keeper.EnableDynamicPrecompile(ctx, address); err != nil {
		return types.Token{}, err
	}

	k.bankKeeper.SetDenomMetaData(ctx, metadata)

	coins := sdk.NewCoins(sdk.NewCoin(denom, supply))
	if err := k.bankKeeper.MintCoins(ctx, types.ModuleName, coins); err != nil {
		return types.Token{}, err
	}
	if err := k.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, creator, coins); err != nil {
		return types.Token{}, err
	}

	ctx.EventManager().EmitEvent(sdk.NewEvent(
		types.EventTypeCreateToken,
		sdk.NewAttribute(types.AttributeKeyDenom, denom),
		sdk.NewAttribute(types.AttributeKeyAddress, token.Address),
		sdk.NewAttribute(types.AttributeKeyCreator, creatorHex),
		sdk.NewAttribute(types.AttributeKeyController, controllerHex),
	))

	return token, nil
}

// deriveAddress walks the creator's sequence until it finds a free address.
func (k Keeper) deriveAddress(
	ctx sdk.Context, creator common.Address, start uint64,
) (common.Address, string, uint64, error) {
	for i := uint64(0); i < maxAddressAttempts; i++ {
		sequence := start + i
		address := types.AddressFor(creator, sequence)
		denom := types.DenomFor(address)

		if types.IsReservedAddress(address) ||
			k.HasToken(ctx, denom) ||
			k.erc20Keeper.IsERC20Registered(ctx, address) ||
			k.evmKeeper.IsContract(ctx, address) {
			continue
		}

		return address, denom, sequence, nil
	}

	return common.Address{}, "", 0, types.ErrAddressCollision.Wrap("no free address found")
}

// validateController normalises and checks the controller address. An empty
// controller means the supply is immutable; a non-empty one must be a contract,
// which is what keeps control out of the hands of a single key.
func (k Keeper) validateController(ctx sdk.Context, controller string) (string, error) {
	if controller == "" {
		return "", nil
	}

	addressHex, err := types.NormalizeAddress(controller)
	if err != nil {
		return "", types.ErrInvalidController.Wrap(err.Error())
	}

	address := common.HexToAddress(addressHex)
	if address == (common.Address{}) {
		return "", types.ErrInvalidController.Wrap("controller cannot be the zero address")
	}
	if !k.evmKeeper.IsContract(ctx, address) {
		return "", types.ErrControllerNotContract.Wrapf("%s has no code", addressHex)
	}

	return addressHex, nil
}

// chargeCreationFee moves the creation fee to the community pool.
func (k Keeper) chargeCreationFee(ctx sdk.Context, creator sdk.AccAddress, params types.Params) error {
	if params.CreationFee.IsZero() {
		return nil
	}

	if err := k.bankKeeper.SendCoinsFromAccountToModule(
		ctx, creator, types.ModuleName, params.CreationFee,
	); err != nil {
		return types.ErrInsufficientFee.Wrap(err.Error())
	}

	return k.distrKeeper.FundCommunityPool(ctx, params.CreationFee, k.ModuleAddress())
}

// bankMetadata builds the bank display metadata for a token.
func bankMetadata(token types.Token) banktypes.Metadata {
	display := strings.ToLower(token.Symbol)

	return banktypes.Metadata{
		Base:    token.Denom,
		Display: display,
		Name:    token.Name,
		Symbol:  token.Symbol,
		DenomUnits: []*banktypes.DenomUnit{
			{Denom: token.Denom, Exponent: 0},
			{Denom: display, Exponent: 18},
		},
	}
}
