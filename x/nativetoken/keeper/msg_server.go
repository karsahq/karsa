package keeper

import (
	"context"

	"github.com/karsahq/karsa/x/nativetoken/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

type msgServer struct {
	Keeper
}

// NewMsgServerImpl returns an implementation of the module Msg service.
func NewMsgServerImpl(k Keeper) types.MsgServer { return msgServer{Keeper: k} }

// CreateNativeToken issues a new native token.
func (m msgServer) CreateNativeToken(
	goCtx context.Context, msg *types.MsgCreateNativeToken,
) (*types.MsgCreateNativeTokenResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	if err := msg.ValidateBasic(); err != nil {
		return nil, err
	}

	// Creation is contract-only by default: everyone who creates goes through the
	// factory precompile, so a token always traces back to a contract.
	if !m.GetParams(ctx).OpenCreation {
		return nil, types.ErrUnauthorized.Wrap(
			"creation through messages is disabled; use the factory precompile",
		)
	}

	creator, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return nil, types.ErrInvalidCreator.Wrap(err.Error())
	}

	token, err := m.Keeper.CreateNativeToken(
		ctx, creator, msg.Symbol, msg.Name, msg.InitialSupply, msg.Controller,
	)
	if err != nil {
		return nil, err
	}

	return &types.MsgCreateNativeTokenResponse{
		Denom:   token.Denom,
		Address: token.Address,
	}, nil
}

// SetTokenVerified updates the governance curation flag.
func (m msgServer) SetTokenVerified(
	goCtx context.Context, msg *types.MsgSetTokenVerified,
) (*types.MsgSetTokenVerifiedResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	if msg.Authority != m.Authority() {
		return nil, types.ErrUnauthorized.Wrapf(
			"expected authority %s, got %s", m.Authority(), msg.Authority,
		)
	}

	token, found := m.GetToken(ctx, msg.Denom)
	if !found {
		return nil, types.ErrTokenNotFound.Wrap(msg.Denom)
	}

	token.Verified = msg.Verified
	m.SetToken(ctx, token)

	ctx.EventManager().EmitEvent(sdk.NewEvent(
		types.EventTypeSetVerified,
		sdk.NewAttribute(types.AttributeKeyDenom, token.Denom),
		sdk.NewAttribute(types.AttributeKeyVerified, boolAttr(msg.Verified)),
	))

	return &types.MsgSetTokenVerifiedResponse{}, nil
}

// UpdateParams updates the module parameters.
func (m msgServer) UpdateParams(
	goCtx context.Context, msg *types.MsgUpdateParams,
) (*types.MsgUpdateParamsResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	if msg.Authority != m.Authority() {
		return nil, types.ErrUnauthorized.Wrapf(
			"expected authority %s, got %s", m.Authority(), msg.Authority,
		)
	}

	if err := m.SetParams(ctx, msg.Params); err != nil {
		return nil, err
	}

	return &types.MsgUpdateParamsResponse{}, nil
}

func boolAttr(value bool) string {
	if value {
		return "true"
	}

	return "false"
}
