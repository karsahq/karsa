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
