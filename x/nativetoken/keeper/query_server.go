package keeper

import (
	"context"
	"strings"

	"github.com/karsahq/karsa/x/nativetoken/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
	query "github.com/cosmos/cosmos-sdk/types/query"
)

type queryServer struct {
	Keeper
}

// NewQueryServerImpl returns an implementation of the module Query service.
func NewQueryServerImpl(k Keeper) types.QueryServer { return queryServer{Keeper: k} }

// Token returns a token by denom or by 0x address.
func (q queryServer) Token(
	goCtx context.Context, req *types.QueryTokenRequest,
) (*types.QueryTokenResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	id := strings.TrimSpace(req.Id)

	if types.IsNativeTokenDenom(id) {
		token, found := q.GetToken(ctx, id)
		if !found {
			return nil, types.ErrTokenNotFound.Wrap(id)
		}

		return &types.QueryTokenResponse{Token: token}, nil
	}

	token, found := q.GetTokenByAddress(ctx, id)
	if !found {
		return nil, types.ErrTokenNotFound.Wrap(id)
	}

	return &types.QueryTokenResponse{Token: token}, nil
}

// Tokens lists every native token with simple offset/limit pagination.
func (q queryServer) Tokens(
	goCtx context.Context, req *types.QueryTokensRequest,
) (*types.QueryTokensResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	offset, limit := uint64(0), uint64(100)
	if req != nil && req.Pagination != nil {
		if req.Pagination.Offset > 0 {
			offset = req.Pagination.Offset
		}
		if req.Pagination.Limit > 0 {
			limit = req.Pagination.Limit
		}
	}

	all := q.GetAllTokens(ctx)
	total := uint64(len(all))

	start := offset
	if start > total {
		start = total
	}
	end := start + limit
	if end > total {
		end = total
	}

	return &types.QueryTokensResponse{
		Tokens:     all[start:end],
		Pagination: &query.PageResponse{Total: total},
	}, nil
}

// Params returns the module parameters.
func (q queryServer) Params(
	goCtx context.Context, _ *types.QueryParamsRequest,
) (*types.QueryParamsResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	return &types.QueryParamsResponse{Params: q.GetParams(ctx)}, nil
}
