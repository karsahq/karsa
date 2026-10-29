package keeper

import (
	"context"
	"strings"

	"github.com/karsahq/karsa/x/amm/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
	query "github.com/cosmos/cosmos-sdk/types/query"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type queryServer struct {
	Keeper
}

// NewQueryServerImpl returns an implementation of the QueryServer interface.
func NewQueryServerImpl(k Keeper) types.QueryServer {
	return &queryServer{Keeper: k}
}

var _ types.QueryServer = queryServer{}

// Pool returns a single pool by id.
func (q queryServer) Pool(goCtx context.Context, req *types.QueryPoolRequest) (*types.QueryPoolResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "empty request")
	}

	ctx := sdk.UnwrapSDKContext(goCtx)

	pool, found := q.GetPool(ctx, req.PoolId)
	if !found {
		return nil, status.Errorf(codes.NotFound, "pool %d not found", req.PoolId)
	}

	return &types.QueryPoolResponse{Pool: pool}, nil
}

// Pools returns all pools with simple offset/limit pagination.
func (q queryServer) Pools(goCtx context.Context, req *types.QueryPoolsRequest) (*types.QueryPoolsResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	var pools []types.Pool
	q.IteratePools(ctx, func(pool types.Pool) bool {
		pools = append(pools, pool)
		return false
	})

	total := uint64(len(pools))
	offset, limit := uint64(0), total
	if req != nil && req.Pagination != nil {
		if req.Pagination.Offset > 0 {
			offset = req.Pagination.Offset
		}
		if req.Pagination.Limit > 0 {
			limit = req.Pagination.Limit
		}
	}

	if offset >= total {
		return &types.QueryPoolsResponse{Pools: []types.Pool{}, Pagination: &query.PageResponse{Total: total}}, nil
	}

	end := offset + limit
	if end > total {
		end = total
	}

	return &types.QueryPoolsResponse{
		Pools:      pools[offset:end],
		Pagination: &query.PageResponse{Total: total},
	}, nil
}

// PoolByAssets returns the pool for an unordered asset pair.
func (q queryServer) PoolByAssets(goCtx context.Context, req *types.QueryPoolByAssetsRequest) (*types.QueryPoolByAssetsResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "empty request")
	}

	ctx := sdk.UnwrapSDKContext(goCtx)

	assetA := strings.ToLower(req.AssetA)
	assetB := strings.ToLower(req.AssetB)
	if assetA > assetB {
		assetA, assetB = assetB, assetA
	}

	id, found := q.GetPoolIDByAssets(ctx, assetA, assetB)
	if !found {
		return nil, status.Errorf(codes.NotFound, "no pool for %s/%s", assetA, assetB)
	}

	pool, found := q.GetPool(ctx, id)
	if !found {
		return nil, status.Errorf(codes.NotFound, "pool %d not found", id)
	}

	return &types.QueryPoolByAssetsResponse{Pool: pool}, nil
}

// PoolsByAssets returns every pool for an unordered asset pair.
func (q queryServer) PoolsByAssets(goCtx context.Context, req *types.QueryPoolsByAssetsRequest) (*types.QueryPoolsByAssetsResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "empty request")
	}

	ctx := sdk.UnwrapSDKContext(goCtx)

	ids := q.GetPoolIDsByAssets(ctx, req.AssetA, req.AssetB)
	pools := make([]types.Pool, 0, len(ids))
	for _, id := range ids {
		pool, found := q.GetPool(ctx, id)
		if !found {
			return nil, status.Errorf(codes.NotFound, "pool %d not found", id)
		}
		pools = append(pools, pool)
	}

	return &types.QueryPoolsByAssetsResponse{Pools: pools}, nil
}

// Quote returns the expected output for a swap path.
func (q queryServer) Quote(goCtx context.Context, req *types.QueryQuoteRequest) (*types.QueryQuoteResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "empty request")
	}

	ctx := sdk.UnwrapSDKContext(goCtx)

	amountOut, err := q.Keeper.QuoteWithPools(ctx, req.Path, req.PoolIds, req.AmountIn)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	return &types.QueryQuoteResponse{AmountOut: amountOut}, nil
}

// QuoteExactOut returns the input required to receive an exact output amount.
func (q queryServer) QuoteExactOut(goCtx context.Context, req *types.QueryQuoteExactOutRequest) (*types.QueryQuoteExactOutResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "empty request")
	}

	ctx := sdk.UnwrapSDKContext(goCtx)

	amountIn, err := q.Keeper.QuoteExactOutWithPools(ctx, req.Path, req.PoolIds, req.AmountOut)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	return &types.QueryQuoteExactOutResponse{AmountIn: amountIn}, nil
}

// Params returns the module params.
func (q queryServer) Twap(goCtx context.Context, req *types.QueryTwapRequest) (*types.QueryTwapResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "empty request")
	}

	ctx := sdk.UnwrapSDKContext(goCtx)

	priceA, priceB, window, err := q.Keeper.Twap(ctx, req.PoolId, req.WindowSeconds)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	return &types.QueryTwapResponse{PriceA: priceA, PriceB: priceB, EffectiveWindow: window}, nil
}

// Params returns the module params.
func (q queryServer) Params(goCtx context.Context, _ *types.QueryParamsRequest) (*types.QueryParamsResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)
	return &types.QueryParamsResponse{Params: q.GetParams(ctx)}, nil
}
