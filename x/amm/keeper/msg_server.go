package keeper

import (
	"context"

	"github.com/karsahq/karsa/x/amm/types"

	"github.com/ethereum/go-ethereum/common"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

type msgServer struct {
	Keeper
}

// NewMsgServerImpl returns an implementation of the MsgServer interface.
func NewMsgServerImpl(k Keeper) types.MsgServer {
	return &msgServer{Keeper: k}
}

var _ types.MsgServer = msgServer{}

// parseAddress accepts either a bech32 or a hex (0x…) address and returns the
// underlying 20-byte account address.
func parseAddress(value string) (sdk.AccAddress, error) {
	if common.IsHexAddress(value) {
		return sdk.AccAddress(common.HexToAddress(value).Bytes()), nil
	}

	return sdk.AccAddressFromBech32(value)
}

// CreatePool creates a new pool.
func (m msgServer) CreatePool(goCtx context.Context, msg *types.MsgCreatePool) (*types.MsgCreatePoolResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	if err := m.acquireLock(ctx); err != nil {
		return nil, err
	}
	defer m.releaseLock(ctx)

	sender, err := sdk.AccAddressFromBech32(msg.Sender)
	if err != nil {
		return nil, types.ErrInvalidAmount.Wrapf("invalid sender: %s", err)
	}

	poolID, _, err := m.Keeper.CreatePoolWithType(
		ctx, sender, msg.AssetA, msg.AssetB, msg.FeeBps, msg.AmountA, msg.AmountB,
		msg.PoolType, msg.Amplification,
	)
	if err != nil {
		return nil, err
	}

	return &types.MsgCreatePoolResponse{PoolId: poolID}, nil
}

// AddLiquidity deposits liquidity into a pool.
func (m msgServer) AddLiquidity(goCtx context.Context, msg *types.MsgAddLiquidity) (*types.MsgAddLiquidityResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	if err := m.acquireLock(ctx); err != nil {
		return nil, err
	}
	defer m.releaseLock(ctx)

	sender, err := sdk.AccAddressFromBech32(msg.Sender)
	if err != nil {
		return nil, types.ErrInvalidAmount.Wrapf("invalid sender: %s", err)
	}

	shares, err := m.Keeper.AddLiquidity(ctx, sender, msg.PoolId, msg.AmountA, msg.AmountB, msg.MinShares)
	if err != nil {
		return nil, err
	}

	return &types.MsgAddLiquidityResponse{Shares: shares}, nil
}

// RemoveLiquidity withdraws liquidity from a pool.
func (m msgServer) RemoveLiquidity(goCtx context.Context, msg *types.MsgRemoveLiquidity) (*types.MsgRemoveLiquidityResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	if err := m.acquireLock(ctx); err != nil {
		return nil, err
	}
	defer m.releaseLock(ctx)

	sender, err := sdk.AccAddressFromBech32(msg.Sender)
	if err != nil {
		return nil, types.ErrInvalidAmount.Wrapf("invalid sender: %s", err)
	}

	amountA, amountB, err := m.Keeper.RemoveLiquidity(ctx, sender, msg.PoolId, msg.Shares, msg.MinA, msg.MinB)
	if err != nil {
		return nil, err
	}

	return &types.MsgRemoveLiquidityResponse{AmountA: amountA, AmountB: amountB}, nil
}

// SwapExactIn executes an exact-input swap.
func (m msgServer) SwapExactIn(goCtx context.Context, msg *types.MsgSwapExactIn) (*types.MsgSwapExactInResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	if err := m.acquireLock(ctx); err != nil {
		return nil, err
	}
	defer m.releaseLock(ctx)

	sender, err := sdk.AccAddressFromBech32(msg.Sender)
	if err != nil {
		return nil, types.ErrInvalidAmount.Wrapf("invalid sender: %s", err)
	}

	receiver := sender
	if msg.Receiver != "" {
		receiver, err = parseAddress(msg.Receiver)
		if err != nil {
			return nil, types.ErrInvalidAmount.Wrapf("invalid receiver: %s", err)
		}
	}

	var integrator sdk.AccAddress
	if msg.Integrator != "" {
		integrator, err = parseAddress(msg.Integrator)
		if err != nil {
			return nil, types.ErrInvalidAmount.Wrapf("invalid integrator: %s", err)
		}
	}

	if msg.Deadline > 0 && ctx.BlockTime().Unix() > msg.Deadline {
		return nil, types.ErrDeadlineExceeded
	}

	amountOut, integratorFee, err := m.Keeper.SwapWithPools(
		ctx, msg.PoolIds, sender, receiver, msg.Path, msg.AmountIn, msg.MinOut, integrator, msg.IntegratorFeeBps,
	)
	if err != nil {
		return nil, err
	}

	return &types.MsgSwapExactInResponse{AmountOut: amountOut, IntegratorFee: integratorFee}, nil
}

// SwapExactOut executes an exact-output swap.
func (m msgServer) SwapExactOut(goCtx context.Context, msg *types.MsgSwapExactOut) (*types.MsgSwapExactOutResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	if err := m.acquireLock(ctx); err != nil {
		return nil, err
	}
	defer m.releaseLock(ctx)

	sender, err := sdk.AccAddressFromBech32(msg.Sender)
	if err != nil {
		return nil, types.ErrInvalidAmount.Wrapf("invalid sender: %s", err)
	}

	receiver := sender
	if msg.Receiver != "" {
		receiver, err = parseAddress(msg.Receiver)
		if err != nil {
			return nil, types.ErrInvalidAmount.Wrapf("invalid receiver: %s", err)
		}
	}

	var integrator sdk.AccAddress
	if msg.Integrator != "" {
		integrator, err = parseAddress(msg.Integrator)
		if err != nil {
			return nil, types.ErrInvalidAmount.Wrapf("invalid integrator: %s", err)
		}
	}

	if msg.Deadline > 0 && ctx.BlockTime().Unix() > msg.Deadline {
		return nil, types.ErrDeadlineExceeded
	}

	amountIn, integratorFee, err := m.Keeper.SwapExactOutWithPools(
		ctx, msg.PoolIds, sender, receiver, msg.Path, msg.AmountOut, msg.MaxAmountIn, integrator, msg.IntegratorFeeBps,
	)
	if err != nil {
		return nil, err
	}

	return &types.MsgSwapExactOutResponse{AmountIn: amountIn, IntegratorFee: integratorFee}, nil
}

// SetPoolStatus changes a pool's operational status. Only the authority may call it.
func (m msgServer) SetPoolStatus(goCtx context.Context, msg *types.MsgSetPoolStatus) (*types.MsgSetPoolStatusResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	if err := m.acquireLock(ctx); err != nil {
		return nil, err
	}
	defer m.releaseLock(ctx)

	if m.Authority() != msg.Authority {
		return nil, types.ErrUnauthorized.Wrapf("expected authority %s", m.Authority())
	}

	if err := m.Keeper.SetPoolStatus(ctx, msg.PoolId, msg.Status); err != nil {
		return nil, err
	}

	return &types.MsgSetPoolStatusResponse{}, nil
}

// DonatePool moves excess custody balances into the pool reserve. Anyone may
// call it: it cannot extract value, it only raises the reserve, which benefits
// LPs pro rata.
func (m msgServer) DonatePool(goCtx context.Context, msg *types.MsgDonatePool) (*types.MsgDonatePoolResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	if _, err := sdk.AccAddressFromBech32(msg.Sender); err != nil {
		return nil, types.ErrUnauthorized.Wrapf("invalid sender: %s", err)
	}

	if err := m.acquireLock(ctx); err != nil {
		return nil, err
	}
	defer m.releaseLock(ctx)

	donated, err := m.Keeper.DonatePool(ctx, msg.PoolId)
	if err != nil {
		return nil, err
	}

	return &types.MsgDonatePoolResponse{Donated: donated}, nil
}

// CheckPool verifies the custody invariant on demand.
func (m msgServer) CheckPool(goCtx context.Context, msg *types.MsgCheckPool) (*types.MsgCheckPoolResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	if _, err := sdk.AccAddressFromBech32(msg.Sender); err != nil {
		return nil, types.ErrUnauthorized.Wrapf("invalid sender: %s", err)
	}

	if err := m.acquireLock(ctx); err != nil {
		return nil, err
	}
	defer m.releaseLock(ctx)

	under, err := m.Keeper.CheckPool(ctx, msg.PoolId)
	if err != nil {
		return nil, err
	}

	return &types.MsgCheckPoolResponse{Undercollateralised: under}, nil
}

// UpdateParams updates the module params. Only the authority may call it.
func (m msgServer) UpdateParams(goCtx context.Context, msg *types.MsgUpdateParams) (*types.MsgUpdateParamsResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	if m.Authority() != msg.Authority {
		return nil, types.ErrUnauthorized.Wrapf("expected authority %s", m.Authority())
	}

	if err := m.SetParams(ctx, msg.Params); err != nil {
		return nil, err
	}

	return &types.MsgUpdateParamsResponse{}, nil
}
