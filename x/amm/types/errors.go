package types

import errorsmod "cosmossdk.io/errors"

// Module errors.
var (
	ErrInvalidAsset              = errorsmod.Register(ModuleName, 1, "invalid asset")
	ErrPoolNotFound              = errorsmod.Register(ModuleName, 2, "pool not found")
	ErrPoolExists                = errorsmod.Register(ModuleName, 3, "pool already exists")
	ErrInvalidAmount             = errorsmod.Register(ModuleName, 4, "invalid amount")
	ErrInsufficientFunds         = errorsmod.Register(ModuleName, 5, "insufficient funds")
	ErrSlippageExceeded          = errorsmod.Register(ModuleName, 6, "slippage exceeded")
	ErrInvalidPath               = errorsmod.Register(ModuleName, 7, "invalid swap path")
	ErrInvalidFee                = errorsmod.Register(ModuleName, 8, "invalid fee")
	ErrUnsupportedAsset          = errorsmod.Register(ModuleName, 9, "unsupported asset")
	ErrInsufficientInitLiquidity = errorsmod.Register(ModuleName, 10, "insufficient initial liquidity")
	ErrDeadlineExceeded          = errorsmod.Register(ModuleName, 11, "deadline exceeded")
	ErrUnauthorized              = errorsmod.Register(ModuleName, 12, "unauthorized")
	ErrInvalidParams             = errorsmod.Register(ModuleName, 13, "invalid params")
)
