package types

import errorsmod "cosmossdk.io/errors"

// Module errors.
var (
	ErrInvalidParams         = errorsmod.Register(ModuleName, 1, "invalid params")
	ErrInvalidDenom          = errorsmod.Register(ModuleName, 2, "invalid denom")
	ErrTokenNotFound         = errorsmod.Register(ModuleName, 3, "token not found")
	ErrTokenExists           = errorsmod.Register(ModuleName, 4, "token already exists")
	ErrInvalidSymbol         = errorsmod.Register(ModuleName, 5, "invalid symbol")
	ErrInvalidName           = errorsmod.Register(ModuleName, 6, "invalid name")
	ErrInvalidSupply         = errorsmod.Register(ModuleName, 7, "invalid supply")
	ErrInvalidController     = errorsmod.Register(ModuleName, 8, "invalid controller")
	ErrInvalidCreator        = errorsmod.Register(ModuleName, 9, "invalid creator")
	ErrAddressCollision      = errorsmod.Register(ModuleName, 10, "address collision")
	ErrControllerNotContract = errorsmod.Register(ModuleName, 11, "controller must be a contract")
	ErrUnauthorized          = errorsmod.Register(ModuleName, 12, "unauthorized")
	ErrInsufficientFee       = errorsmod.Register(ModuleName, 13, "insufficient creation fee")
	ErrCreatorNotContract    = errorsmod.Register(ModuleName, 14, "creator must be a contract")
)
