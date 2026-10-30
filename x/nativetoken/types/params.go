package types

import (
	"errors"
	"fmt"
	"math/big"

	sdkmath "cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// MaxSupply is the largest supply representable by an EVM uint256.
var MaxSupply = sdkmath.NewIntFromBigInt(
	new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1)),
)

// DefaultParams returns the default module parameters.
func DefaultParams() Params {
	return Params{
		CreationFee:      sdk.Coins{},
		MinSymbolLen:     3,
		MaxSymbolLen:     12,
		MaxNameLen:       64,
		MaxInitialSupply: MaxSupply,
		OpenCreation:     false,
	}
}

// Validate checks the parameters for internal consistency.
func (p Params) Validate() error {
	if err := p.CreationFee.Validate(); err != nil {
		return fmt.Errorf("invalid creation_fee: %w", err)
	}

	if p.MinSymbolLen < 1 || p.MinSymbolLen > p.MaxSymbolLen {
		return fmt.Errorf("invalid symbol length range %d..%d", p.MinSymbolLen, p.MaxSymbolLen)
	}
	if p.MaxSymbolLen > 32 {
		return fmt.Errorf("max_symbol_len %d is too large", p.MaxSymbolLen)
	}

	if p.MaxNameLen < 1 || p.MaxNameLen > 256 {
		return fmt.Errorf("invalid max_name_len %d", p.MaxNameLen)
	}

	if !p.MaxInitialSupply.IsPositive() {
		return errors.New("max_initial_supply must be positive")
	}
	if p.MaxInitialSupply.GT(MaxSupply) {
		return errors.New("max_initial_supply exceeds uint256")
	}

	return nil
}

// ValidateSymbol checks a symbol against the params.
func (p Params) ValidateSymbol(symbol string) error {
	if len(symbol) < int(p.MinSymbolLen) || len(symbol) > int(p.MaxSymbolLen) {
		return fmt.Errorf("symbol must be %d..%d characters", p.MinSymbolLen, p.MaxSymbolLen)
	}

	for _, r := range symbol {
		isLower := r >= 'a' && r <= 'z'
		isUpper := r >= 'A' && r <= 'Z'
		isDigit := r >= '0' && r <= '9'
		if !isLower && !isUpper && !isDigit {
			return fmt.Errorf("symbol %q may only contain letters and digits", symbol)
		}
	}

	return nil
}

// ValidateName checks a display name against the params.
func (p Params) ValidateName(name string) error {
	if len(name) == 0 || len(name) > int(p.MaxNameLen) {
		return fmt.Errorf("name must be 1..%d characters", p.MaxNameLen)
	}

	return nil
}

// ValidateSupply checks an initial supply against the params.
func (p Params) ValidateSupply(supply sdkmath.Int) error {
	if !supply.IsPositive() {
		return errors.New("initial supply must be positive")
	}
	if supply.GT(p.MaxInitialSupply) {
		return fmt.Errorf("initial supply exceeds max %s", p.MaxInitialSupply)
	}

	return nil
}
