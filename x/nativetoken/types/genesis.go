package types

import (
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// DefaultGenesisState returns the default genesis state.
func DefaultGenesisState() *GenesisState {
	return &GenesisState{
		Params:    DefaultParams(),
		Tokens:    []Token{},
		Sequences: []CreatorSequence{},
	}
}

// Validate checks the genesis state for internal consistency.
func (gs GenesisState) Validate() error {
	if err := gs.Params.Validate(); err != nil {
		return fmt.Errorf("invalid params: %w", err)
	}

	seen := make(map[string]struct{}, len(gs.Tokens))
	for _, token := range gs.Tokens {
		if _, ok := AddressFromDenom(token.Denom); !ok {
			return fmt.Errorf("token %q has an invalid denom", token.Denom)
		}
		if _, dup := seen[token.Denom]; dup {
			return fmt.Errorf("duplicate token denom %q", token.Denom)
		}
		seen[token.Denom] = struct{}{}

		if err := gs.Params.ValidateSymbol(token.Symbol); err != nil {
			return fmt.Errorf("token %q: %w", token.Denom, err)
		}
		if err := gs.Params.ValidateName(token.Name); err != nil {
			return fmt.Errorf("token %q: %w", token.Denom, err)
		}
		if _, err := NormalizeAddress(token.Address); err != nil {
			return fmt.Errorf("token %q: %w", token.Denom, err)
		}
		if _, err := NormalizeAddress(token.Creator); err != nil {
			return fmt.Errorf("token %q: %w", token.Denom, err)
		}
		if token.Controller != "" {
			if _, err := NormalizeAddress(token.Controller); err != nil {
				return fmt.Errorf("token %q: %w", token.Denom, err)
			}
		}
	}

	creators := make(map[string]struct{}, len(gs.Sequences))
	for _, seq := range gs.Sequences {
		normalized, err := NormalizeAddress(seq.Creator)
		if err != nil {
			return fmt.Errorf("sequence entry: %w", err)
		}
		if _, dup := creators[normalized]; dup {
			return fmt.Errorf("duplicate sequence entry for %q", normalized)
		}
		creators[normalized] = struct{}{}
	}

	return nil
}

// ValidateBasic performs stateless validation of the create message.
func (m MsgCreateNativeToken) ValidateBasic() error {
	if _, err := sdk.AccAddressFromBech32(m.Creator); err != nil {
		return ErrInvalidCreator.Wrapf("invalid creator: %s", err)
	}
	if m.Controller != "" {
		if _, err := NormalizeAddress(m.Controller); err != nil {
			return ErrInvalidController.Wrap(err.Error())
		}
	}
	if !m.InitialSupply.IsPositive() {
		return ErrInvalidSupply.Wrap("initial supply must be positive")
	}

	return nil
}
