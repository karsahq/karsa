package types

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

const (
	// ModuleName defines the module name.
	ModuleName = "nativetoken"
	// StoreKey defines the primary module store key.
	StoreKey = ModuleName
	// RouterKey defines the module's message routing key.
	RouterKey = ModuleName
)

const (
	// DenomPrefix marks a bank denom that represents a native ERC20 token.
	//
	// The prefix is permanent: it is part of the address <-> denom mapping, so
	// changing it would orphan every token that has already been created.
	DenomPrefix = "n:"

	// addressPreimagePrefix namespaces the hash used to derive token addresses.
	// A prefix distinct from "amm/lp/" keeps native tokens disjoint from LP
	// shares, which occupy the same 20-byte precompile space.
	addressPreimagePrefix = "karsa/native/"

	// DenomLen is the exact length of a native token denom: "n:" + "0x" + 40 hex.
	DenomLen = 44
)

// Static precompile addresses reserved for the token precompiles.
const (
	// FactoryPrecompileAddress creates native tokens from EVM contracts.
	FactoryPrecompileAddress = "0x0000000000000000000000000000000000000901"
	// MinterPrecompileAddress mints and burns native tokens on behalf of a
	// registered controller contract.
	MinterPrecompileAddress = "0x0000000000000000000000000000000000000902"
)

// AddressFor derives the deterministic EVM address of the token a creator
// creates at the given sequence number.
//
// The preimage is a plain string so anyone can reproduce it off-chain:
//
//	sha256("karsa/native/" + lowercase_hex_creator + "/" + decimal_sequence)[12:]
func AddressFor(creator common.Address, sequence uint64) common.Address {
	preimage := fmt.Sprintf(
		"%s%s/%d", addressPreimagePrefix, strings.ToLower(creator.Hex()), sequence,
	)
	sum := sha256.Sum256([]byte(preimage))

	return common.BytesToAddress(sum[12:])
}

// DenomFor returns the bank denom for a native token address.
func DenomFor(address common.Address) string {
	return DenomPrefix + strings.ToLower(address.Hex())
}

// AddressFromDenom parses a native token denom back into its address.
func AddressFromDenom(denom string) (common.Address, bool) {
	if len(denom) != DenomLen || !strings.HasPrefix(denom, DenomPrefix+"0x") {
		return common.Address{}, false
	}

	hexPart := strings.TrimPrefix(denom, DenomPrefix)
	// Denoms are compared verbatim, so a mixed-case denom is a different denom.
	// Only the lowercase form is valid.
	if strings.ToLower(hexPart) != hexPart || !common.IsHexAddress(hexPart) {
		return common.Address{}, false
	}

	return common.HexToAddress(hexPart), true
}

// IsNativeTokenDenom reports whether denom is shaped like a native token denom.
// It does not check that the token exists.
func IsNativeTokenDenom(denom string) bool {
	_, ok := AddressFromDenom(denom)
	return ok
}

// IsReservedAddress reports whether an address falls inside the static
// precompile range (0x0001..0x09ff), which a token address must never do.
func IsReservedAddress(address common.Address) bool {
	b := address.Bytes()
	for _, x := range b[:18] {
		if x != 0 {
			return false
		}
	}

	v := uint16(b[18])<<8 | uint16(b[19])

	return v >= 0x0001 && v <= 0x09ff
}
