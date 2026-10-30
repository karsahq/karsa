package types

import (
	"encoding/binary"
	"fmt"
	"strings"
)

var (
	// TokenKeyPrefix indexes tokens by denom.
	TokenKeyPrefix = []byte{0x01}
	// SequenceKeyPrefix stores the per-creator sequence used for address derivation.
	SequenceKeyPrefix = []byte{0x02}
	// AddressIndexPrefix maps a lowercase 0x address to its denom.
	AddressIndexPrefix = []byte{0x03}
	// ParamsKey stores the module params.
	ParamsKey = []byte{0x04}
	// TokenListKeyPrefix enumerates every token for queries and genesis export.
	TokenListKeyPrefix = []byte{0x05}
)

// TokenKey returns the store key for a token denom.
func TokenKey(denom string) []byte {
	return append(append([]byte{}, TokenKeyPrefix...), []byte(denom)...)
}

// TokenListKey is the enumeration key for a denom. The value is empty.
func TokenListKey(denom string) []byte {
	return append(append([]byte{}, TokenListKeyPrefix...), []byte(denom)...)
}

// SequenceKey returns the store key for a creator's sequence counter.
func SequenceKey(creator string) []byte {
	return append(append([]byte{}, SequenceKeyPrefix...), []byte(creator)...)
}

// AddressIndexKey returns the store key mapping an address to its denom.
func AddressIndexKey(address string) []byte {
	return append(append([]byte{}, AddressIndexPrefix...), []byte(strings.ToLower(address))...)
}

// SequenceBytes encodes a uint64 sequence as a fixed-width key suffix.
func SequenceBytes(sequence uint64) []byte {
	bz := make([]byte, 8)
	binary.BigEndian.PutUint64(bz, sequence)

	return bz
}

// NormalizeAddress validates and lowercases a 0x address.
func NormalizeAddress(address string) (string, error) {
	if !strings.HasPrefix(address, "0x") && !strings.HasPrefix(address, "0X") {
		return "", fmt.Errorf("address %q must be a 0x hex address", address)
	}
	if len(address) != 42 {
		return "", fmt.Errorf("address %q must be 20 bytes", address)
	}

	lower := strings.ToLower(address)
	if _, ok := AddressFromDenom(DenomPrefix + lower); !ok {
		return "", fmt.Errorf("address %q is not valid hex", address)
	}

	return lower, nil
}
