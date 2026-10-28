package types

import (
	"encoding/binary"
	"strconv"
)

const (
	// ModuleName defines the module name.
	ModuleName = "amm"
	// StoreKey defines the primary module store key.
	StoreKey = ModuleName
	// RouterKey defines the module's message routing key.
	RouterKey = ModuleName
)

var (
	// PoolKeyPrefix is the prefix for pools stored by id.
	PoolKeyPrefix = []byte{0x01}
	// PoolByAssetsPrefix maps an unordered pair of assets to a pool id.
	PoolByAssetsPrefix = []byte{0x02}
	// NextPoolIDKey stores the next pool id.
	NextPoolIDKey = []byte{0x03}
	// ParamsKey stores the module params.
	ParamsKey = []byte{0x04}
)

// PoolKey returns the store key for a pool id.
func PoolKey(id uint64) []byte {
	bz := make([]byte, 8)
	binary.BigEndian.PutUint64(bz, id)
	return append(append([]byte{}, PoolKeyPrefix...), bz...)
}

// PoolByAssetsKey returns the store key for an asset pair. Callers must pass the
// assets already sorted ascending.
func PoolByAssetsKey(assetA, assetB string) []byte {
	key := append([]byte{}, PoolByAssetsPrefix...)
	key = append(key, []byte(assetA+"|"+assetB)...)
	return key
}

// LPDenom returns the bank denom of the LP share for a pool.
func LPDenom(id uint64) string {
	return "amm/pool/" + strconv.FormatUint(id, 10)
}
