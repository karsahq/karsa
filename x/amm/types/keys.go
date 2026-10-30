package types

import (
	"crypto/sha256"
	"encoding/binary"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
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
	// PoolByAssetsPrefix maps an unordered pair of assets to a list of pool ids.
	PoolByAssetsPrefix = []byte{0x02}
	// NextPoolIDKey stores the next pool id.
	NextPoolIDKey = []byte{0x03}
	// ParamsKey stores the module params.
	ParamsKey = []byte{0x04}
	// ReentrancyKey is set while a state-mutating message is executing.
	ReentrancyKey = []byte{0x05}
	// ObservationsKeyPrefix stores TWAP observations per pool.
	ObservationsKeyPrefix = []byte{0x06}
	// PoolKeyByParamsPrefix maps (pair, pool type, fee) to a pool id.
	PoolKeyByParamsPrefix = []byte{0x07}
)

// PrecompileAddress is the fixed EVM address of the AMM precompile.
const PrecompileAddress = "0x0000000000000000000000000000000000000900"

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

// PoolKeyByParamsKey returns the uniqueness key for a pool configuration.
// Callers must pass the assets already sorted ascending.
func PoolKeyByParamsKey(assetA, assetB string, poolType PoolType, feeBps uint32) []byte {
	key := append([]byte{}, PoolKeyByParamsPrefix...)
	key = append(key, []byte(assetA+"|"+assetB+"|")...)
	key = append(key, []byte(strconv.FormatInt(int64(poolType), 10)+"|")...)
	key = append(key, []byte(strconv.FormatUint(uint64(feeBps), 10))...)
	return key
}

// LPDenom returns the bank denom of the LP share for a pool.
func LPDenom(id uint64) string {
	return "amm/pool/" + strconv.FormatUint(id, 10)
}

// LPAssetAddress derives the deterministic ERC20 precompile address of an LP denom.
//
// The x/erc20 helper used for IBC vouchers (GetIBCDenomAddress) only accepts
// "ibc/…" denoms, so LP shares need their own namespaced derivation. The
// "amm/lp/" prefix keeps it disjoint from IBC trace hashes.
func LPAssetAddress(lpDenom string) common.Address {
	hash := sha256.Sum256([]byte("amm/lp/" + lpDenom))
	return common.BytesToAddress(hash[12:])
}

// CustodyAddress derives the address that holds a directly custodied ERC20 for a
// pool.
//
// Each pool gets its own address so a donation or a misbehaving token in one
// pool cannot shift another pool's reserve. The "amm/custody/" prefix keeps it
// disjoint from "amm/lp/".
func CustodyAddress(poolID uint64) common.Address {
	hash := sha256.Sum256([]byte("amm/custody/" + strconv.FormatUint(poolID, 10)))
	return common.BytesToAddress(hash[12:])
}
