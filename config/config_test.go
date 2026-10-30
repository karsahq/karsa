package config

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

// The native ERC20 address is an identity, not a configuration knob. Keep the
// constant locked to the documented derivation so a refactor cannot silently
// move every wallet, pool and explorer reference.
func TestNativeERC20AddressIsDeterministic(t *testing.T) {
	sum := sha256.Sum256([]byte("karsa/erc20/akra"))
	derived := "0x" + hex.EncodeToString(sum[12:])

	require.Equal(t, common.HexToAddress(derived), common.HexToAddress(NativeERC20Address))
}
