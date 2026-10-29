package precompile_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/karsahq/karsa/x/amm/precompile"
)

// TestABIMatchesInterface keeps the Go ABI in sync with IAmm.sol.
func TestABIMatchesInterface(t *testing.T) {
	expected := map[string]string{
		"quote":       "quote(address[],uint64[],uint256)",
		"getPool":     "getPool(address,address)",
		"getPoolById": "getPoolById(uint64)",
		"getPools":    "getPools(address,address)",
		"swapExactIn": "swapExactIn(address[],uint64[],uint256,uint256,address,address,uint256)",
	}

	require.Len(t, precompile.ABI.Methods, len(expected))

	for name, sig := range expected {
		method, found := precompile.ABI.Methods[name]
		require.True(t, found, "missing method %s", name)
		require.Equal(t, sig, method.Sig, "signature mismatch for %s", name)
	}
}

// TestPrecompileAddress pins the address documented in IAmm.sol.
func TestPrecompileAddress(t *testing.T) {
	require.Equal(t, "0x0000000000000000000000000000000000000900", precompile.Address.Hex())
}
