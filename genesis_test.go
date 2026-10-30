package karsa

import (
	"testing"

	ammtypes "github.com/karsahq/karsa/x/amm/types"
	nativetokentypes "github.com/karsahq/karsa/x/nativetoken/types"

	"github.com/stretchr/testify/require"
)

// The app's genesis adds the Karsa precompiles on top of the evmOS defaults.
// `karsad init` builds its genesis from App.DefaultGenesis so these end up in a
// fresh chain; building from per-module defaults instead would leave a chain
// with no working precompile at all.
func TestNewEVMGenesisStateActivatesKarsaPrecompiles(t *testing.T) {
	genesis := NewEVMGenesisState()

	require.Contains(t, genesis.Params.ActiveStaticPrecompiles, ammtypes.PrecompileAddress)
	require.Contains(t, genesis.Params.ActiveStaticPrecompiles, nativetokentypes.FactoryPrecompileAddress)
	require.Contains(t, genesis.Params.ActiveStaticPrecompiles, nativetokentypes.MinterPrecompileAddress)
}
