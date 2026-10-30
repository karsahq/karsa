package karsa

import (
	"testing"

	ammtypes "github.com/karsahq/karsa/x/amm/types"
	nativetokentypes "github.com/karsahq/karsa/x/nativetoken/types"

	feemarkettypes "github.com/cosmos/evm/x/feemarket/types"
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

// A default base fee of 1e9 akra per gas makes every ordinary transaction
// unpayable unless the sender also sets an equally large gas price. Karsa
// disables the base fee, and `karsad init` must serialise that choice through
// the BasicModuleManager override; otherwise the fee checker rejects txs that
// look valid at broadcast time.
func TestDefaultGenesisDisablesBaseFee(t *testing.T) {
	app, _ := setup(false, 0, "karsa_262144-1", 262144)

	var genesis feemarkettypes.GenesisState
	app.AppCodec().MustUnmarshalJSON(app.DefaultGenesis()[feemarkettypes.ModuleName], &genesis)

	require.True(t, genesis.Params.NoBaseFee)
}
