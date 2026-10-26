package ante

import (
	"testing"

	evm "github.com/cosmos/evm"
	"github.com/cosmos/evm/tests/integration/ante"
	testapp "github.com/cosmos/evm/testutil/app"
	"github.com/karsahq/karsa/tests/integration"
)

func TestAnte_Integration(t *testing.T) {
	create := testapp.ToEvmAppCreator[evm.AnteIntegrationApp](integration.CreateKarsa, "evm.AnteIntegrationApp")
	ante.TestIntegrationAnteHandler(t, create)
}

func BenchmarkAnteHandler(b *testing.B) {
	create := testapp.ToEvmAppCreator[evm.AnteIntegrationApp](integration.CreateKarsa, "evm.AnteIntegrationApp")
	// Run the benchmark with a mock EVM app
	ante.RunBenchmarkAnteHandler(b, create)
}

func TestValidateHandlerOptions(t *testing.T) {
	create := testapp.ToEvmAppCreator[evm.AnteIntegrationApp](integration.CreateKarsa, "evm.AnteIntegrationApp")
	ante.RunValidateHandlerOptionsTest(t, create)
}
