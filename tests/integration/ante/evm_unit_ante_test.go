package ante

import (
	"testing"

	evm "github.com/cosmos/evm"
	"github.com/stretchr/testify/suite"

	"github.com/cosmos/evm/tests/integration/ante"
	testapp "github.com/cosmos/evm/testutil/app"
	"github.com/karsa/karsa/tests/integration"
)

func TestEvmUnitAnteTestSuite(t *testing.T) {
	create := testapp.ToEvmAppCreator[evm.AnteIntegrationApp](integration.CreateKarsa, "evm.AnteIntegrationApp")
	suite.Run(t, ante.NewEvmUnitAnteTestSuite(create))
}
