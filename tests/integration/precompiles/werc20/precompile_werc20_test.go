package werc20

import (
	"testing"

	"github.com/stretchr/testify/suite"

	evm "github.com/cosmos/evm"
	"github.com/cosmos/evm/tests/integration/precompiles/werc20"
	testapp "github.com/cosmos/evm/testutil/app"
	"github.com/karsa/karsa/tests/integration"
)

func TestWERC20PrecompileUnitTestSuite(t *testing.T) {
	create := testapp.ToEvmAppCreator[evm.WERC20PrecompileApp](integration.CreateKarsa, "evm.WERC20PrecompileApp")
	s := werc20.NewPrecompileUnitTestSuite(create)
	suite.Run(t, s)
}

func TestWERC20PrecompileIntegrationTestSuite(t *testing.T) {
	create := testapp.ToEvmAppCreator[evm.WERC20PrecompileApp](integration.CreateKarsa, "evm.WERC20PrecompileApp")
	werc20.TestPrecompileIntegrationTestSuite(t, create)
}
