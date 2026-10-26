package gov

import (
	"testing"

	"github.com/stretchr/testify/suite"

	evm "github.com/cosmos/evm"
	"github.com/cosmos/evm/tests/integration/precompiles/gov"
	testapp "github.com/cosmos/evm/testutil/app"
	"github.com/karsa/karsa/tests/integration"
)

func TestGovPrecompileTestSuite(t *testing.T) {
	create := testapp.ToEvmAppCreator[evm.GovPrecompileApp](integration.CreateKarsa, "evm.GovPrecompileApp")
	s := gov.NewPrecompileTestSuite(create)
	suite.Run(t, s)
}

func TestGovPrecompileIntegrationTestSuite(t *testing.T) {
	create := testapp.ToEvmAppCreator[evm.GovPrecompileApp](integration.CreateKarsa, "evm.GovPrecompileApp")
	gov.TestPrecompileIntegrationTestSuite(t, create)
}
