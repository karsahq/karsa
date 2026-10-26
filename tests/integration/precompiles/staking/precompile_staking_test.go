package staking

import (
	"testing"

	"github.com/stretchr/testify/suite"

	evm "github.com/cosmos/evm"
	"github.com/cosmos/evm/tests/integration/precompiles/staking"
	testapp "github.com/cosmos/evm/testutil/app"
	"github.com/karsa/karsa/tests/integration"
)

func TestStakingPrecompileTestSuite(t *testing.T) {
	create := testapp.ToEvmAppCreator[evm.StakingPrecompileApp](integration.CreateKarsa, "evm.StakingPrecompileApp")
	s := staking.NewPrecompileTestSuite(create)
	suite.Run(t, s)
}

func TestStakingPrecompileIntegrationTestSuite(t *testing.T) {
	create := testapp.ToEvmAppCreator[evm.StakingPrecompileApp](integration.CreateKarsa, "evm.StakingPrecompileApp")
	staking.TestPrecompileIntegrationTestSuite(t, create)
}
