package integration

import (
	"testing"

	"github.com/stretchr/testify/suite"

	evm "github.com/cosmos/evm"
	"github.com/cosmos/evm/tests/integration/x/ibc"
	testapp "github.com/cosmos/evm/testutil/app"
)

func TestIBCKeeperTestSuite(t *testing.T) {
	create := testapp.ToEvmAppCreator[evm.IBCIntegrationApp](CreateKarsa, "evm.IBCIntegrationApp")
	s := ibc.NewKeeperTestSuite(create)
	suite.Run(t, s)
}
