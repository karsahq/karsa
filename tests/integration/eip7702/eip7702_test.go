package eip7702

import (
	"testing"

	evm "github.com/cosmos/evm"
	"github.com/cosmos/evm/tests/integration/eip7702"
	testapp "github.com/cosmos/evm/testutil/app"
	"github.com/karsahq/karsa/tests/integration"
)

func TestEIP7702IntegrationTestSuite(t *testing.T) {
	create := testapp.ToEvmAppCreator[evm.IntegrationNetworkApp](integration.CreateKarsa, "evm.IntegrationNetworkApp")
	eip7702.TestEIP7702IntegrationTestSuite(t, create)
}
