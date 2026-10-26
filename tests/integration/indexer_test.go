package integration

import (
	"testing"

	evm "github.com/cosmos/evm"
	"github.com/cosmos/evm/tests/integration/indexer"
	testapp "github.com/cosmos/evm/testutil/app"
)

func TestKVIndexer(t *testing.T) {
	create := testapp.ToEvmAppCreator[evm.IntegrationNetworkApp](CreateKarsa, "evm.IntegrationNetworkApp")
	indexer.TestKVIndexer(t, create)
}
