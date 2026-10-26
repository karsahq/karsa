package common

import (
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/cosmos/evm/tests/integration/precompiles/common"
	"github.com/karsahq/karsa/tests/integration"
)

func TestStaticCallTestSuite(t *testing.T) {
	s := common.NewStaticCallTestSuite(integration.CreateKarsa)
	suite.Run(t, s)
}
