package config

import (
	"testing"

	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	cosmosevmutils "github.com/cosmos/evm/utils"
	erc20types "github.com/cosmos/evm/x/erc20/types"

	"github.com/stretchr/testify/require"

	ammtypes "github.com/karsahq/karsa/x/amm/types"
)

func TestBlockedAddressesAllowAMMModuleButBlockPrecompile(t *testing.T) {
	blocked := BlockedAddresses()

	ammModule := authtypes.NewModuleAddress(ammtypes.ModuleName).String()
	require.False(t, blocked[ammModule], "AMM module must be able to receive minted bank denom")

	erc20Module := authtypes.NewModuleAddress(erc20types.ModuleName).String()
	require.True(t, blocked[erc20Module], "other module accounts stay blocked")

	ammPrecompile := cosmosevmutils.Bech32StringFromHexAddress(ammtypes.PrecompileAddress)
	require.True(t, blocked[ammPrecompile], "AMM precompile address must stay blocked")
}
