package karsa

import (
	"encoding/json"

	sdkmath "cosmossdk.io/math"

	testconstants "github.com/cosmos/evm/testutil/constants"
	erc20types "github.com/cosmos/evm/x/erc20/types"
	feemarkettypes "github.com/cosmos/evm/x/feemarket/types"
	evmtypes "github.com/cosmos/evm/x/vm/types"
	"github.com/karsahq/karsa/config"
	ammtypes "github.com/karsahq/karsa/x/amm/types"
	nativetokentypes "github.com/karsahq/karsa/x/nativetoken/types"

	minttypes "github.com/cosmos/cosmos-sdk/x/mint/types"
)

// GenesisState of the blockchain is represented here as a map of raw json
// messages key'd by an identifier string.
// The identifier is used to determine which module genesis information belongs
// to so it may be appropriately routed during init chain.
// Within this application default genesis information is retrieved from
// the ModuleBasicManager which populates json from each BasicModule
// object provided to it during init.
type GenesisState map[string]json.RawMessage

// NewEVMGenesisState returns the default genesis state for the EVM module.
//
// NOTE: for the example chain implementation we need to set the default EVM denomination,
// enable ALL precompiles, and include default preinstalls.
func NewEVMGenesisState() *evmtypes.GenesisState {
	evmGenState := evmtypes.DefaultGenesisState()
	evmGenState.Params.EvmDenom = config.BaseDenom
	evmGenState.Params.ExtendedDenomOptions = &evmtypes.ExtendedDenomOptions{ExtendedDenom: config.BaseDenom}
	evmGenState.Params.ActiveStaticPrecompiles = append(
		append([]string{}, evmtypes.AvailableStaticPrecompiles...),
		ammtypes.PrecompileAddress,
		nativetokentypes.FactoryPrecompileAddress,
		nativetokentypes.MinterPrecompileAddress,
	)
	evmGenState.Preinstalls = evmtypes.DefaultPreinstalls

	return evmGenState
}

// NewErc20GenesisState returns the default genesis state for the ERC20 module.
//
// NOTE: for the example chain implementation we are also adding a default token pair,
// which is the base denomination of the chain (i.e. the WEVMOS contract).
func NewErc20GenesisState() *erc20types.GenesisState {
	erc20GenState := erc20types.DefaultGenesisState()

	// Use the example token pairs, but point the native pair at the Karsa base denom.
	tokenPairs := make([]erc20types.TokenPair, len(testconstants.ExampleTokenPairs))
	copy(tokenPairs, testconstants.ExampleTokenPairs)
	for i := range tokenPairs {
		tokenPairs[i].Denom = config.BaseDenom
	}
	erc20GenState.TokenPairs = tokenPairs
	erc20GenState.NativePrecompiles = []string{testconstants.WEVMOSContractMainnet}

	return erc20GenState
}

// NewMintGenesisState returns the default genesis state for the mint module.
//
// It carries the Karsa supply schedule rather than the SDK defaults: a flat 5%
// inflation (rate change zero, min and max equal), 21,038,400 blocks per year
// (~1.5s blocks), and a 1 billion KRA cap. These used to live only in the
// local_node.sh jq patches, so a chain initialised without that script ran on
// SDK defaults - 7% to 20% moving inflation and no supply cap.
func NewMintGenesisState() *minttypes.GenesisState {
	mintGenState := minttypes.DefaultGenesisState()

	mintGenState.Params.MintDenom = config.BaseDenom
	mintGenState.Params.InflationRateChange = sdkmath.LegacyZeroDec()
	mintGenState.Params.InflationMax = sdkmath.LegacyMustNewDecFromStr("0.05")
	mintGenState.Params.InflationMin = sdkmath.LegacyMustNewDecFromStr("0.05")
	mintGenState.Params.BlocksPerYear = config.BlocksPerYear
	mintGenState.Params.MaxSupply = config.MaxSupply

	mintGenState.Minter.Inflation = sdkmath.LegacyMustNewDecFromStr("0.05")

	return mintGenState
}

// NewFeeMarketGenesisState returns the default genesis state for the feemarket module.
//
// NOTE: for the example chain implementation we are disabling the base fee.
func NewFeeMarketGenesisState() *feemarkettypes.GenesisState {
	feeMarketGenState := feemarkettypes.DefaultGenesisState()
	feeMarketGenState.Params.NoBaseFee = true

	return feeMarketGenState
}
