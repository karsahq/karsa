package config

import (
	sdkmath "cosmossdk.io/math"

	clienthelpers "cosmossdk.io/client/v2/helpers"
	serverconfig "github.com/cosmos/cosmos-sdk/server/config"
	cosmosevmserverconfig "github.com/cosmos/evm/server/config"
)

const (
	// BaseDenom is the smallest unit of the native token. It carries 18 decimals,
	// which matches the EVM decimals of the native coin.
	BaseDenom = "akra"
	// DisplayDenom is the display unit of the native token.
	DisplayDenom = "kra"
	// Symbol is the ticker symbol of the native token.
	Symbol = "KRA"

	// NativeERC20Address is the ERC20 view of akra. It is derived as
	// sha256("karsa/erc20/akra")[12:], the same scheme used for custody and
	// native-token addresses, and is registered as a native precompile at
	// genesis. Changing it is a consensus-breaking genesis change.
	NativeERC20Address = "0xd9171c1192d82ecd4f71dec2ee0264769af9531e"
)

const (
	// BlocksPerYear corresponds to ~1.5s blocks, the configured cadence.
	BlocksPerYear uint64 = 21_038_400
)

// MaxSupply is the hard cap in base units: 1 billion KRA at 18 decimals.
var MaxSupply = sdkmath.NewIntFromUint64(1_000_000_000).MulRaw(1_000_000_000_000_000_000)

func MustGetDefaultNodeHome() string {
	defaultNodeHome, err := clienthelpers.GetNodeHomeDirectory(".karsa")
	if err != nil {
		panic(err)
	}
	return defaultNodeHome
}

// InitAppConfig helps to override default appConfig template and configs.
// return "", nil if no custom configuration is required for the application.
func InitAppConfig(denom string, evmChainID uint64) (string, interface{}) {
	// Optionally allow the chain developer to overwrite the SDK's default
	// server config.
	srvCfg := serverconfig.DefaultConfig()
	// The SDK's default minimum gas price is set to "" (empty value) inside
	// app.toml. If left empty by validators, the node will halt on startup.
	// However, the chain developer can set a default app.toml value for their
	// validators here.
	//
	// In summary:
	// - if you leave srvCfg.MinGasPrices = "", all validators MUST tweak their
	//   own app.toml config,
	// - if you set srvCfg.MinGasPrices non-empty, validators CAN tweak their
	//   own app.toml to override, or use this default value.
	//
	// In this example application, we set the min gas prices to 0.
	srvCfg.MinGasPrices = "0" + denom

	evmCfg := cosmosevmserverconfig.DefaultEVMConfig()
	evmCfg.EVMChainID = evmChainID

	customAppConfig := EVMAppConfig{
		Config:  *srvCfg,
		EVM:     *evmCfg,
		JSONRPC: *cosmosevmserverconfig.DefaultJSONRPCConfig(),
		TLS:     *cosmosevmserverconfig.DefaultTLSConfig(),
	}

	return EVMAppTemplate, customAppConfig
}

type EVMAppConfig struct {
	serverconfig.Config

	EVM     cosmosevmserverconfig.EVMConfig
	JSONRPC cosmosevmserverconfig.JSONRPCConfig
	TLS     cosmosevmserverconfig.TLSConfig
}

const EVMAppTemplate = serverconfig.DefaultConfigTemplate + cosmosevmserverconfig.DefaultEVMConfigTemplate
