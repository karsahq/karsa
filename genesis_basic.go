package karsa

import (
	"encoding/json"

	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/types/module"
	"github.com/cosmos/cosmos-sdk/x/mint"

	"github.com/cosmos/evm/x/erc20"
	"github.com/cosmos/evm/x/vm"
)

// The app's default genesis differs from the per-module defaults for three
// modules: the EVM module gets the Karsa precompile list and denom, the erc20
// module gets the genesis token pair, and mint gets the Karsa supply schedule.
//
// `karsad init` serialises the BasicManager defaults, so without these overrides
// a freshly initialised chain would start with no active precompile at all - the
// AMM, token factory and minter would be dead - and nothing would report it.

type evmGenesisBasic struct{ vm.AppModuleBasic }

func (evmGenesisBasic) DefaultGenesis(cdc codec.JSONCodec) json.RawMessage {
	return cdc.MustMarshalJSON(NewEVMGenesisState())
}

type erc20GenesisBasic struct{ erc20.AppModuleBasic }

func (erc20GenesisBasic) DefaultGenesis(cdc codec.JSONCodec) json.RawMessage {
	return cdc.MustMarshalJSON(NewErc20GenesisState())
}

type mintGenesisBasic struct{ mint.AppModuleBasic }

func (mintGenesisBasic) DefaultGenesis(cdc codec.JSONCodec) json.RawMessage {
	return cdc.MustMarshalJSON(NewMintGenesisState())
}

// genesisBasicOverrides maps module names to basics whose DefaultGenesis returns
// the app-level genesis.
func genesisBasicOverrides() map[string]module.AppModuleBasic {
	return map[string]module.AppModuleBasic{
		vm.AppModuleBasic{}.Name():    evmGenesisBasic{},
		erc20.AppModuleBasic{}.Name(): erc20GenesisBasic{},
		mint.AppModuleBasic{}.Name():  mintGenesisBasic{},
	}
}
