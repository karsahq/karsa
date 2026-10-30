package karsa

import (
	"encoding/json"

	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/x/bank"
	"github.com/cosmos/cosmos-sdk/x/gov"
	"github.com/cosmos/cosmos-sdk/x/mint"
	"github.com/cosmos/cosmos-sdk/x/staking"

	"github.com/cosmos/evm/x/erc20"
	"github.com/cosmos/evm/x/vm"
)

// The app's default genesis differs from the per-module defaults for several
// modules: every denom-bearing module must use akra instead of the SDK's "stake"
// placeholder, and the EVM module needs the Karsa precompile list.
//
// `karsad init` serialises the BasicManager defaults. Without these overrides a
// freshly initialised chain would have no active precompile at all (the AMM,
// token factory and minter would be dead) and staking would bond a denom that
// does not exist, so gentx and validators could not work. Nothing reported it.

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

type stakingGenesisBasic struct{ staking.AppModuleBasic }

func (stakingGenesisBasic) DefaultGenesis(cdc codec.JSONCodec) json.RawMessage {
	return cdc.MustMarshalJSON(NewStakingGenesisState())
}

type govGenesisBasic struct{ gov.AppModuleBasic }

func (govGenesisBasic) DefaultGenesis(cdc codec.JSONCodec) json.RawMessage {
	return cdc.MustMarshalJSON(NewGovGenesisState())
}

type bankGenesisBasic struct{ bank.AppModuleBasic }

func (bankGenesisBasic) DefaultGenesis(cdc codec.JSONCodec) json.RawMessage {
	return cdc.MustMarshalJSON(NewBankGenesisState())
}
