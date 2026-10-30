package config

import (
	"maps"
	"sort"

	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	distrtypes "github.com/cosmos/cosmos-sdk/x/distribution/types"
	govtypes "github.com/cosmos/cosmos-sdk/x/gov/types"
	minttypes "github.com/cosmos/cosmos-sdk/x/mint/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	cosmosevmutils "github.com/cosmos/evm/utils"
	erc20types "github.com/cosmos/evm/x/erc20/types"
	feemarkettypes "github.com/cosmos/evm/x/feemarket/types"
	vmtypes "github.com/cosmos/evm/x/vm/types"
	transfertypes "github.com/cosmos/ibc-go/v11/modules/apps/transfer/types"
	corevm "github.com/ethereum/go-ethereum/core/vm"
	ammtypes "github.com/karsahq/karsa/x/amm/types"
	nativetokentypes "github.com/karsahq/karsa/x/nativetoken/types"
)

// BlockedAddresses returns all the app's blocked account addresses.
//
// Note, this includes:
//   - module accounts
//   - Ethereum's native precompiled smart contracts
//   - Cosmos EVM' available static precompiled contracts
func BlockedAddresses() map[string]bool {
	blockedAddrs := make(map[string]bool)

	maccPerms := GetMaccPerms()
	accs := make([]string, 0, len(maccPerms))
	for acc := range maccPerms {
		accs = append(accs, acc)
	}
	sort.Strings(accs)

	for _, acc := range accs {
		blockedAddrs[authtypes.NewModuleAddress(acc).String()] = true
	}

	// The AMM module must receive minted bank denom when converting an external
	// ERC20 to its bank-backed form. Keeping the module address unblocked is what
	// lets x/erc20 mint directly to the pool's custody account. The AMM precompile
	// address below remains blocked.
	delete(blockedAddrs, authtypes.NewModuleAddress(ammtypes.ModuleName).String())

	blockedPrecompilesHex := make([]string, 0, len(vmtypes.AvailableStaticPrecompiles)+len(corevm.PrecompiledAddressesPrague)+1)
	blockedPrecompilesHex = append(blockedPrecompilesHex, vmtypes.AvailableStaticPrecompiles...)
	blockedPrecompilesHex = append(blockedPrecompilesHex, ammtypes.PrecompileAddress)
	blockedPrecompilesHex = append(blockedPrecompilesHex, nativetokentypes.FactoryPrecompileAddress)
	blockedPrecompilesHex = append(blockedPrecompilesHex, nativetokentypes.MinterPrecompileAddress)
	for _, addr := range corevm.PrecompiledAddressesPrague {
		blockedPrecompilesHex = append(blockedPrecompilesHex, addr.Hex())
	}

	for _, precompile := range blockedPrecompilesHex {
		blockedAddrs[cosmosevmutils.Bech32StringFromHexAddress(precompile)] = true
	}

	return blockedAddrs
}

// module account permissions
var maccPerms = map[string][]string{
	authtypes.FeeCollectorName:     nil,
	distrtypes.ModuleName:          nil,
	transfertypes.ModuleName:       {authtypes.Minter, authtypes.Burner},
	minttypes.ModuleName:           {authtypes.Minter},
	stakingtypes.BondedPoolName:    {authtypes.Burner, authtypes.Staking},
	stakingtypes.NotBondedPoolName: {authtypes.Burner, authtypes.Staking},
	govtypes.ModuleName:            {authtypes.Burner},

	// Cosmos EVM modules
	vmtypes.ModuleName:        {authtypes.Minter, authtypes.Burner},
	feemarkettypes.ModuleName: nil,
	erc20types.ModuleName:     {authtypes.Minter, authtypes.Burner},

	// Karsa modules
	ammtypes.ModuleName:         {authtypes.Minter, authtypes.Burner},
	nativetokentypes.ModuleName: {authtypes.Minter, authtypes.Burner},
}

// GetMaccPerms returns a copy of the module account permissions
func GetMaccPerms() map[string][]string {
	return maps.Clone(maccPerms)
}
