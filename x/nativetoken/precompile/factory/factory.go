package factory

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"

	cmn "github.com/cosmos/evm/precompiles/common"

	"github.com/karsahq/karsa/x/nativetoken/keeper"
	nativetokentypes "github.com/karsahq/karsa/x/nativetoken/types"

	sdkmath "cosmossdk.io/math"
	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// PrecompileAddress is the fixed address of the token factory precompile.
const PrecompileAddress = nativetokentypes.FactoryPrecompileAddress

// CreateTokenMethod is the only method exposed.
const CreateTokenMethod = "createToken"

const abiJSON = `[
  {
    "name": "createToken",
    "type": "function",
    "stateMutability": "nonpayable",
    "inputs": [
      {"name": "name", "type": "string"},
      {"name": "symbol", "type": "string"},
      {"name": "initialSupply", "type": "uint256"},
      {"name": "controller", "type": "address"}
    ],
    "outputs": [{"name": "token", "type": "address"}]
  }
]`

var (
	// ABI is the parsed factory precompile ABI.
	ABI abi.ABI
	// Address is the factory precompile address.
	Address = common.HexToAddress(PrecompileAddress)
)

func init() {
	parsed, err := abi.JSON(bytes.NewReader([]byte(abiJSON)))
	if err != nil {
		panic("failed to parse nativetoken factory precompile abi: " + err.Error())
	}
	ABI = parsed
}

var _ vm.PrecompiledContract = &Precompile{}

// Precompile exposes native token creation to EVM contracts.
type Precompile struct {
	cmn.Precompile
	abi.ABI
	keeper keeper.Keeper
}

// NewPrecompile creates a new factory precompile.
func NewPrecompile(k keeper.Keeper) *Precompile {
	return &Precompile{
		Precompile: cmn.Precompile{
			KvGasConfig:          storetypes.KVGasConfig(),
			TransientKVGasConfig: storetypes.TransientGasConfig(),
			ContractAddress:      Address,
		},
		ABI:    ABI,
		keeper: k,
	}
}

// Name returns the precompile name.
func (Precompile) Name() string { return "nativetoken-factory" }

// RequiredGas returns the gas required to execute the precompile call.
func (p Precompile) RequiredGas(input []byte) uint64 {
	if len(input) < 4 {
		return 0
	}

	method, err := p.MethodById(input[:4])
	if err != nil {
		return 0
	}

	return p.Precompile.RequiredGas(input, p.IsTransaction(method))
}

// Run executes the precompile.
func (p Precompile) Run(evm *vm.EVM, contract *vm.Contract, readOnly bool) ([]byte, error) {
	return p.RunNativeAction(evm, contract, func(ctx sdk.Context) ([]byte, error) {
		return p.Execute(ctx, evm.StateDB, contract, readOnly)
	})
}

// IsTransaction reports whether the method mutates state.
func (Precompile) IsTransaction(*abi.Method) bool { return true }

// Execute dispatches the ABI method.
func (p Precompile) Execute(
	ctx sdk.Context, stateDB vm.StateDB, contract *vm.Contract, readOnly bool,
) ([]byte, error) {
	method, args, err := cmn.SetupABI(p.ABI, contract, readOnly, p.IsTransaction)
	if err != nil {
		return nil, err
	}

	switch method.Name {
	case CreateTokenMethod:
		return p.createToken(ctx, stateDB, contract, method, args)
	default:
		return nil, fmt.Errorf(cmn.ErrUnknownMethod, method.Name)
	}
}

func (p Precompile) createToken(
	ctx sdk.Context, stateDB vm.StateDB, contract *vm.Contract, method *abi.Method, args []interface{},
) ([]byte, error) {
	if len(args) != 4 {
		return nil, fmt.Errorf(cmn.ErrInvalidNumberOfArgs, 4, len(args))
	}

	name, ok := args[0].(string)
	if !ok {
		return nil, fmt.Errorf("invalid name argument")
	}
	symbol, ok := args[1].(string)
	if !ok {
		return nil, fmt.Errorf("invalid symbol argument")
	}
	supply, ok := args[2].(*big.Int)
	if !ok || supply == nil {
		return nil, fmt.Errorf("invalid initialSupply argument")
	}
	controller, ok := args[3].(common.Address)
	if !ok {
		return nil, fmt.Errorf("invalid controller argument")
	}

	controllerHex := ""
	if controller != (common.Address{}) {
		controllerHex = controller.Hex()
	}

	// The caller becomes the creator. The keeper rejects callers without code, so
	// an EOA cannot reach this path even by calling the precompile directly.
	creator := sdk.AccAddress(contract.Caller().Bytes())

	token, err := p.keeper.CreateNativeToken(
		ctx, creator, symbol, name, sdkmath.NewIntFromBigInt(supply), controllerHex,
	)
	if err != nil {
		return nil, err
	}

	tokenAddr := common.HexToAddress(token.Address)
	if err := nativetokentypes.EmitTokenCreated(
		stateDB, Address, tokenAddr, contract.Caller(), token.Symbol,
	); err != nil {
		return nil, err
	}

	return method.Outputs.Pack(tokenAddr)
}
