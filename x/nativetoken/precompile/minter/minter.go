package minter

import (
	"bytes"
	"fmt"
	"math/big"
	"strings"

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

// PrecompileAddress is the fixed address of the token minter precompile.
const PrecompileAddress = nativetokentypes.MinterPrecompileAddress

// Method names.
const (
	MintMethod = "mint"
	BurnMethod = "burn"
)

const abiJSON = `[
  {
    "name": "mint",
    "type": "function",
    "stateMutability": "nonpayable",
    "inputs": [
      {"name": "token", "type": "address"},
      {"name": "to", "type": "address"},
      {"name": "amount", "type": "uint256"}
    ],
    "outputs": []
  },
  {
    "name": "burn",
    "type": "function",
    "stateMutability": "nonpayable",
    "inputs": [
      {"name": "token", "type": "address"},
      {"name": "amount", "type": "uint256"}
    ],
    "outputs": []
  }
]`

var (
	// ABI is the parsed minter precompile ABI.
	ABI abi.ABI
	// Address is the minter precompile address.
	Address = common.HexToAddress(PrecompileAddress)
)

func init() {
	parsed, err := abi.JSON(bytes.NewReader([]byte(abiJSON)))
	if err != nil {
		panic("failed to parse nativetoken minter precompile abi: " + err.Error())
	}
	ABI = parsed
}

var _ vm.PrecompiledContract = &Precompile{}

// Precompile lets a registered controller contract mint and burn a token.
type Precompile struct {
	cmn.Precompile
	abi.ABI
	keeper keeper.Keeper
}

// NewPrecompile creates a new minter precompile.
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
func (Precompile) Name() string { return "nativetoken-minter" }

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
		return p.Execute(ctx, contract, readOnly)
	})
}

// IsTransaction reports whether the method mutates state.
func (Precompile) IsTransaction(*abi.Method) bool { return true }

// Execute dispatches the ABI method.
func (p Precompile) Execute(ctx sdk.Context, contract *vm.Contract, readOnly bool) ([]byte, error) {
	method, args, err := cmn.SetupABI(p.ABI, contract, readOnly, p.IsTransaction)
	if err != nil {
		return nil, err
	}

	switch method.Name {
	case MintMethod:
		return p.mint(ctx, contract, method, args)
	case BurnMethod:
		return p.burn(ctx, contract, method, args)
	default:
		return nil, fmt.Errorf(cmn.ErrUnknownMethod, method.Name)
	}
}

func (p Precompile) mint(
	ctx sdk.Context, contract *vm.Contract, method *abi.Method, args []interface{},
) ([]byte, error) {
	tokenAddr, to, amount, err := parseMintArgs(args)
	if err != nil {
		return nil, err
	}

	token, found := p.keeper.GetTokenByAddress(ctx, tokenAddr)
	if !found {
		return nil, nativetokentypes.ErrTokenNotFound.Wrap(tokenAddr)
	}

	err = p.keeper.MintByController(
		ctx, contract.Caller(), token.Denom,
		sdk.AccAddress(to.Bytes()), sdkmath.NewIntFromBigInt(amount),
	)
	if err != nil {
		return nil, err
	}

	return method.Outputs.Pack()
}

func (p Precompile) burn(
	ctx sdk.Context, contract *vm.Contract, method *abi.Method, args []interface{},
) ([]byte, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf(cmn.ErrInvalidNumberOfArgs, 2, len(args))
	}

	tokenArg, ok := args[0].(common.Address)
	if !ok {
		return nil, fmt.Errorf("invalid token argument")
	}
	amount, ok := args[1].(*big.Int)
	if !ok || amount == nil {
		return nil, fmt.Errorf("invalid amount argument")
	}

	tokenAddr := strings.ToLower(tokenArg.Hex())
	token, found := p.keeper.GetTokenByAddress(ctx, tokenAddr)
	if !found {
		return nil, nativetokentypes.ErrTokenNotFound.Wrap(tokenAddr)
	}

	// Burn only from the controller's own balance. Letting the controller burn
	// arbitrary holders would reintroduce a freeze power the model rejects.
	caller := contract.Caller()
	err := p.keeper.BurnByController(
		ctx, caller, token.Denom,
		sdk.AccAddress(caller.Bytes()), sdkmath.NewIntFromBigInt(amount),
	)
	if err != nil {
		return nil, err
	}

	return method.Outputs.Pack()
}

func parseMintArgs(args []interface{}) (string, common.Address, *big.Int, error) {
	if len(args) != 3 {
		return "", common.Address{}, nil, fmt.Errorf(cmn.ErrInvalidNumberOfArgs, 3, len(args))
	}

	tokenArg, ok := args[0].(common.Address)
	if !ok {
		return "", common.Address{}, nil, fmt.Errorf("invalid token argument")
	}
	to, ok := args[1].(common.Address)
	if !ok {
		return "", common.Address{}, nil, fmt.Errorf("invalid to argument")
	}
	amount, ok := args[2].(*big.Int)
	if !ok || amount == nil {
		return "", common.Address{}, nil, fmt.Errorf("invalid amount argument")
	}

	return strings.ToLower(tokenArg.Hex()), to, amount, nil
}
