package precompile

import (
	"bytes"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"

	cmn "github.com/cosmos/evm/precompiles/common"
	"github.com/cosmos/evm/x/vm/statedb"

	"github.com/karsahq/karsa/x/amm/keeper"
	ammtypes "github.com/karsahq/karsa/x/amm/types"

	sdkmath "cosmossdk.io/math"

	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// PrecompileAddress is the fixed address of the AMM precompile.
const PrecompileAddress = ammtypes.PrecompileAddress

// Method names.
const (
	QuoteMethod       = "quote"
	GetPoolMethod     = "getPool"
	SwapExactInMethod = "swapExactIn"
)

const abiJSON = `[
  {
    "name": "quote",
    "type": "function",
    "stateMutability": "view",
    "inputs": [
      {"name": "path", "type": "address[]"},
      {"name": "amountIn", "type": "uint256"}
    ],
    "outputs": [{"name": "amountOut", "type": "uint256"}]
  },
  {
    "name": "getPool",
    "type": "function",
    "stateMutability": "view",
    "inputs": [
      {"name": "assetA", "type": "address"},
      {"name": "assetB", "type": "address"}
    ],
    "outputs": [
      {"name": "id", "type": "uint64"},
      {"name": "reserveA", "type": "uint256"},
      {"name": "reserveB", "type": "uint256"},
      {"name": "totalShares", "type": "uint256"},
      {"name": "feeBps", "type": "uint32"}
    ]
  },
  {
    "name": "swapExactIn",
    "type": "function",
    "stateMutability": "nonpayable",
    "inputs": [
      {"name": "path", "type": "address[]"},
      {"name": "amountIn", "type": "uint256"},
      {"name": "minOut", "type": "uint256"},
      {"name": "receiver", "type": "address"},
      {"name": "integrator", "type": "address"},
      {"name": "integratorFeeBps", "type": "uint256"}
    ],
    "outputs": [
      {"name": "amountOut", "type": "uint256"},
      {"name": "integratorFee", "type": "uint256"}
    ]
  }
]`

var (
	// ABI is the parsed AMM precompile ABI.
	ABI abi.ABI
	// Address is the AMM precompile address.
	Address = common.HexToAddress(PrecompileAddress)
)

func init() {
	parsed, err := abi.JSON(bytes.NewReader([]byte(abiJSON)))
	if err != nil {
		panic("failed to parse amm precompile abi: " + err.Error())
	}
	ABI = parsed
}

// Keeper is the module functionality exposed to EVM contracts.
type Keeper interface {
	Quote(ctx sdk.Context, path []string, amountIn sdkmath.Int) (sdkmath.Int, error)
	GetPool(ctx sdk.Context, id uint64) (ammtypes.Pool, bool)
	GetPoolIDByAssets(ctx sdk.Context, assetA, assetB string) (uint64, bool)
	SwapFromPrecompile(
		ctx sdk.Context,
		stateDB *statedb.StateDB,
		caller, receiver common.Address,
		path []string,
		amountIn, minOut sdkmath.Int,
		integrator common.Address,
		integratorFeeBps uint32,
	) (sdkmath.Int, sdkmath.Int, error)
}

var _ vm.PrecompiledContract = &Precompile{}

// Precompile exposes the AMM module to EVM contracts.
type Precompile struct {
	cmn.Precompile
	abi.ABI
	keeper Keeper
}

// NewPrecompile creates a new AMM precompile.
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
func (Precompile) Name() string { return "amm" }

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
func (Precompile) IsTransaction(method *abi.Method) bool {
	return method.Name == SwapExactInMethod
}

// Execute dispatches the ABI method.
func (p Precompile) Execute(ctx sdk.Context, stateDB vm.StateDB, contract *vm.Contract, readOnly bool) ([]byte, error) {
	method, args, err := cmn.SetupABI(p.ABI, contract, readOnly, p.IsTransaction)
	if err != nil {
		return nil, err
	}

	switch method.Name {
	case QuoteMethod:
		return p.quote(ctx, method, args)
	case GetPoolMethod:
		return p.getPool(ctx, method, args)
	case SwapExactInMethod:
		return p.swapExactIn(ctx, stateDB, contract, method, args)
	default:
		return nil, fmt.Errorf(cmn.ErrUnknownMethod, method.Name)
	}
}

func (p Precompile) quote(ctx sdk.Context, method *abi.Method, args []interface{}) ([]byte, error) {
	path, amountIn, err := parsePathAndAmount(args, 0, 1)
	if err != nil {
		return nil, err
	}

	amountOut, err := p.keeper.Quote(ctx, path, sdkmath.NewIntFromBigInt(amountIn))
	if err != nil {
		return nil, err
	}

	return method.Outputs.Pack(amountOut.BigInt())
}

func (p Precompile) getPool(ctx sdk.Context, method *abi.Method, args []interface{}) ([]byte, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("invalid number of arguments: expected 2, got %d", len(args))
	}

	assetA, ok := args[0].(common.Address)
	if !ok {
		return nil, fmt.Errorf("invalid assetA")
	}
	assetB, ok := args[1].(common.Address)
	if !ok {
		return nil, fmt.Errorf("invalid assetB")
	}

	addrA := strings.ToLower(assetA.Hex())
	addrB := strings.ToLower(assetB.Hex())
	if addrA > addrB {
		addrA, addrB = addrB, addrA
	}

	id, found := p.keeper.GetPoolIDByAssets(ctx, addrA, addrB)
	if !found {
		return nil, ammtypes.ErrPoolNotFound.Wrapf("no pool for %s/%s", addrA, addrB)
	}

	pool, found := p.keeper.GetPool(ctx, id)
	if !found {
		return nil, ammtypes.ErrPoolNotFound.Wrapf("pool %d", id)
	}

	return method.Outputs.Pack(
		id, pool.ReserveA.BigInt(), pool.ReserveB.BigInt(), pool.TotalShares.BigInt(), pool.FeeBps,
	)
}

func (p Precompile) swapExactIn(
	ctx sdk.Context,
	stateDB vm.StateDB,
	contract *vm.Contract,
	method *abi.Method,
	args []interface{},
) ([]byte, error) {
	if len(args) != 6 {
		return nil, fmt.Errorf("invalid number of arguments: expected 6, got %d", len(args))
	}

	evmStateDB, ok := stateDB.(*statedb.StateDB)
	if !ok {
		return nil, fmt.Errorf(cmn.ErrNotRunInEvm)
	}

	path, amountIn, err := parsePathAndAmount(args, 0, 1)
	if err != nil {
		return nil, err
	}

	minOut, ok := args[2].(*big.Int)
	if !ok {
		return nil, fmt.Errorf("invalid minOut")
	}

	receiver, ok := args[3].(common.Address)
	if !ok {
		return nil, fmt.Errorf("invalid receiver")
	}
	if receiver == (common.Address{}) {
		receiver = contract.Caller()
	}

	integrator, ok := args[4].(common.Address)
	if !ok {
		return nil, fmt.Errorf("invalid integrator")
	}

	feeBps, ok := args[5].(*big.Int)
	if !ok || !feeBps.IsUint64() {
		return nil, fmt.Errorf("invalid integratorFeeBps")
	}

	amountOut, integratorFee, err := p.keeper.SwapFromPrecompile(
		ctx, evmStateDB, contract.Caller(), receiver, path,
		sdkmath.NewIntFromBigInt(amountIn), sdkmath.NewIntFromBigInt(minOut),
		integrator, uint32(feeBps.Uint64()),
	)
	if err != nil {
		return nil, err
	}

	return method.Outputs.Pack(amountOut.BigInt(), integratorFee.BigInt())
}

// parsePathAndAmount decodes a `(address[] path, uint256 amount)` argument pair.
func parsePathAndAmount(args []interface{}, pathIdx, amountIdx int) ([]string, *big.Int, error) {
	if len(args) <= amountIdx {
		return nil, nil, fmt.Errorf("invalid number of arguments: expected at least %d, got %d", amountIdx+1, len(args))
	}

	addrs, ok := args[pathIdx].([]common.Address)
	if !ok || len(addrs) < 2 {
		return nil, nil, ammtypes.ErrInvalidPath.Wrap("path must contain at least 2 addresses")
	}

	path := make([]string, len(addrs))
	for i, addr := range addrs {
		path[i] = strings.ToLower(addr.Hex())
	}

	amount, ok := args[amountIdx].(*big.Int)
	if !ok {
		return nil, nil, ammtypes.ErrInvalidAmount.Wrap("invalid amount")
	}

	return path, amount, nil
}
