package types

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"

	sdkmath "cosmossdk.io/math"
)

// swapEventJSON is the EVM event emitted once per hop when a swap comes through
// the precompile. Fees are not included: they are reported by the Cosmos event,
// and computing them per hop would duplicate the curve math.
const swapEventJSON = `[
  {
    "name": "Swap",
    "type": "event",
    "inputs": [
      {"name": "sender", "type": "address", "indexed": true},
      {"name": "poolId", "type": "uint64", "indexed": true},
      {"name": "tokenIn", "type": "address", "indexed": true},
      {"name": "amountIn", "type": "uint256", "indexed": false},
      {"name": "tokenOut", "type": "address", "indexed": false},
      {"name": "amountOut", "type": "uint256", "indexed": false}
    ]
  }
]`

// swapEvent is the parsed Swap event.
var swapEvent abi.Event

func init() {
	parsed, err := abi.JSON(bytes.NewReader([]byte(swapEventJSON)))
	if err != nil {
		panic("failed to parse amm evm events: " + err.Error())
	}

	event, ok := parsed.Events["Swap"]
	if !ok {
		panic("amm evm events are missing Swap")
	}
	swapEvent = event
}

// SwapEventID is the topic of the Swap event, useful for indexers.
func SwapEventID() common.Hash { return swapEvent.ID }

// EmitSwapLog appends the EVM log for one swap hop.
//
// Only the EVM path emits this: a swap sent as a Cosmos message has no EVM
// receipt to attach a log to, and its data is in the Cosmos events instead.
func EmitSwapLog(
	stateDB vm.StateDB,
	sender common.Address,
	poolID uint64,
	tokenIn common.Address,
	amountIn sdkmath.Int,
	tokenOut common.Address,
	amountOut sdkmath.Int,
) error {
	data, err := swapEvent.Inputs.NonIndexed().Pack(amountIn.BigInt(), tokenOut, amountOut.BigInt())
	if err != nil {
		return fmt.Errorf("pack swap log: %w", err)
	}

	topics := []common.Hash{
		swapEvent.ID,
		common.BytesToHash(common.LeftPadBytes(sender.Bytes(), 32)),
		common.BigToHash(new(big.Int).SetUint64(poolID)),
		common.BytesToHash(common.LeftPadBytes(tokenIn.Bytes(), 32)),
	}

	stateDB.AddLog(&ethtypes.Log{
		Address: common.HexToAddress(PrecompileAddress),
		Topics:  topics,
		Data:    data,
	})

	return nil
}
