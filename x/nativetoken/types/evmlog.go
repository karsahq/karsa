package types

import (
	"bytes"
	"fmt"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"

	sdkmath "cosmossdk.io/math"
)

// evmEventsJSON covers the events emitted by the factory and minter precompiles.
// They exist so an EVM explorer can show token creation and supply changes
// without reading Cosmos events, which an EVM-only indexer never sees.
const evmEventsJSON = `[
  {
    "name": "TokenCreated",
    "type": "event",
    "inputs": [
      {"name": "token", "type": "address", "indexed": true},
      {"name": "creator", "type": "address", "indexed": true},
      {"name": "symbol", "type": "string", "indexed": false}
    ]
  },
  {
    "name": "Mint",
    "type": "event",
    "inputs": [
      {"name": "token", "type": "address", "indexed": true},
      {"name": "to", "type": "address", "indexed": true},
      {"name": "amount", "type": "uint256", "indexed": false}
    ]
  },
  {
    "name": "Burn",
    "type": "event",
    "inputs": [
      {"name": "token", "type": "address", "indexed": true},
      {"name": "from", "type": "address", "indexed": true},
      {"name": "amount", "type": "uint256", "indexed": false}
    ]
  }
]`

var (
	tokenCreatedEvent abi.Event
	mintEvent         abi.Event
	burnEvent         abi.Event
)

func init() {
	parsed, err := abi.JSON(bytes.NewReader([]byte(evmEventsJSON)))
	if err != nil {
		panic("failed to parse nativetoken evm events: " + err.Error())
	}

	tokenCreatedEvent = parsed.Events["TokenCreated"]
	mintEvent = parsed.Events["Mint"]
	burnEvent = parsed.Events["Burn"]
}

// TokenCreatedEventID is the topic of TokenCreated.
func TokenCreatedEventID() common.Hash { return tokenCreatedEvent.ID }

// MintEventID is the topic of Mint.
func MintEventID() common.Hash { return mintEvent.ID }

// BurnEventID is the topic of Burn.
func BurnEventID() common.Hash { return burnEvent.ID }

// EmitTokenCreated logs a token creation from the factory precompile.
func EmitTokenCreated(
	stateDB vm.StateDB, emitter, token, creator common.Address, symbol string,
) error {
	data, err := tokenCreatedEvent.Inputs.NonIndexed().Pack(symbol)
	if err != nil {
		return fmt.Errorf("pack token created log: %w", err)
	}

	stateDB.AddLog(&ethtypes.Log{
		Address: emitter,
		Topics: []common.Hash{
			tokenCreatedEvent.ID,
			common.BytesToHash(common.LeftPadBytes(token.Bytes(), 32)),
			common.BytesToHash(common.LeftPadBytes(creator.Bytes(), 32)),
		},
		Data: data,
	})

	return nil
}

// EmitMint logs a mint from the minter precompile.
func EmitMint(
	stateDB vm.StateDB, emitter, token, to common.Address, amount sdkmath.Int,
) error {
	data, err := mintEvent.Inputs.NonIndexed().Pack(amount.BigInt())
	if err != nil {
		return fmt.Errorf("pack mint log: %w", err)
	}

	stateDB.AddLog(&ethtypes.Log{
		Address: emitter,
		Topics: []common.Hash{
			mintEvent.ID,
			common.BytesToHash(common.LeftPadBytes(token.Bytes(), 32)),
			common.BytesToHash(common.LeftPadBytes(to.Bytes(), 32)),
		},
		Data: data,
	})

	return nil
}

// EmitBurn logs a burn from the minter precompile.
func EmitBurn(
	stateDB vm.StateDB, emitter, token, from common.Address, amount sdkmath.Int,
) error {
	data, err := burnEvent.Inputs.NonIndexed().Pack(amount.BigInt())
	if err != nil {
		return fmt.Errorf("pack burn log: %w", err)
	}

	stateDB.AddLog(&ethtypes.Log{
		Address: emitter,
		Topics: []common.Hash{
			burnEvent.ID,
			common.BytesToHash(common.LeftPadBytes(token.Bytes(), 32)),
			common.BytesToHash(common.LeftPadBytes(from.Bytes(), 32)),
		},
		Data: data,
	})

	return nil
}
