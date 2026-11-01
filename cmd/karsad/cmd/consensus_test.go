package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	cmttypes "github.com/cometbft/cometbft/types"

	genutiltypes "github.com/cosmos/cosmos-sdk/x/genutil/types"
)

func TestSetBlockLimits(t *testing.T) {
	cases := []struct {
		name          string
		withConsensus bool
	}{
		{name: "replaces the SDK defaults", withConsensus: true},
		{name: "fills in a missing consensus section"},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			genFile := filepath.Join(t.TempDir(), "genesis.json")
			writeTestGenesis(t, genFile, test.withConsensus)

			if err := setBlockLimits(genFile, defaultBlockMaxGas, defaultBlockMaxBytes); err != nil {
				t.Fatalf("setBlockLimits: %v", err)
			}

			got, err := genutiltypes.AppGenesisFromFile(genFile)
			if err != nil {
				t.Fatalf("read genesis: %v", err)
			}
			if got.Consensus == nil || got.Consensus.Params == nil {
				t.Fatal("consensus params missing after the update")
			}
			if got.Consensus.Params.Block.MaxGas != defaultBlockMaxGas {
				t.Fatalf("max_gas = %d, want %d", got.Consensus.Params.Block.MaxGas, defaultBlockMaxGas)
			}
			if got.Consensus.Params.Block.MaxBytes != defaultBlockMaxBytes {
				t.Fatalf("max_bytes = %d, want %d", got.Consensus.Params.Block.MaxBytes, defaultBlockMaxBytes)
			}

			var appState map[string]map[string]any
			if err := json.Unmarshal(got.AppState, &appState); err != nil {
				t.Fatalf("decode app state: %v", err)
			}
			params, _ := appState["evm"]["params"].(map[string]any)
			if params["evm_denom"] != "akra" {
				t.Fatalf("app state changed, evm denom is %v", params["evm_denom"])
			}
		})
	}
}

func TestSetBlockLimitsRejectsMissingFile(t *testing.T) {
	err := setBlockLimits(filepath.Join(t.TempDir(), "missing.json"), defaultBlockMaxGas, defaultBlockMaxBytes)
	if err == nil {
		t.Fatal("expected an error for a missing genesis file")
	}
}

func writeTestGenesis(t *testing.T, path string, withConsensus bool) {
	t.Helper()
	doc := map[string]any{
		"app_name":       "karsad",
		"chain_id":       "karsa_262144-1",
		"initial_height": "1",
		"app_state":      json.RawMessage(`{"evm":{"params":{"evm_denom":"akra"}}}`),
	}
	if withConsensus {
		doc["consensus"] = map[string]any{"params": cmttypes.DefaultConsensusParams()}
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("encode genesis: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write genesis: %v", err)
	}
}
