package cmd

import (
	"fmt"
	"path/filepath"

	cmttypes "github.com/cometbft/cometbft/types"
	"github.com/spf13/cobra"

	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/types/module"
	"github.com/cosmos/cosmos-sdk/x/genutil"
	genutilcli "github.com/cosmos/cosmos-sdk/x/genutil/client/cli"
	genutiltypes "github.com/cosmos/cosmos-sdk/x/genutil/types"
)

const (
	// defaultBlockMaxGas is the gas a block may consume.
	defaultBlockMaxGas = 300_000_000
	// defaultBlockMaxBytes caps oversized blocks. With ~330-byte transfers the
	// gas limit is the practical constraint, so this only stops pathological
	// blocks.
	defaultBlockMaxBytes = 3_000_000
)

// initCmd wraps the SDK init command with the block limits Karsa needs. The SDK
// writes CometBFT's defaults, where max_gas is -1; the EVM keeps its own view of
// the block gas limit and reads -1 as zero, so a chain initialized without a
// patched genesis accepts bank transfers but rejects every EVM transaction.
func initCmd(mbm module.BasicManager, defaultNodeHome string) *cobra.Command {
	cmd := genutilcli.InitCmd(mbm, defaultNodeHome)
	runE := cmd.RunE
	cmd.RunE = func(command *cobra.Command, args []string) error {
		if err := runE(command, args); err != nil {
			return err
		}
		return applyBlockLimits(command)
	}
	return cmd
}

func applyBlockLimits(command *cobra.Command) error {
	home, err := command.Flags().GetString(flags.FlagHome)
	if err != nil {
		return err
	}
	return setBlockLimits(filepath.Join(home, "config", "genesis.json"), defaultBlockMaxGas, defaultBlockMaxBytes)
}

// setBlockLimits rewrites the consensus block limits in an existing genesis
// file and leaves the application state untouched.
func setBlockLimits(genFile string, maxGas, maxBytes int64) error {
	appGenesis, err := genutiltypes.AppGenesisFromFile(genFile)
	if err != nil {
		return fmt.Errorf("read genesis %s: %w", genFile, err)
	}
	if appGenesis.Consensus == nil {
		appGenesis.Consensus = &genutiltypes.ConsensusGenesis{}
	}
	if appGenesis.Consensus.Params == nil {
		appGenesis.Consensus.Params = cmttypes.DefaultConsensusParams()
	}
	appGenesis.Consensus.Params.Block.MaxGas = maxGas
	appGenesis.Consensus.Params.Block.MaxBytes = maxBytes
	if err := genutil.ExportGenesisFile(appGenesis, genFile); err != nil {
		return fmt.Errorf("write genesis %s: %w", genFile, err)
	}
	return nil
}
