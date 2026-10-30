package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/cosmos/cosmos-sdk/server"
	"github.com/cosmos/cosmos-sdk/x/genutil"
	genutilcli "github.com/cosmos/cosmos-sdk/x/genutil/client/cli"
	genutiltypes "github.com/cosmos/cosmos-sdk/x/genutil/types"

	karsa "github.com/karsahq/karsa"
)

// NewInitCmd wraps the SDK init command so the genesis is built from
// App.DefaultGenesis instead of the per-module defaults.
//
// The module defaults omit everything the app layers on top: the active static
// precompile list (AMM, token factory, minter, bank, staking, ICS20, …) and the
// genesis token pairs. A chain initialised from module defaults therefore starts
// with no working precompile at all, and nothing reports it.
func NewInitCmd(app *karsa.App, defaultNodeHome string) *cobra.Command {
	cmd := genutilcli.InitCmd(app.BasicModuleManager, defaultNodeHome)
	sdkRunE := cmd.RunE

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if err := sdkRunE(cmd, args); err != nil {
			return err
		}

		return replaceAppState(cmd, app)
	}

	return cmd
}

// replaceAppState rewrites only the app_state of the genesis file created by the
// SDK command, leaving the chain id, consensus params and initial height alone.
func replaceAppState(cmd *cobra.Command, app *karsa.App) error {
	serverCtx := server.GetServerContextFromCmd(cmd)
	genFile := serverCtx.Config.GenesisFile()

	appGenesis, err := genutiltypes.AppGenesisFromFile(genFile)
	if err != nil {
		return fmt.Errorf("read genesis: %w", err)
	}

	appState, err := json.MarshalIndent(app.DefaultGenesis(), "", " ")
	if err != nil {
		return fmt.Errorf("marshal default genesis: %w", err)
	}
	appGenesis.AppState = appState

	if err := genutil.ExportGenesisFile(appGenesis, genFile); err != nil {
		return fmt.Errorf("export genesis: %w", err)
	}

	return nil
}
