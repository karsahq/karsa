package main

import (
	"fmt"
	"os"

	svrcmd "github.com/cosmos/cosmos-sdk/server/cmd"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/evm/evmd/cmd/karsad/cmd"
	"github.com/cosmos/evm/evmd/config"
)

func main() {
	setupSDKConfig()

	rootCmd := cmd.NewRootCmd()
	if err := svrcmd.Execute(rootCmd, "karsad", config.MustGetDefaultNodeHome()); err != nil {
		fmt.Fprintln(rootCmd.OutOrStderr(), err)
		os.Exit(1)
	}
}

func setupSDKConfig() {
	cfg := sdk.GetConfig()
	config.SetBech32Prefixes(cfg)
	cfg.Seal()

	// Modules derive their default genesis denom from sdk.DefaultBondDenom, so set
	// it before any module default genesis is generated (e.g. by "karsad init").
	sdk.DefaultBondDenom = config.BaseDenom
}
