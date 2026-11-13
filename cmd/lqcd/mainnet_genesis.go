// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"os"

	"cosmossdk.io/log/v2"
	"github.com/LQC-labs/LQC-Mainnet-Development/app"
	"github.com/LQC-labs/LQC-Mainnet-Development/genesis"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/spf13/cobra"
)

func mainnetGenesisCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "validate-runtime", Short: "Validate explicit Mainnet Genesis inputs offline; never start a node", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) (err error) {
			network, _ := cmd.Flags().GetString("network")
			configPath, _ := cmd.Flags().GetString("config")
			genesisPath, _ := cmd.Flags().GetString("genesis")
			digest, _ := cmd.Flags().GetString("expected-genesis-sha256")
			if network != "mainnet" || configPath == "" || genesisPath == "" || digest == "" {
				return fmt.Errorf("explicit --network mainnet, --config, --genesis and --expected-genesis-sha256 required")
			}
			raw, err := genesis.ReadMainnetInputFile(configPath, genesis.MaxMainnetConfigBytes)
			if err != nil {
				return err
			}
			profile, err := genesis.DecodeMainnetConfig(raw)
			if err != nil {
				return err
			}
			loaded, err := genesis.LoadMainnetFile(genesisPath, profile, digest)
			if err != nil {
				return err
			}
			// Memory DB and a fresh scratch home only; no persistent node home,
			// key generation, InitChain, listener or block execution is involved.
			home, err := os.MkdirTemp("", "lqc-mainnet-genesis-validation-")
			if err != nil {
				return err
			}
			db := dbm.NewMemDB()
			a, err := app.NewWithConfig(log.NewNopLogger(), db, home, profile)
			if err != nil {
				_ = db.Close()
				return err
			}
			defer func() {
				if closeErr := a.Close(); err == nil {
					err = closeErr
				}
			}()
			report, err := genesis.ValidateMainnet(a, loaded)
			if err != nil {
				return err
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(report)
		},
	}
	cmd.Flags().String("network", "", "Explicit mainnet selection")
	cmd.Flags().String("config", "", "Absolute path to explicit runtime JSON")
	cmd.Flags().String("genesis", "", "Absolute path to candidate Genesis JSON")
	cmd.Flags().String("expected-genesis-sha256", "", "Independently supplied lowercase SHA-256")
	return cmd
}
