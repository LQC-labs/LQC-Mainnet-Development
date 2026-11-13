// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"cosmossdk.io/log/v2"
	"github.com/LQC-labs/LQC-Mainnet-Development/app"
	"github.com/LQC-labs/LQC-Mainnet-Development/genesis"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/spf13/cobra"
)

func newRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:           "lqcd",
		Short:         "LQC application, Genesis validation and local test node CLI",
		Long:          "LQC CLI for Genesis validation and explicitly acknowledged isolated loopback test networks. Public Mainnet runtime is unavailable.",
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE:          func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	root.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the LQC application version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "lqcd %s\n", app.Version)
			return err
		},
	})
	initCmd := &cobra.Command{
		Use: "init", Short: "Create a new unfunded test Devnet genesis.json (never overwrite)", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			home, _ := cmd.Flags().GetString("home")
			if home == "" {
				return fmt.Errorf("explicit --home is required")
			}
			chainID, _ := cmd.Flags().GetString("chain-id")
			if chainID != "lqc-devnet-test-1" {
				return fmt.Errorf("only lqc-devnet-test-1 is supported")
			}
			// Refuse existing Genesis before constructing the application.
			if _, err := os.Lstat(filepath.Join(home, "config", "genesis.json")); err == nil {
				return fmt.Errorf("genesis.json already exists")
			} else if !os.IsNotExist(err) {
				return err
			}
			return withGenesisApp(func(a *app.App) error {
				path, err := genesis.Init(a, home)
				if err == nil {
					_, err = fmt.Fprintln(cmd.OutOrStdout(), path)
				}
				return err
			})
		},
	}
	initCmd.Flags().String("home", "", "Explicit isolated test home")
	initCmd.Flags().String("chain-id", "lqc-devnet-test-1", "Fixed test Cosmos chain ID")
	genesisCmd := &cobra.Command{Use: "genesis", Short: "Offline Devnet and Mainnet Genesis tools"}
	genesisCmd.AddCommand(&cobra.Command{
		Use: "validate <file>", Short: "Validate an unfunded Genesis draft without modifying it", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			return withGenesisApp(func(a *app.App) error {
				if err := genesis.Validate(a, data); err != nil {
					return err
				}
				_, err := fmt.Fprintln(cmd.OutOrStdout(), "LQC test Devnet Genesis draft valid (no validators or funding)")
				return err
			})
		},
	})
	genesisCmd.AddCommand(mainnetGenesisCommand())
	root.AddCommand(initCmd, genesisCmd, singleValidatorCommand(), startCommand())
	return root
}

func withGenesisApp(run func(*app.App) error) (err error) {
	home, err := os.MkdirTemp("", "lqc-genesis-app-")
	if err != nil {
		return err
	}
	db := dbm.NewMemDB()
	a, err := app.New(log.NewNopLogger(), db, home)
	if err != nil {
		_ = db.Close()
		return err
	}
	defer func() {
		if closeErr := a.Close(); err == nil {
			err = closeErr
		}
	}()
	return run(a)
}

func main() {
	if err := newRootCommand().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
