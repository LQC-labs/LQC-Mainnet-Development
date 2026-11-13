// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/LQC-labs/LQC-Mainnet-Development/app"
	"github.com/LQC-labs/LQC-Mainnet-Development/genesis"
	"github.com/cosmos/cosmos-sdk/crypto/keys/ed25519"
	"github.com/cosmos/evm/crypto/ethsecp256k1"
	"github.com/spf13/cobra"
)

// This stage intentionally discards ephemeral signers. It creates a public
// test artifact, not an operational node home. Key custody/start belongs to ④.
func singleValidatorCommand() *cobra.Command {
	command := &cobra.Command{Use: "single-validator", Short: "Isolated signed-gentx TEST Genesis (no node or retained keys)"}
	var home string
	create := &cobra.Command{Use: "create", Args: cobra.NoArgs, Short: "Create a public test Genesis in a NEW isolated home; ephemeral keys are discarded",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !filepath.IsAbs(home) {
				return fmt.Errorf("explicit absolute NEW test --home required")
			}
			// Mkdir refuses every existing path, including symlinks. Never overwrite.
			if err := os.Mkdir(home, 0700); err != nil {
				return err
			}
			return withGenesisApp(func(a *app.App) error {
				account, err := ethsecp256k1.GenerateKey()
				if err != nil {
					return err
				}
				consensus := ed25519.GenPrivKey()
				data, err := genesis.NewSingleValidator(a, account, consensus.PubKey())
				if err != nil {
					return err
				}
				if err = os.Mkdir(filepath.Join(home, "config"), 0700); err != nil {
					return err
				}
				path := filepath.Join(home, "config", "genesis.json")
				file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
				if err != nil {
					return err
				}
				_, writeErr := file.Write(data)
				closeErr := file.Close()
				if writeErr != nil {
					return writeErr
				}
				if closeErr != nil {
					return closeErr
				}
				_, err = fmt.Fprintln(cmd.OutOrStdout(), path)
				return err
			})
		}}
	create.Flags().StringVar(&home, "home", "", "New absolute isolated test home; parent must exist")
	validate := &cobra.Command{Use: "validate <genesis.json>", Args: cobra.ExactArgs(1), Short: "Verify signature and actual InitChain in a disposable in-memory app; no block/commit",
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			return withGenesisApp(func(a *app.App) error {
				if err := genesis.VerifySingleValidatorRuntime(a, data); err != nil {
					return err
				}
				_, err := fmt.Fprintln(cmd.OutOrStdout(), "Single-validator TEST Genesis PASS: signed gentx, one validator, positive power; no block/commit")
				return err
			})
		}}
	command.AddCommand(create, validate)
	return command
}
