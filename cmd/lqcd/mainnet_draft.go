// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"

	"github.com/LQC-labs/LQC-Mainnet-Development/app"
	"github.com/LQC-labs/LQC-Mainnet-Development/genesis"
	"github.com/spf13/cobra"
)

func mainnetDraftCommand() *cobra.Command {
	draft := &cobra.Command{Use: "mainnet-draft", Short: "Offline tools for an unfunded, validator-free Mainnet draft"}
	draft.AddCommand(&cobra.Command{
		Use: "create", Short: "Write a Mainnet Genesis draft to stdout", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return withOfflineGenesisApp(app.NewMainnetDraft, func(a *app.App) error {
				data, err := genesis.NewMainnetDraft(a)
				if err != nil {
					return err
				}
				_, err = cmd.OutOrStdout().Write(data)
				return err
			})
		},
	}, &cobra.Command{
		Use: "validate <file>", Short: "Validate Mainnet draft identities and denominations offline", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			return withOfflineGenesisApp(app.NewMainnetDraft, func(a *app.App) error {
				if err := genesis.ValidateMainnetDraft(a, data); err != nil {
					return err
				}
				_, err := fmt.Fprintln(cmd.OutOrStdout(), "LQC Mainnet Genesis draft valid (unfunded, no validators)")
				return err
			})
		},
	})
	return draft
}
