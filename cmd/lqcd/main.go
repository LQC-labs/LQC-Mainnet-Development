// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"

	"github.com/LQC-labs/LQC-Mainnet-Development/app"
	"github.com/spf13/cobra"
)

func newRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:           "lqcd",
		Short:         "LQC test Devnet application CLI (Core 2/2-1)",
		Long:          "LQC Cosmos SDK / Cosmos EVM application CLI. Genesis and node startup are not available in this stage.",
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
	return root
}

func main() {
	if err := newRootCommand().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
