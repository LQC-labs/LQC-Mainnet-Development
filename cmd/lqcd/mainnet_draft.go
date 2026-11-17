// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"os"

	chainconfig "github.com/LQC-labs/LQC-Mainnet-Development/chain/config"
	"github.com/LQC-labs/LQC-Mainnet-Development/genesis"
	"github.com/spf13/cobra"
)

// This command only reads two offline proposals. It never starts an app,
// initializes a node, creates validator keys, or approves activation.
func mainnetDraftValidationCommand() *cobra.Command {
	return &cobra.Command{
		Use: "validate-mainnet-draft <profile.json> <genesis.json>",
		Short: "Offline mainnet Genesis draft preflight (not activation approval)",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			profileData, err := os.ReadFile(args[0])
			if err != nil { return fmt.Errorf("read profile: %w", err) }
			if err := genesis.ValidateMainnetProfile(profileData); err != nil {
				return fmt.Errorf("invalid mainnet profile: %w", err)
			}
			var profile genesis.MainnetProfile
			if err := json.Unmarshal(profileData, &profile); err != nil { return err }
			if profile.Chain.Chain.NetworkKind != chainconfig.NetworkMainnet {
				return fmt.Errorf("mainnet profile required")
			}
			draftData, err := os.ReadFile(args[1])
			if err != nil { return fmt.Errorf("read draft: %w", err) }
			if err := genesis.ValidateMainnetDraft(profile.Chain, draftData); err != nil {
				return fmt.Errorf("invalid mainnet draft: %w", err)
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), "LQC offline mainnet draft preflight valid; NOT SDK module validation or launch approval")
			return err
		},
	}
}
