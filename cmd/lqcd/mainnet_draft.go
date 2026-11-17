// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	chainconfig "github.com/LQC-labs/LQC-Mainnet-Development/chain/config"
	"github.com/LQC-labs/LQC-Mainnet-Development/genesis"
	"github.com/spf13/cobra"
)

const maxOfflineDraftBytes int64 = 8 << 20

// readBoundedOfflineFile rejects oversized inputs before JSON decoding.
// A regular file or pipe cannot consume unbounded memory.
func readBoundedOfflineFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil { return nil, err }
	defer f.Close()
	info, err := f.Stat()
	if err != nil { return nil, err }
	if !info.Mode().IsRegular() { return nil, fmt.Errorf("offline input must be a regular file") }
	if info.Size() > maxOfflineDraftBytes { return nil, fmt.Errorf("offline input exceeds 8 MiB") }
	data, err := io.ReadAll(io.LimitReader(f, maxOfflineDraftBytes+1))
	if err != nil { return nil, err }
	if int64(len(data)) > maxOfflineDraftBytes { return nil, fmt.Errorf("offline input exceeds 8 MiB") }
	return data, nil
}

// This command only reads two offline proposals. It never starts an app,
// initializes a node, creates validator keys, or approves activation.
func mainnetDraftValidationCommand() *cobra.Command {
	return &cobra.Command{
		Use: "validate-mainnet-draft <profile.json> <genesis.json>",
		Short: "Offline mainnet Genesis draft preflight (not activation approval)",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			profileData, err := readBoundedOfflineFile(args[0])
			if err != nil { return fmt.Errorf("read profile: %w", err) }
			if err := genesis.ValidateMainnetProfile(profileData); err != nil {
				return fmt.Errorf("invalid mainnet profile: %w", err)
			}
			var profile genesis.MainnetProfile
			if err := json.Unmarshal(profileData, &profile); err != nil { return err }
			if profile.Chain.Chain.NetworkKind != chainconfig.NetworkMainnet {
				return fmt.Errorf("mainnet profile required")
			}
			draftData, err := readBoundedOfflineFile(args[1])
			if err != nil { return fmt.Errorf("read draft: %w", err) }
			if err := genesis.ValidateMainnetDraft(profile.Chain, draftData); err != nil {
				return fmt.Errorf("invalid mainnet draft: %w", err)
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), "LQC offline mainnet draft preflight valid; NOT SDK module validation or launch approval")
			return err
		},
	}
}
