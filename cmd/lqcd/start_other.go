//go:build !linux

// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"fmt"
	"github.com/spf13/cobra"
)

func startCommand() *cobra.Command {
	return &cobra.Command{Use: "start", RunE: func(*cobra.Command, []string) error { return fmt.Errorf("isolated local node runtime requires Linux") }}
}
