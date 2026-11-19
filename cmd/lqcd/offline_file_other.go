// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package main

import (
	"fmt"
	"os"
)

// Offline mainnet draft inputs require Linux openat2 no-symlink enforcement.
func openOfflineDraftFile(path string) (*os.File, error) {
	return nil, fmt.Errorf("offline mainnet draft file opening requires Linux")
}
