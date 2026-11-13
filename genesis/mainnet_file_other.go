//go:build !linux

// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0
package genesis

import "fmt"

// Fail closed on unsupported platforms; existing Devnet APIs are unchanged.
func ReadMainnetInputFile(path string, limit int64) ([]byte, error) {
	return nil, fmt.Errorf("secure Mainnet file loading requires Linux")
}
