// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"fmt"

	"cosmossdk.io/log/v2"
	chainconfig "github.com/LQC-labs/LQC-Mainnet-Development/chain/config"
	dbm "github.com/cosmos/cosmos-db"
)

// NewWithRuntime is the explicit runtime boundary for the existing application.
// Only the pinned test Devnet is wired into the current Cosmos EVM constructor.
// Mainnet is deliberately rejected before database or SDK global initialization;
// a separate fully tested mainnet constructor is required before activation.
func NewWithRuntime(logger log.Logger, db dbm.DB, home string, runtime chainconfig.RuntimeConfig) (*App, error) {
	if err := runtime.Validate(); err != nil {
		return nil, fmt.Errorf("invalid application runtime: %w", err)
	}
	if runtime.Chain.NetworkKind != chainconfig.NetworkDevnet {
		return nil, fmt.Errorf("mainnet application runtime is not yet integrated")
	}
	return New(logger, db, home)
}
