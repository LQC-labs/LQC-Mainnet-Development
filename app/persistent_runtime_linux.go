//go:build linux

// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"fmt"
	"reflect"

	"cosmossdk.io/log/v2"
	chainconfig "github.com/LQC-labs/LQC-Mainnet-Development/chain/config"
)

// OpenPersistentWithRuntime rejects unsupported chain identities before
// touching the home directory, chain database, or Cosmos SDK global state.
// It does not enable mainnet startup or create any validator material.
func OpenPersistentWithRuntime(logger log.Logger, home string, runtime chainconfig.RuntimeConfig) (*App, error) {
	if err := runtime.Validate(); err != nil {
		return nil, fmt.Errorf("invalid persistent runtime: %w", err)
	}
	if runtime.Chain.NetworkKind != chainconfig.NetworkDevnet {
		return nil, fmt.Errorf("mainnet persistent runtime is not yet integrated")
	}
	pinned := chainconfig.RuntimeFromDevnet(chainconfig.TestOnlyDevnetConfig())
	if !reflect.DeepEqual(runtime, pinned) {
		return nil, fmt.Errorf("persistent runtime does not match pinned test Devnet identity")
	}
	return OpenPersistent(logger, home)
}
