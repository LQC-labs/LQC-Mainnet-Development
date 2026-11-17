// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"strings"
	"testing"

	"cosmossdk.io/log/v2"
	chainconfig "github.com/LQC-labs/LQC-Mainnet-Development/chain/config"
	dbm "github.com/cosmos/cosmos-db"
)

func TestRuntimeApplicationBoundary(t *testing.T) {
	dev := chainconfig.RuntimeFromDevnet(chainconfig.TestOnlyDevnetConfig())
	application, err := NewWithRuntime(log.NewNopLogger(), dbm.NewMemDB(), t.TempDir(), dev)
	if err != nil { t.Fatal(err) }
	if application.SDK.ChainID() != dev.Chain.CosmosChainID { t.Fatal("Devnet chain ID changed") }
	if err := application.Close(); err != nil { t.Fatal(err) }

	mainnet := chainconfig.RuntimeConfig{
		Chain: chainconfig.ChainConfig{
			NetworkKind: chainconfig.NetworkMainnet,
			CosmosChainID: "lqc-runtime-fixture-1",
			EVMChainID: 423456783,
			Bech32Prefix: "lqcfixture",
			NativeDenom: "afixture",
		},
		MinimumGasPrice: "0.01afixture",
	}
	if err := mainnet.Validate(); err != nil { t.Fatalf("invalid fixture: %v", err) }
	if app, err := NewWithRuntime(log.NewNopLogger(), dbm.NewMemDB(), t.TempDir(), mainnet); app != nil || err == nil || !strings.Contains(err.Error(), "not yet integrated") {
		t.Fatalf("mainnet unexpectedly constructed: app=%v err=%v", app, err)
	}
	invalid := dev
	invalid.Chain.EVMChainID = 56
	if app, err := NewWithRuntime(log.NewNopLogger(), dbm.NewMemDB(), t.TempDir(), invalid); app != nil || err == nil {
		t.Fatalf("reserved EVM ID accepted: app=%v err=%v", app, err)
	}
}
