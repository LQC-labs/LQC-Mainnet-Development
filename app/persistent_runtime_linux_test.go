//go:build linux

// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cosmossdk.io/log/v2"
	chainconfig "github.com/LQC-labs/LQC-Mainnet-Development/chain/config"
)

func TestPersistentRuntimeRejectsUnsupportedIdentityWithoutDiskWrites(t *testing.T) {
	dev := chainconfig.RuntimeFromDevnet(chainconfig.TestOnlyDevnetConfig())
	cases := []struct {
		name string
		runtime chainconfig.RuntimeConfig
	}{
		{name: "alternate cosmos chain", runtime: func() chainconfig.RuntimeConfig {
			r := dev; r.Chain.CosmosChainID = "lqc-other-test-1"; return r
		}()},
		{name: "alternate gas price", runtime: func() chainconfig.RuntimeConfig {
			r := dev; r.MinimumGasPrice = "0.02" + r.Chain.NativeDenom; return r
		}()},
		{name: "reserved evm id", runtime: func() chainconfig.RuntimeConfig {
			r := dev; r.Chain.EVMChainID = 56; return r
		}()},
		{name: "mainnet", runtime: chainconfig.RuntimeConfig{
			Chain: chainconfig.ChainConfig{
				NetworkKind: chainconfig.NetworkMainnet,
				CosmosChainID: "lqc-persistent-fixture-1",
				EVMChainID: 423456783,
				Bech32Prefix: "lqcfixture",
				NativeDenom: "afixture",
			},
			MinimumGasPrice: "0.01afixture",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := filepath.Join(t.TempDir(), "not-created")
			a, err := OpenPersistentWithRuntime(log.NewNopLogger(), home, tc.runtime)
			if a != nil || err == nil {
				t.Fatalf("unsupported runtime accepted: app=%v err=%v", a, err)
			}
			if _, err := os.Stat(home); !os.IsNotExist(err) {
				t.Fatalf("persistent home touched on rejection: %v", err)
			}
		})
	}
	// A supported identity reaches the existing path-security preflight.
	// A nonexistent home must still be rejected without creating it.
	home := filepath.Join(t.TempDir(), "not-created")
	a, err := OpenPersistentWithRuntime(log.NewNopLogger(), home, dev)
	if a != nil || err == nil || !strings.Contains(err.Error(), "no such file") {
		t.Fatalf("expected existing path preflight: app=%v err=%v", a, err)
	}
	if _, err := os.Stat(home); !os.IsNotExist(err) {
		t.Fatalf("home unexpectedly created: %v", err)
	}
}
