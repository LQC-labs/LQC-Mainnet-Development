// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

func TestTestOnlyDevnetConfig(t *testing.T) {
	cfg := TestOnlyDevnetConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("TestOnlyDevnetConfig().Validate() error = %v", err)
	}
	if cfg.Chain.CosmosChainID != "lqc-devnet-test-1" {
		t.Fatalf("unexpected TEST-only Cosmos chain ID: %q", cfg.Chain.CosmosChainID)
	}
	if cfg.Chain.EVMChainID != 917001 {
		t.Fatalf("unexpected TEST-only EVM chain ID: %d", cfg.Chain.EVMChainID)
	}
	if cfg.Chain.NativeDenom != "atest" || cfg.MinimumGasPrice != "0atest" {
		t.Fatalf("TEST-only token/gas settings were not preserved")
	}
}

func TestTestOnlyDevnetConfigRejectsBSCAndExampleIDs(t *testing.T) {
	for _, id := range []uint64{56, 97, 9001} {
		cfg := TestOnlyDevnetConfig()
		cfg.Chain.EVMChainID = id
		if err := cfg.Validate(); err == nil {
			t.Errorf("Validate() accepted reserved EVM chain ID %d", id)
		}
	}
}

func TestDevnetConfigRejectsProductionLikeOverrides(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*DevnetConfig)
	}{
		{name: "mainnet kind", mutate: func(c *DevnetConfig) { c.Chain.NetworkKind = NetworkMainnet }},
		{name: "non-test denom", mutate: func(c *DevnetConfig) { c.Chain.NativeDenom = "ulqc" }},
		{name: "non-test gas price", mutate: func(c *DevnetConfig) { c.MinimumGasPrice = "1ulqc" }},
		{name: "zero EVM ID", mutate: func(c *DevnetConfig) { c.Chain.EVMChainID = 0 }},
		{name: "different valid Cosmos ID", mutate: func(c *DevnetConfig) { c.Chain.CosmosChainID = "other-devnet-1" }},
		{name: "different valid EVM ID", mutate: func(c *DevnetConfig) { c.Chain.EVMChainID = 917002 }},
		{name: "different valid Bech32 prefix", mutate: func(c *DevnetConfig) { c.Chain.Bech32Prefix = "other" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := TestOnlyDevnetConfig()
			tt.mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("Validate() unexpectedly accepted override")
			}
		})
	}
}
