// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

func validDevnet() ChainConfig {
	return ChainConfig{
		NetworkKind:   NetworkDevnet,
		CosmosChainID: "lqc-devnet-test-1",
		EVMChainID:    917001, // Test fixture only; not an adopted network ID.
		Bech32Prefix:  "lqctest",
		NativeDenom:   "atest",
	}
}

func validMainnet() ChainConfig {
	return ChainConfig{
		NetworkKind:   NetworkMainnet,
		CosmosChainID: "lqc-mainnet-test-1",
		EVMChainID:    917002, // Test fixture only; not an adopted network ID.
		Bech32Prefix:  "lqcmain",
		NativeDenom:   "ulqc",
	}
}

func TestChainConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  ChainConfig
		wantErr bool
	}{
		{name: "valid explicit config", config: validDevnet()},
		{name: "zero value requires explicit config", config: ChainConfig{}, wantErr: true},
		{name: "unknown network kind", config: func() ChainConfig { c := validDevnet(); c.NetworkKind = "test"; return c }(), wantErr: true},
		{name: "missing Cosmos chain ID", config: func() ChainConfig { c := validDevnet(); c.CosmosChainID = ""; return c }(), wantErr: true},
		{name: "Cosmos chain ID without revision", config: func() ChainConfig { c := validDevnet(); c.CosmosChainID = "lqc-devnet"; return c }(), wantErr: true},
		{name: "uppercase Cosmos chain ID", config: func() ChainConfig { c := validDevnet(); c.CosmosChainID = "LQC-devnet-1"; return c }(), wantErr: true},
		{name: "double hyphen Cosmos chain ID", config: func() ChainConfig { c := validDevnet(); c.CosmosChainID = "lqc--devnet-1"; return c }(), wantErr: true},
		{name: "zero EVM chain ID", config: func() ChainConfig { c := validDevnet(); c.EVMChainID = 0; return c }(), wantErr: true},
		{name: "BSC mainnet ID forbidden", config: withEVMChainID(56), wantErr: true},
		{name: "BSC testnet ID forbidden", config: withEVMChainID(97), wantErr: true},
		{name: "example ID forbidden", config: withEVMChainID(9001), wantErr: true},
		{name: "missing Bech32 prefix", config: func() ChainConfig { c := validDevnet(); c.Bech32Prefix = ""; return c }(), wantErr: true},
		{name: "uppercase Bech32 prefix", config: func() ChainConfig { c := validDevnet(); c.Bech32Prefix = "Lqc"; return c }(), wantErr: true},
		{name: "Bech32 prefix starts with digit", config: func() ChainConfig { c := validDevnet(); c.Bech32Prefix = "1lqc"; return c }(), wantErr: true},
		{name: "Bech32 maximum length accepted", config: func() ChainConfig {
			c := validDevnet()
			c.Bech32Prefix = "a" + strings.Repeat("1", maxBech32HRPLength-1)
			return c
		}()},
		{name: "Bech32 over maximum rejected", config: func() ChainConfig {
			c := validDevnet()
			c.Bech32Prefix = "a" + strings.Repeat("1", maxBech32HRPLength)
			return c
		}(), wantErr: true},
		{name: "missing native denom", config: func() ChainConfig { c := validDevnet(); c.NativeDenom = ""; return c }(), wantErr: true},
		{name: "native denom too short", config: func() ChainConfig { c := validDevnet(); c.NativeDenom = "ab"; return c }(), wantErr: true},
		{name: "native denom invalid character", config: func() ChainConfig { c := validDevnet(); c.NativeDenom = "at est"; return c }(), wantErr: true},
		{name: "native denom maximum length accepted", config: func() ChainConfig {
			c := validDevnet()
			c.NativeDenom = "a" + strings.Repeat("b", maxDenomLength-1)
			return c
		}()},
		{name: "native denom over maximum rejected", config: func() ChainConfig {
			c := validDevnet()
			c.NativeDenom = "a" + strings.Repeat("b", maxDenomLength)
			return c
		}(), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateNetworkPair(t *testing.T) {
	tests := []struct {
		name    string
		devnet  ChainConfig
		mainnet ChainConfig
		wantErr bool
	}{
		{name: "distinct explicit IDs", devnet: validDevnet(), mainnet: validMainnet()},
		{name: "duplicate Cosmos ID", devnet: validDevnet(), mainnet: func() ChainConfig { c := validMainnet(); c.CosmosChainID = validDevnet().CosmosChainID; return c }(), wantErr: true},
		{name: "duplicate EVM ID", devnet: validDevnet(), mainnet: func() ChainConfig { c := validMainnet(); c.EVMChainID = validDevnet().EVMChainID; return c }(), wantErr: true},
		{name: "wrong first network kind", devnet: validMainnet(), mainnet: validMainnet(), wantErr: true},
		{name: "wrong second network kind", devnet: validDevnet(), mainnet: validDevnet(), wantErr: true},
		{name: "invalid member rejected", devnet: validDevnet(), mainnet: func() ChainConfig { c := validMainnet(); c.NativeDenom = ""; return c }(), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateNetworkPair(tt.devnet, tt.mainnet)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateNetworkPair() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func withEVMChainID(id uint64) ChainConfig {
	c := validDevnet()
	c.EVMChainID = id
	return c
}
