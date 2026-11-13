// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

package config

import "fmt"

const (
	testDevnetCosmosChainID = "lqc-devnet-test-1"
	testDevnetEVMChainID    = uint64(917001)
	testDevnetBech32Prefix  = "lqctest"
	testDevnetNativeDenom   = "atest"
	testDevnetMinGasPrice   = "0atest"
)

// DevnetConfig contains an isolated TEST-only profile. These values are test
// fixtures, not adopted or production network parameters. This profile is not
// connected to any BSC address, RPC endpoint, wallet, or real asset.
type DevnetConfig struct {
	Chain           ChainConfig
	MinimumGasPrice string
}

// TestOnlyDevnetConfig returns a deterministic TEST-only configuration for
// validation and local development. It must not be used as a production config.
func TestOnlyDevnetConfig() DevnetConfig {
	return DevnetConfig{
		Chain: ChainConfig{
			NetworkKind:   NetworkDevnet,
			CosmosChainID: testDevnetCosmosChainID,
			EVMChainID:    testDevnetEVMChainID,
			Bech32Prefix:  testDevnetBech32Prefix,
			NativeDenom:   testDevnetNativeDenom,
		},
		MinimumGasPrice: testDevnetMinGasPrice,
	}
}

// Validate rejects values outside the deliberately narrow TEST-only profile.
func (d DevnetConfig) Validate() error {
	if d.Chain.NetworkKind != NetworkDevnet {
		return fmt.Errorf("test devnet profile requires network kind %q", NetworkDevnet)
	}
	if err := d.Chain.Validate(); err != nil {
		return fmt.Errorf("invalid test devnet chain config: %w", err)
	}
	if d.Chain.NativeDenom != testDevnetNativeDenom {
		return fmt.Errorf("test devnet native denomination must be %q", testDevnetNativeDenom)
	}
	if d.Chain.CosmosChainID != testDevnetCosmosChainID {
		return fmt.Errorf("test devnet Cosmos chain ID must be %q", testDevnetCosmosChainID)
	}
	if d.Chain.EVMChainID != testDevnetEVMChainID {
		return fmt.Errorf("test devnet EVM chain ID must be %d", testDevnetEVMChainID)
	}
	if d.Chain.Bech32Prefix != testDevnetBech32Prefix {
		return fmt.Errorf("test devnet Bech32 prefix must be %q", testDevnetBech32Prefix)
	}
	if d.MinimumGasPrice != testDevnetMinGasPrice {
		return fmt.Errorf("test devnet minimum gas price must be %q", testDevnetMinGasPrice)
	}
	return nil
}
