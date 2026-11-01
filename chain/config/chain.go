// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

// Package config defines explicit, validated LQC chain configuration.
package config

import (
	"fmt"
	"regexp"
	"strings"
)

// NetworkKind identifies a configuration's intended network. It does not
// imply that either network has been launched.
type NetworkKind string

const (
	NetworkDevnet  NetworkKind = "devnet"
	NetworkMainnet NetworkKind = "mainnet"
)

const (
	bscMainnetChainID  = uint64(56)
	bscTestnetChainID  = uint64(97)
	exampleChainID     = uint64(9001)
	maxBech32HRPLength = 83
	maxDenomLength     = 128
)

var (
	cosmosChainIDPattern = regexp.MustCompile("^[a-z0-9][a-z0-9-]*-[0-9]+$")
	bech32HRPPattern     = regexp.MustCompile("^[a-z][a-z0-9]*$")
	nativeDenomPattern   = regexp.MustCompile("^[a-zA-Z][a-zA-Z0-9/:._-]*$")
)

// ChainConfig keeps the Cosmos chain identifier and EVM chain identifier
// separate. All fields are intentionally explicit; this package supplies no
// production chain IDs, address prefixes, or denomination defaults.
type ChainConfig struct {
	NetworkKind   NetworkKind
	CosmosChainID string
	EVMChainID    uint64
	Bech32Prefix  string
	NativeDenom   string
}

// Validate checks one configuration's required values and basic formats.
func (c ChainConfig) Validate() error {
	if c.NetworkKind != NetworkDevnet && c.NetworkKind != NetworkMainnet {
		return fmt.Errorf("network kind must be %q or %q", NetworkDevnet, NetworkMainnet)
	}

	if c.CosmosChainID == "" {
		return fmt.Errorf("cosmos chain ID is required")
	}
	if !cosmosChainIDPattern.MatchString(c.CosmosChainID) || strings.Contains(c.CosmosChainID, "--") {
		return fmt.Errorf("cosmos chain ID must use lowercase letters, digits, hyphens, and a numeric revision suffix")
	}

	if c.EVMChainID == 0 {
		return fmt.Errorf("EVM chain ID must be non-zero")
	}
	if c.EVMChainID == bscMainnetChainID || c.EVMChainID == bscTestnetChainID || c.EVMChainID == exampleChainID {
		return fmt.Errorf("EVM chain ID %d is reserved by this project policy", c.EVMChainID)
	}

	if len(c.Bech32Prefix) == 0 || len(c.Bech32Prefix) > maxBech32HRPLength || !bech32HRPPattern.MatchString(c.Bech32Prefix) {
		return fmt.Errorf("Bech32 prefix must be 1-%d lowercase ASCII letters or digits and start with a letter", maxBech32HRPLength)
	}

	if len(c.NativeDenom) < 3 || len(c.NativeDenom) > maxDenomLength || !nativeDenomPattern.MatchString(c.NativeDenom) {
		return fmt.Errorf("native denomination must be 3-%d characters, start with a letter, and use only letters, digits, /, :, ., _, or -", maxDenomLength)
	}

	return nil
}

// ValidateNetworkPair validates explicit Devnet and Mainnet configurations
// and prevents either identifier from being reused across the pair.
func ValidateNetworkPair(devnet, mainnet ChainConfig) error {
	if devnet.NetworkKind != NetworkDevnet {
		return fmt.Errorf("first configuration must be %q", NetworkDevnet)
	}
	if mainnet.NetworkKind != NetworkMainnet {
		return fmt.Errorf("second configuration must be %q", NetworkMainnet)
	}
	if err := devnet.Validate(); err != nil {
		return fmt.Errorf("invalid Devnet configuration: %w", err)
	}
	if err := mainnet.Validate(); err != nil {
		return fmt.Errorf("invalid Mainnet configuration: %w", err)
	}
	if devnet.CosmosChainID == mainnet.CosmosChainID {
		return fmt.Errorf("Devnet and Mainnet Cosmos chain IDs must differ")
	}
	if devnet.EVMChainID == mainnet.EVMChainID {
		return fmt.Errorf("Devnet and Mainnet EVM chain IDs must differ")
	}
	return nil
}
