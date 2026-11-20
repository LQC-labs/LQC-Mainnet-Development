// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

package config

const (
	MainnetDisplayDenom = "LQC"
	MainnetDecimals     = 18
)

// MainnetChainConfig returns the approved development identity. Deployment
// settings and public RPC endpoints are supplied separately.
func MainnetChainConfig() ChainConfig {
	return ChainConfig{
		NetworkKind:   NetworkMainnet,
		CosmosChainID: "lqc-1",
		EVMChainID:    768167,
		Bech32Prefix:  "lqc",
		NativeDenom:   "alqc",
	}
}

// RuntimeConfig holds the application profile. Devnet's JSON shape is retained.
type RuntimeConfig struct {
	Chain           ChainConfig
	MinimumGasPrice string
}

func (r RuntimeConfig) AsTestDevnet() (DevnetConfig, error) {
	d := DevnetConfig{Chain: r.Chain, MinimumGasPrice: r.MinimumGasPrice}
	return d, d.Validate()
}
