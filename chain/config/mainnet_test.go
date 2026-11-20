// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"os"
	"testing"
)

func TestApprovedMainnetRegistry(t *testing.T) {
	chain := MainnetChainConfig()
	if err := ValidateNetworkPair(TestOnlyDevnetConfig().Chain, chain); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../../config/networks.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var entries struct {
		Mainnet struct {
			EVMChainID    uint64   `json:"chainId"`
			CosmosChainID string   `json:"cosmosChainId"`
			NativeDenom   string   `json:"nativeDenom"`
			DisplayDenom  string   `json:"displayDenom"`
			Decimals      uint32   `json:"decimals"`
			Bech32Prefix  string   `json:"bech32Prefix"`
			RPCURLs       []string `json:"rpcUrls"`
		} `json:"lqcMainnet"`
	}
	if err := json.Unmarshal(raw, &entries); err != nil {
		t.Fatal(err)
	}
	m := entries.Mainnet
	if m.EVMChainID != chain.EVMChainID || m.CosmosChainID != chain.CosmosChainID ||
		m.NativeDenom != chain.NativeDenom || m.Bech32Prefix != chain.Bech32Prefix ||
		m.DisplayDenom != MainnetDisplayDenom || m.Decimals != MainnetDecimals {
		t.Fatal("Mainnet registry and approved chain configuration differ")
	}
	if m.RPCURLs == nil || len(m.RPCURLs) != 0 {
		t.Fatal("Mainnet RPC must be an explicit empty list")
	}
}
