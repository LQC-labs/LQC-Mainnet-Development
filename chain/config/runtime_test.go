// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"encoding/json"
	"testing"
)

// Synthetic offline fixtures only; these values are not LQC mainnet parameters.
func runtimeFixture() RuntimeConfig {
	return RuntimeConfig{Chain: ChainConfig{NetworkKind: NetworkMainnet, CosmosChainID: "runtime-fixture-1", EVMChainID: 423456781, Bech32Prefix: "runtest", NativeDenom: "arfixture"}, MinimumGasPrice: "0.01arfixture"}
}

func TestRuntimeDevnetCompatibility(t *testing.T) {
	d := TestOnlyDevnetConfig()
	r := RuntimeFromDevnet(d)
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	back, err := r.AsTestDevnet()
	if err != nil || back != d {
		t.Fatal("strict Devnet round trip failed", err)
	}
	oldJSON, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	newJSON, err := json.Marshal(r)
	if err != nil || !bytes.Equal(oldJSON, newJSON) {
		t.Fatal("legacy identity JSON changed", err)
	}
	r.Chain.NetworkKind = NetworkMainnet
	if r.Validate() == nil {
		t.Fatal("mainnet accepted the Devnet identifiers")
	}
	r = RuntimeFromDevnet(d)
	r.Chain.NativeDenom = "other"
	if r.Validate() == nil {
		t.Fatal("strict Devnet checks weakened")
	}
}

func TestExplicitRuntimeValidation(t *testing.T) {
	r := runtimeFixture()
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.AsTestDevnet(); err == nil {
		t.Fatal("mainnet converted to test Devnet")
	}
	if (RuntimeConfig{}).Validate() == nil {
		t.Fatal("empty profile accepted")
	}
	for name, mutate := range map[string]func(*RuntimeConfig){
		"network missing": func(r *RuntimeConfig) { r.Chain.NetworkKind = "" },
		"network unknown": func(r *RuntimeConfig) { r.Chain.NetworkKind = "unknown" },
		"cosmos missing":  func(r *RuntimeConfig) { r.Chain.CosmosChainID = "" },
		"cosmos reused":   func(r *RuntimeConfig) { r.Chain.CosmosChainID = testDevnetCosmosChainID },
		"evm zero":        func(r *RuntimeConfig) { r.Chain.EVMChainID = 0 },
		"evm reused":      func(r *RuntimeConfig) { r.Chain.EVMChainID = testDevnetEVMChainID },
		"evm reserved":    func(r *RuntimeConfig) { r.Chain.EVMChainID = 56 },
		"prefix missing":  func(r *RuntimeConfig) { r.Chain.Bech32Prefix = "" },
		"denom missing":   func(r *RuntimeConfig) { r.Chain.NativeDenom = "" },
		"gas missing":     func(r *RuntimeConfig) { r.MinimumGasPrice = "" },
		"gas negative":    func(r *RuntimeConfig) { r.MinimumGasPrice = "-1arfixture" },
		"gas wrong denom": func(r *RuntimeConfig) { r.MinimumGasPrice = "1other" },
		"gas multiple":    func(r *RuntimeConfig) { r.MinimumGasPrice = "1arfixture,2other" },
		"gas whitespace":  func(r *RuntimeConfig) { r.MinimumGasPrice = " 1arfixture" },
		"gas malformed":   func(r *RuntimeConfig) { r.MinimumGasPrice = "invalid" },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := r
			mutate(&cfg)
			if cfg.Validate() == nil {
				t.Fatal("invalid profile accepted")
			}
		})
	}
}
