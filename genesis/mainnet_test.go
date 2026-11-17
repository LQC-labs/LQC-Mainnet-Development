// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

package genesis

import (
	"bytes"
	"encoding/json"
	"testing"

	chainconfig "github.com/LQC-labs/LQC-Mainnet-Development/chain/config"
)

func mainnetFixture() MainnetProfile {
	return MainnetProfile{Chain: chainconfig.RuntimeConfig{
		Chain: chainconfig.ChainConfig{
			NetworkKind: chainconfig.NetworkMainnet,
			CosmosChainID: "lqc-offline-fixture-1",
			EVMChainID: 423456781,
			Bech32Prefix: "lqctestfixture",
			NativeDenom: "afixture",
		},
		MinimumGasPrice: "0.01afixture",
	}}
}

func TestMainnetProposalOfflineValidation(t *testing.T) {
	p := mainnetFixture()
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateMainnetProfile(raw); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*MainnetProfile){
		"devnet": func(p *MainnetProfile) { p.Chain.Chain.NetworkKind = chainconfig.NetworkDevnet },
		"reserved EVM": func(p *MainnetProfile) { p.Chain.Chain.EVMChainID = 56 },
		"missing Cosmos ID": func(p *MainnetProfile) { p.Chain.Chain.CosmosChainID = "" },
		"invalid denom": func(p *MainnetProfile) { p.Chain.MinimumGasPrice = "1other" },
		"premature approval": func(p *MainnetProfile) { p.Approved = true },
		"validator activation": func(p *MainnetProfile) { p.ValidatorCount = 1 },
		"genesis activation": func(p *MainnetProfile) { p.GenesisHash = "not-approved" },
	} {
		t.Run(name, func(t *testing.T) {
			c := p
			mutate(&c)
			data, err := json.Marshal(c)
			if err != nil { t.Fatal(err) }
			if ValidateMainnetProfile(data) == nil { t.Fatal("unsafe mainnet proposal accepted") }
		})
	}
	for _, raw := range [][]byte{
		nil,
		[]byte("{}"),
		[]byte("{\"unexpected\":true}"),
		append(append([]byte{}, raw...), []byte(" {}")...),
	} {
		if ValidateMainnetProfile(raw) == nil { t.Fatal("malformed mainnet proposal accepted") }
	}
}

func TestMainnetProfileRejectsDuplicateKeys(t *testing.T) {
	p := mainnetFixture()
	raw, err := json.Marshal(p)
	if err != nil { t.Fatal(err) }
	if err := ValidateMainnetProfile(raw); err != nil { t.Fatal(err) }
	for name, mutated := range map[string][]byte{
		"root override": append([]byte(`{"approved":true,`), raw[1:]...),
		"nested chain override": bytes.Replace(raw, []byte(`"EVMChainID":423456781`), []byte(`"EVMChainID":56,"EVMChainID":423456781`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if bytes.Equal(raw, mutated) { t.Fatal("fixture mutation failed") }
			if err := ValidateMainnetProfile(mutated); err == nil { t.Fatal("duplicate keys accepted") }
		})
	}
}
