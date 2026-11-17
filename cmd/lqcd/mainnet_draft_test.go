// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	chainconfig "github.com/LQC-labs/LQC-Mainnet-Development/chain/config"
	"github.com/LQC-labs/LQC-Mainnet-Development/genesis"
)

func TestOfflineMainnetDraftCLI(t *testing.T) {
	dir := t.TempDir()
	profile := genesis.MainnetProfile{Chain: chainconfig.RuntimeConfig{
		Chain: chainconfig.ChainConfig{
			NetworkKind: chainconfig.NetworkMainnet, CosmosChainID: "lqc-offline-cli-fixture-1",
			EVMChainID: 423456782, Bech32Prefix: "lqcfixture", NativeDenom: "afixture",
		},
		MinimumGasPrice: "0.01afixture",
	}}
	profileData, err := json.Marshal(profile)
	if err != nil { t.Fatal(err) }
	draft := []byte(`{"chain_id":"lqc-offline-cli-fixture-1","validators":[],"app_state":{"auth":{"accounts":[]},"bank":{"balances":[],"supply":[]},"staking":{"validators":[]},"genutil":{"gen_txs":[]}}}`)
	p := filepath.Join(dir,"profile.json")
	g := filepath.Join(dir,"genesis.json")
	if err := os.WriteFile(p, profileData, 0600); err != nil { t.Fatal(err) }
	if err := os.WriteFile(g, draft, 0600); err != nil { t.Fatal(err) }
	run := func(wantSuccess bool) {
		t.Helper()
		root := newRootCommand()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetArgs([]string{"genesis","validate-mainnet-draft",p,g})
		err := root.Execute()
		if (err == nil) != wantSuccess { t.Fatalf("success=%v err=%v",wantSuccess,err) }
		if wantSuccess && !strings.Contains(out.String(),"NOT SDK module validation") { t.Fatal("missing safety disclaimer") }
	}
	run(true)
	if err := os.WriteFile(g, []byte(`{"chain_id":"wrong","validators":[],"app_state":{}}`), 0600); err != nil { t.Fatal(err) }
	run(false)
	if err := os.WriteFile(g, draft, 0600); err != nil { t.Fatal(err) }
	if err := os.WriteFile(p, []byte(`{"approved":true}`), 0600); err != nil { t.Fatal(err) }
	run(false)
}
