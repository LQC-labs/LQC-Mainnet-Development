// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	"cosmossdk.io/log/v2"
	"github.com/LQC-labs/LQC-Mainnet-Development/app"
	chainconfig "github.com/LQC-labs/LQC-Mainnet-Development/chain/config"
	"github.com/LQC-labs/LQC-Mainnet-Development/genesis"
	dbm "github.com/cosmos/cosmos-db"
	sdk "github.com/cosmos/cosmos-sdk/types"
	evmtypes "github.com/cosmos/evm/x/vm/types"
)

// Synthetic, offline application fixture; never a production network profile.
func runtimeFixture() chainconfig.RuntimeConfig {
	return chainconfig.RuntimeConfig{Chain: chainconfig.ChainConfig{NetworkKind: chainconfig.NetworkMainnet, CosmosChainID: "runtime-fixture-1", EVMChainID: 423456781, Bech32Prefix: "runtest", NativeDenom: "arfixture"}, MinimumGasPrice: "0.01arfixture"}
}

func runtimeChild(t *testing.T, name string, env ...string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^"+name+"$", "-test.count=1", "-test.v", "-test.timeout=90s")
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated runtime child failed: %v\n%s", err, out)
	}
	t.Log(string(out))
	return string(out)
}

func TestRuntimeApplicationProfiles(t *testing.T) {
	for _, name := range []string{"mainnet-fixture", "explicit-devnet"} {
		t.Run(name, func(t *testing.T) { runtimeChild(t, "TestRuntimeApplicationChild", "LQC_STEP1_APP_CASE="+name) })
	}
}

func TestRuntimeApplicationChild(t *testing.T) {
	mode := os.Getenv("LQC_STEP1_APP_CASE")
	if mode == "" {
		t.Skip("subprocess only")
	}
	cfg := runtimeFixture()
	if mode == "explicit-devnet" {
		cfg = chainconfig.RuntimeFromDevnet(chainconfig.TestOnlyDevnetConfig())
	}
	db := dbm.NewMemDB()
	a, err := app.NewWithConfig(log.NewNopLogger(), db, t.TempDir(), cfg)
	if err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	defer func() {
		if err := a.Close(); err != nil {
			t.Error(err)
		}
	}()
	if a.Profile != cfg || a.SDK.ChainID() != cfg.Chain.CosmosChainID || a.SDK.LastBlockHeight() != 0 {
		t.Fatal("profile not applied or unexpected commit")
	}
	sdkCfg := sdk.GetConfig()
	p := cfg.Chain.Bech32Prefix
	if sdkCfg.GetBech32AccountAddrPrefix() != p || sdkCfg.GetBech32ValidatorAddrPrefix() != p+"valoper" || sdkCfg.GetBech32ConsensusAddrPrefix() != p+"valcons" {
		t.Fatal("address prefixes not applied")
	}
	if c := evmtypes.GetEthChainConfig(); c == nil || c.ChainID.Uint64() != cfg.Chain.EVMChainID {
		t.Fatal("EVM identity not applied")
	}
	if mode == "mainnet-fixture" {
		if _, err := genesis.New(a); err == nil {
			t.Fatal("mainnet reached test Genesis generation")
		}
	} else {
		raw, err := genesis.New(a)
		if err != nil || genesis.Validate(a, raw) != nil {
			t.Fatal("Devnet Genesis regression", err)
		}
	}
	other := cfg
	other.Chain.CosmosChainID = "different-fixture-1"
	if mode == "explicit-devnet" {
		other = runtimeFixture()
	}
	otherDB := dbm.NewMemDB()
	defer otherDB.Close()
	if b, err := app.NewWithConfig(log.NewNopLogger(), otherDB, t.TempDir(), other); err == nil || !strings.Contains(err.Error(), "different runtime profile") || b != nil {
		t.Fatal("process profile switch not rejected", err)
	}
	if sdkCfg.GetBech32AccountAddrPrefix() != p || evmtypes.GetEthChainConfig().ChainID.Uint64() != cfg.Chain.EVMChainID {
		t.Fatal("global configuration changed")
	}
	encoded, _ := json.Marshal(cfg)
	t.Logf("configured synthetic profile=%s height=0; globals retained", encoded)
}
