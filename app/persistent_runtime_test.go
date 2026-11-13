//go:build linux

// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"cosmossdk.io/log/v2"
	"github.com/LQC-labs/LQC-Mainnet-Development/app"
	chainconfig "github.com/LQC-labs/LQC-Mainnet-Development/chain/config"
	dbm "github.com/cosmos/cosmos-db"
)

func runtimeHome(t *testing.T) string {
	t.Helper()
	home := filepath.Join(t.TempDir(), "home")
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(home, "data"), 0700); err != nil {
		t.Fatal(err)
	}
	return home
}

func runtimeSnapshot(t *testing.T, home string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(home, func(p string, e os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e.IsDir() {
			out[p] = "directory"
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		s, err := e.Info()
		if err != nil {
			return err
		}
		out[p] = fmt.Sprintf("%x:%o:%d", sha256.Sum256(b), s.Mode().Perm(), s.ModTime().UnixNano())
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func persistentChild(t *testing.T, home string, cfg chainconfig.RuntimeConfig, mode string) {
	t.Helper()
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	runtimeChild(t, "TestRuntimePersistentChild", "LQC_STEP1_PERSISTENT_HOME="+home, "LQC_STEP1_PERSISTENT_CONFIG="+string(b), "LQC_STEP1_PERSISTENT_MODE="+mode)
}

func TestRuntimePersistentChild(t *testing.T) {
	home := os.Getenv("LQC_STEP1_PERSISTENT_HOME")
	if home == "" {
		t.Skip("subprocess only")
	}
	var cfg chainconfig.RuntimeConfig
	if err := json.Unmarshal([]byte(os.Getenv("LQC_STEP1_PERSISTENT_CONFIG")), &cfg); err != nil {
		t.Fatal(err)
	}
	mode := os.Getenv("LQC_STEP1_PERSISTENT_MODE")
	var a *app.App
	var err error
	if mode == "legacy-wrapper" {
		a, err = app.OpenPersistent(log.NewNopLogger(), home)
	} else {
		a, err = app.OpenPersistentWithConfig(log.NewNopLogger(), home, cfg)
	}
	if strings.HasPrefix(mode, "reject:") {
		if err == nil || a != nil || !strings.Contains(err.Error(), strings.TrimPrefix(mode, "reject:")) {
			t.Fatal("expected rejection", mode, err)
		}
		t.Log("expected rejection:", err)
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if a.Profile != cfg || a.SDK.ChainID() != cfg.Chain.CosmosChainID || a.SDK.LastBlockHeight() != 0 {
		t.Fatal("wrong restored profile or unexpected commit")
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimePersistentIdentity(t *testing.T) {
	home := runtimeHome(t)
	cfg := runtimeFixture()
	persistentChild(t, home, cfg, "open")
	identity := filepath.Join(home, "data/application.identity.json")
	original, err := os.ReadFile(identity)
	if err != nil {
		t.Fatal(err)
	}
	db, err := dbm.NewDB("application", dbm.GoLevelDBBackend, filepath.Join(home, "data"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetSync([]byte("runtime-preserved-marker"), []byte("preserved")); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*chainconfig.RuntimeConfig){
		"cosmos": func(c *chainconfig.RuntimeConfig) { c.Chain.CosmosChainID = "other-fixture-1" },
		"evm":    func(c *chainconfig.RuntimeConfig) { c.Chain.EVMChainID++ },
		"prefix": func(c *chainconfig.RuntimeConfig) { c.Chain.Bech32Prefix = "different" },
		"denom":  func(c *chainconfig.RuntimeConfig) { c.Chain.NativeDenom = "other"; c.MinimumGasPrice = "0.01other" },
		"gas":    func(c *chainconfig.RuntimeConfig) { c.MinimumGasPrice = "0.02arfixture" },
		"network": func(c *chainconfig.RuntimeConfig) {
			*c = chainconfig.RuntimeFromDevnet(chainconfig.TestOnlyDevnetConfig())
		},
	} {
		t.Run(name, func(t *testing.T) {
			other := cfg
			mutate(&other)
			if err := other.Validate(); err != nil {
				t.Fatal("invalid mismatch fixture", err)
			}
			before := runtimeSnapshot(t, home)
			persistentChild(t, home, other, "reject:stored application chain identity mismatch")
			if !reflect.DeepEqual(before, runtimeSnapshot(t, home)) {
				t.Fatal("rejected open modified persistent files")
			}
		})
	}
	persistentChild(t, home, cfg, "open")
	after, err := os.ReadFile(identity)
	if err != nil || string(after) != string(original) {
		t.Fatal("identity overwritten", err)
	}
	db, err = dbm.NewDB("application", dbm.GoLevelDBBackend, filepath.Join(home, "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	b, err := db.Get([]byte("runtime-preserved-marker"))
	if err != nil || string(b) != "preserved" {
		t.Fatal("existing DB content lost", err)
	}
}

func TestRuntimeLegacyDevnetIdentity(t *testing.T) {
	home := runtimeHome(t)
	d := chainconfig.TestOnlyDevnetConfig()
	legacy, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(home, "data/application.identity.json")
	if err := os.WriteFile(p, legacy, 0600); err != nil {
		t.Fatal(err)
	}
	cfg := chainconfig.RuntimeFromDevnet(d)
	persistentChild(t, home, cfg, "legacy-wrapper")
	persistentChild(t, home, cfg, "open")
	got, err := os.ReadFile(p)
	if err != nil || string(got) != string(legacy) {
		t.Fatal("legacy identity migrated or overwritten", err)
	}
	before := runtimeSnapshot(t, home)
	persistentChild(t, home, runtimeFixture(), "reject:stored application chain identity mismatch")
	if !reflect.DeepEqual(before, runtimeSnapshot(t, home)) {
		t.Fatal("Devnet DB changed on mainnet request")
	}
}

func TestRuntimeMalformedIdentity(t *testing.T) {
	for _, name := range []string{"unknown-field", "trailing-json", "invalid-profile", "missing-identity"} {
		t.Run(name, func(t *testing.T) {
			home := runtimeHome(t)
			b, _ := json.Marshal(runtimeFixture())
			want := "stored application chain identity mismatch"
			switch name {
			case "unknown-field":
				b = append(b[:len(b)-1], []byte(",\"Unexpected\":true}")...)
			case "trailing-json":
				b = append(b, []byte(" {}")...)
			case "invalid-profile":
				b = []byte("{}")
			case "missing-identity":
				if err := os.Mkdir(filepath.Join(home, "data/application.db"), 0700); err != nil {
					t.Fatal(err)
				}
				want = "existing application DB has no trusted chain identity"
			}
			if name != "missing-identity" {
				if err := os.WriteFile(filepath.Join(home, "data/application.identity.json"), b, 0600); err != nil {
					t.Fatal(err)
				}
			}
			before := runtimeSnapshot(t, home)
			persistentChild(t, home, runtimeFixture(), "reject:"+want)
			if !reflect.DeepEqual(before, runtimeSnapshot(t, home)) {
				t.Fatal("untrusted state modified")
			}
		})
	}
}
