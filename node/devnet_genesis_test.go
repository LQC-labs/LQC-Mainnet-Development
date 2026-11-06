//go:build linux

// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

package node

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"cosmossdk.io/log/v2"
	"github.com/LQC-labs/LQC-Mainnet-Development/app"
	"github.com/LQC-labs/LQC-Mainnet-Development/genesis"
	dbm "github.com/cosmos/cosmos-db"
)

func TestInitDevnetHome(t *testing.T) {
	if runDevnetChild(t, "valid") {
		return
	}
	a := devnetTestApp(t)
	home := filepath.Join(t.TempDir(), "devnet")
	if err := InitDevnetHome(a, home); err != nil {
		t.Fatal(err)
	}
	before := snapshotDevnet(t, home)
	if err := ValidateDevnetHome(a, home); err != nil {
		t.Fatal(err)
	}
	if err := InitDevnetHome(a, home); err == nil {
		t.Fatal("existing home accepted")
	}
	after := snapshotDevnet(t, home)
	for name, content := range before {
		if !bytes.Equal(after[name], content) {
			t.Fatalf("validation or repeated init changed %s", name)
		}
	}
	for _, dir := range []string{"", "config", "data"} {
		assertMode(t, filepath.Join(home, dir), 0700)
	}
	for name := range before {
		assertMode(t, filepath.Join(home, name), 0600)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestPreparedDevnetInitChain$", "-test.v")
	command.Env = append(os.Environ(), "LQC_PREPARED_HOME="+home)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("prepared gentx runtime verification failed: %v\n%s", err, output)
	}
	t.Log("prepared home gentx InitChain PASS; one validator, positive power, matching consensus public key, delegation and bank conservation")
}

func TestPreparedDevnetInitChain(t *testing.T) {
	home := os.Getenv("LQC_PREPARED_HOME")
	if home == "" {
		t.Skip("executed by parent test in an independent process")
	}
	a := devnetTestApp(t)
	if err := ValidateDevnetHome(a, home); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(home, "config/genesis.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = genesis.VerifySingleValidatorRuntime(a, raw); err != nil {
		t.Fatal(err)
	}
}

func TestDevnetHomeRejectsInvalidInputs(t *testing.T) {
	for _, mode := range []string{"consensus-mismatch", "chain-id", "evm-id", "prefix", "denom", "gentx", "signature", "key-permissions", "directory-permissions", "symlink-key", "missing-key", "signing-state", "corrupt-key"} {
		t.Run(mode, func(t *testing.T) {
			if runDevnetChild(t, mode) {
				return
			}
			a := devnetTestApp(t)
			parent := t.TempDir()
			home := filepath.Join(parent, "devnet")
			if err := InitDevnetHome(a, home); err != nil {
				t.Fatal(err)
			}
			genesisPath := filepath.Join(home, "config/genesis.json")
			raw, err := os.ReadFile(genesisPath)
			if err != nil {
				t.Fatal(err)
			}
			var doc map[string]interface{}
			if err = json.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}
			changedGenesis := false
			switch mode {
			case "consensus-mismatch":
				other := filepath.Join(parent, "other")
				if err = CreateHome(other); err != nil {
					t.Fatal(err)
				}
				key, err := os.ReadFile(filepath.Join(other, "config/priv_validator_key.json"))
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(filepath.Join(home, "config/priv_validator_key.json"), key, 0600); err != nil {
					t.Fatal(err)
				}
			case "chain-id":
				doc["chain_id"] = "wrong-devnet-1"
				changedGenesis = true
			case "evm-id", "prefix", "denom":
				chain := doc["lqc_profile"].(map[string]interface{})["Chain"].(map[string]interface{})
				field, value := "EVMChainID", interface{}(917002)
				if mode == "prefix" {
					field, value = "Bech32Prefix", "cosmos"
				}
				if mode == "denom" {
					field, value = "NativeDenom", "stake"
				}
				chain[field] = value
				changedGenesis = true
			case "gentx":
				doc["app_state"].(map[string]interface{})["genutil"].(map[string]interface{})["gen_txs"] = []interface{}{}
				changedGenesis = true
			case "signature":
				gentx := doc["app_state"].(map[string]interface{})["genutil"].(map[string]interface{})["gen_txs"].([]interface{})[0].(map[string]interface{})
				gentx["signatures"] = []interface{}{"AAAA"}
				changedGenesis = true
			case "key-permissions":
				if err = os.Chmod(filepath.Join(home, "config/node_key.json"), 0644); err != nil {
					t.Fatal(err)
				}
			case "directory-permissions":
				if err = os.Chmod(filepath.Join(home, "config"), 0755); err != nil {
					t.Fatal(err)
				}
			case "symlink-key":
				path := filepath.Join(home, "config/node_key.json")
				if err = os.Rename(path, path+".original"); err != nil {
					t.Fatal(err)
				}
				if err = os.Symlink(path+".original", path); err != nil {
					t.Fatal(err)
				}
			case "missing-key":
				path := filepath.Join(home, "config/node_key.json")
				if err = os.Rename(path, path+".saved"); err != nil {
					t.Fatal(err)
				}
			case "signing-state":
				if err = os.WriteFile(filepath.Join(home, "data/priv_validator_state.json"), []byte(`{"height":"1","round":0,"step":0}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "corrupt-key":
				if err = os.WriteFile(filepath.Join(home, "config/priv_validator_key.json"), []byte("{invalid"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if changedGenesis {
				content, err := json.Marshal(doc)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(genesisPath, content, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err = ValidateDevnetHome(a, home); err == nil {
				t.Fatalf("accepted invalid %s", mode)
			}
		})
	}
}

func TestPreparedDevnetRejectsSymlinkHome(t *testing.T) {
	if runDevnetChild(t, "symlink-home") {
		return
	}
	a := devnetTestApp(t)
	parent := t.TempDir()
	home := filepath.Join(parent, "devnet")
	if err := InitDevnetHome(a, home); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "linked")
	if err := os.Symlink(home, link); err != nil {
		t.Fatal(err)
	}
	if err := ValidateDevnetHome(a, link); err == nil {
		t.Fatal("symlink home accepted")
	}
	if err := InitDevnetHome(a, link); err == nil {
		t.Fatal("symlink home overwritten")
	}
}

func snapshotDevnet(t *testing.T, home string) map[string][]byte {
	t.Helper()
	snapshot := make(map[string][]byte)
	for _, name := range []string{"config/genesis.json", "config/priv_validator_key.json", "config/node_key.json", "data/priv_validator_state.json"} {
		content, err := os.ReadFile(filepath.Join(home, name))
		if err != nil {
			t.Fatal(err)
		}
		snapshot[name] = content
	}
	return snapshot
}

func devnetTestApp(t *testing.T) *app.App {
	t.Helper()
	database := dbm.NewMemDB()
	a, err := app.New(log.NewNopLogger(), database, t.TempDir())
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := a.Close(); err != nil {
			t.Error(err)
		}
	})
	return a
}

func runDevnetChild(t *testing.T, name string) bool {
	t.Helper()
	if os.Getenv("LQC_DEVNET_PREP_CASE") == name {
		return false
	}
	command := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$", "-test.v")
	command.Env = append(os.Environ(), "LQC_DEVNET_PREP_CASE="+name)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated %s failed: %v\n%s", name, err, output)
	}
	t.Log(string(output))
	return true
}
