//go:build linux

// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0
package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"cosmossdk.io/log/v2"
	dbm "github.com/cosmos/cosmos-db"
)

func TestPersistentDBReconnect(t *testing.T) {
	if home := os.Getenv("LQC_PERSISTENT_APP_HOME"); home != "" {
		a, err := OpenPersistent(log.NewNopLogger(), home)
		if err != nil {
			t.Fatal(err)
		}
		if a.SDK.LastBlockHeight() != 0 || a.SDK.ChainID() != "lqc-devnet-test-1" {
			t.Fatal("unexpected unstarted persistent app")
		}
		if err = a.Close(); err != nil {
			t.Fatal(err)
		}
		return
	}
	home := filepath.Join(t.TempDir(), "home")
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(home, "data"), 0700); err != nil {
		t.Fatal(err)
	}
	invoke := func() {
		command := exec.Command(os.Args[0], "-test.run=^TestPersistentDBReconnect$", "-test.v")
		command.Env = append(os.Environ(), "LQC_PERSISTENT_APP_HOME="+home)
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("persistent child: %v\n%s", err, output)
		}
	}
	invoke()
	// A raw DB marker verifies actual storage survives process/app closure,
	// without manufacturing an SDK commit or generating any block.
	database, err := dbm.NewDB("application", dbm.GoLevelDBBackend, filepath.Join(home, "data"))
	if err != nil {
		t.Fatal(err)
	}
	if err = database.SetSync([]byte("lqc-reconnect-test"), []byte("preserved")); err != nil {
		t.Fatal(err)
	}
	if err = database.Close(); err != nil {
		t.Fatal(err)
	}
	invoke()
	database, err = dbm.NewDB("application", dbm.GoLevelDBBackend, filepath.Join(home, "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	value, err := database.Get([]byte("lqc-reconnect-test"))
	if err != nil || string(value) != "preserved" {
		t.Fatal("persistent DB data lost")
	}
}

func TestPersistentRejectsUntrustedPaths(t *testing.T) {
	for _, mode := range []string{"missing-home", "symlink-home", "identity-mismatch", "unidentified-db", "identity-symlink"} {
		t.Run(mode, func(t *testing.T) {
			parent := t.TempDir()
			home := filepath.Join(parent, "home")
			if mode != "missing-home" {
				if err := os.Mkdir(home, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(filepath.Join(home, "data"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			switch mode {
			case "symlink-home":
				linked := filepath.Join(parent, "link")
				if err := os.Symlink(home, linked); err != nil {
					t.Fatal(err)
				}
				home = linked
			case "identity-mismatch":
				if err := os.WriteFile(filepath.Join(home, "data/application.identity.json"), []byte(`{"Chain":{"CosmosChainID":"wrong"}}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "unidentified-db":
				if err := os.Mkdir(filepath.Join(home, "data/application.db"), 0700); err != nil {
					t.Fatal(err)
				}
			case "identity-symlink":
				target := filepath.Join(parent, "identity")
				if err := os.WriteFile(target, []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, filepath.Join(home, "data/application.identity.json")); err != nil {
					t.Fatal(err)
				}
			}
			if a, err := OpenPersistent(log.NewNopLogger(), home); err == nil {
				a.Close()
				t.Fatal("untrusted home accepted")
			}
		})
	}
}
