//go:build linux

// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

package node

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"

	cmtjson "github.com/cometbft/cometbft/libs/json"
	"github.com/cometbft/cometbft/p2p"
	"github.com/cometbft/cometbft/privval"
)

func TestCreateHomePermissionsAndKeys(t *testing.T) {
	home := filepath.Join(t.TempDir(), "devnet")
	if err := CreateHome(home); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"", "config", "data"} {
		assertMode(t, filepath.Join(home, dir), 0700)
	}
	for _, file := range []string{"config/priv_validator_key.json", "config/node_key.json", "data/priv_validator_state.json"} {
		assertMode(t, filepath.Join(home, file), 0600)
	}
	consensusBytes, err := os.ReadFile(filepath.Join(home, "config/priv_validator_key.json"))
	if err != nil {
		t.Fatal(err)
	}
	var consensus privval.FilePVKey
	if err = cmtjson.Unmarshal(consensusBytes, &consensus); err != nil {
		t.Fatal("invalid consensus key encoding")
	}
	nodeKey, err := p2p.LoadNodeKey(filepath.Join(home, "config/node_key.json"))
	if err != nil {
		t.Fatal("invalid node key encoding")
	}
	if consensus.PrivKey == nil || consensus.PubKey == nil || !consensus.PrivKey.PubKey().Equals(consensus.PubKey) || !bytes.Equal(consensus.Address, consensus.PubKey.Address()) {
		t.Fatal("inconsistent consensus key")
	}
	if nodeKey.PrivKey == nil || nodeKey.PubKey().Equals(consensus.PubKey) {
		t.Fatal("keys must be independent")
	}
	stateBytes, err := os.ReadFile(filepath.Join(home, "data/priv_validator_state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var state privval.FilePVLastSignState
	if err = cmtjson.Unmarshal(stateBytes, &state); err != nil {
		t.Fatal("invalid signing state encoding")
	}
	if state.Height != 0 || state.Round != 0 || state.Step != 0 || len(state.Signature) != 0 || len(state.SignBytes) != 0 {
		t.Fatal("new home must have unsigned initial state")
	}
	if err = CreateHome(home); err == nil {
		t.Fatal("existing home accepted")
	}
	after, err := os.ReadFile(filepath.Join(home, "config/priv_validator_key.json"))
	if err != nil || !bytes.Equal(after, consensusBytes) {
		t.Fatal("existing key changed")
	}
	for _, artifact := range []string{"config/genesis.json", "data/application.db", "config/config.toml"} {
		if _, err = os.Lstat(filepath.Join(home, artifact)); !os.IsNotExist(err) {
			t.Fatal("unexpected node artifact")
		}
	}
}

func TestCreateHomeRejectsPaths(t *testing.T) {
	parent := t.TempDir()
	existing := filepath.Join(parent, "existing")
	if err := os.Mkdir(existing, 0755); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(existing, "keep")
	if err := os.WriteFile(marker, []byte("preserve"), 0644); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(parent, "file")
	if err := os.WriteFile(file, []byte("preserve"), 0644); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(parent, "linked")
	if err := os.Symlink(existing, linked); err != nil {
		t.Fatal(err)
	}
	dangling := filepath.Join(parent, "dangling")
	if err := os.Symlink(filepath.Join(parent, "absent"), dangling); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"empty": "", "relative": "devnet", "root": "/", "directory": existing,
		"file": file, "leaf symlink": linked, "dangling symlink": dangling,
		"parent symlink": linked + "/child", "dot": parent + "/./new", "dotdot": parent + "/existing/../new",
		"empty component": parent + "//new", "trailing slash": parent + "/new/", "missing parent": parent + "/missing/new",
	} {
		t.Run(name, func(t *testing.T) {
			if err := CreateHome(path); err == nil {
				t.Fatal("unsafe or existing path accepted")
			}
		})
	}
	content, err := os.ReadFile(marker)
	if err != nil || string(content) != "preserve" {
		t.Fatal("existing home modified")
	}
	content, err = os.ReadFile(file)
	if err != nil || string(content) != "preserve" {
		t.Fatal("existing file modified")
	}
	assertMode(t, existing, 0755)
	if _, err = os.Lstat(filepath.Join(existing, "child")); !os.IsNotExist(err) {
		t.Fatal("symlink target modified")
	}
}

func TestCreateHomeConcurrentExclusive(t *testing.T) {
	home := filepath.Join(t.TempDir(), "devnet")
	var group sync.WaitGroup
	results := make(chan error, 8)
	for range 8 {
		group.Add(1)
		go func() { defer group.Done(); results <- CreateHome(home) }()
	}
	group.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("expected exactly one creator; got %d", successes)
	}
	assertMode(t, home, 0700)
	assertMode(t, filepath.Join(home, "config/priv_validator_key.json"), 0600)
}

func assertMode(t *testing.T, path string, expected os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != expected {
		t.Fatalf("unexpected permissions for %s: %v", path, info.Mode())
	}
}
