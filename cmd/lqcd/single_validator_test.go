// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestSingleValidatorCLI(t *testing.T) {
	if path := os.Getenv("LQC_SINGLE_VALIDATOR_CLI_INPUT"); path != "" {
		root := newRootCommand()
		root.SetArgs([]string{"single-validator", "validate", path})
		if err := root.Execute(); err != nil {
			t.Fatal(err)
		}
		return
	}
	parent := t.TempDir()
	home := filepath.Join(parent, "isolated-test")
	root := newRootCommand()
	var output bytes.Buffer
	root.SetOut(&output)
	root.SetArgs([]string{"single-validator", "create", "--home", home})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(home, "config", "genesis.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	root = newRootCommand()
	root.SetArgs([]string{"single-validator", "create", "--home", home})
	if err := root.Execute(); err == nil {
		t.Fatal("existing home accepted")
	}
	for _, candidate := range []string{"", "relative-home"} {
		root = newRootCommand()
		root.SetArgs([]string{"single-validator", "create", "--home", candidate})
		if err := root.Execute(); err == nil {
			t.Fatal("nonabsolute home accepted")
		}
	}
	if err := os.Symlink(home, filepath.Join(parent, "linked-home")); err != nil {
		t.Fatal(err)
	}
	root = newRootCommand()
	root.SetArgs([]string{"single-validator", "create", "--home", filepath.Join(parent, "linked-home")})
	if err := root.Execute(); err == nil {
		t.Fatal("symlink home accepted")
	}
	command := exec.Command(os.Args[0], "-test.run=^TestSingleValidatorCLI$", "-test.v")
	command.Env = append(os.Environ(), "LQC_SINGLE_VALIDATOR_CLI_INPUT="+path)
	result, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("CLI runtime validation: %v\n%s", err, result)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("input Genesis changed")
	}
	for _, name := range []string{"priv_validator_key.json", "node_key.json"} {
		if _, err := os.Stat(filepath.Join(home, "config", name)); !os.IsNotExist(err) {
			t.Fatal("private key persisted")
		}
	}
	if bytes.Contains(before, []byte("priv_key")) || bytes.Contains(before, []byte("mnemonic")) {
		t.Fatal("unexpected secret field")
	}
	t.Log("create/validate CLI PASS; existing and symlink homes refused; public input unchanged")
}
