// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMainnetGenesisCLIInputs(t *testing.T) {
	for _, args := range [][]string{
		{"genesis", "validate-runtime"},
		{"genesis", "validate-runtime", "--network", "devnet"},
		{"genesis", "validate-runtime", "--network", "mainnet", "--config", "/missing", "--genesis", "/missing"},
	} {
		root := newRootCommand()
		root.SetArgs(args)
		if err := root.Execute(); err == nil {
			t.Fatal("incomplete Mainnet inputs accepted")
		}
	}
	path := filepath.Join(t.TempDir(), "runtime.json")
	if err := os.WriteFile(path, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	root := newRootCommand()
	root.SetArgs([]string{"genesis", "validate-runtime", "--network", "mainnet", "--config", path, "--genesis", "/missing", "--expected-genesis-sha256", strings.Repeat("0", 64)})
	if err := root.Execute(); err == nil {
		t.Fatal("empty profile accepted")
	}
	root = newRootCommand()
	root.SetArgs([]string{"genesis", "validate-runtime", "--help"})
	var out bytes.Buffer
	root.SetOut(&out)
	if err := root.Execute(); err != nil || !strings.Contains(out.String(), "expected-genesis-sha256") {
		t.Fatal("missing explicit digest flag", err)
	}
	for _, forbidden := range []string{"start", "keys"} {
		root = newRootCommand()
		root.SetArgs([]string{forbidden})
		if root.Execute() == nil {
			t.Fatal("unapproved CLI enabled", forbidden)
		}
	}
}
