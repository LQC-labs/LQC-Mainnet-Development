//go:build linux

// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestStartExplicitInputs(t *testing.T) {
	for _, args := range [][]string{{"start"}, {"start", "--network", "mainnet"}, {"start", "--network", "mainnet", "--home", t.TempDir(), "--local-test-only"}} {
		root := newRootCommand()
		root.SetArgs(args)
		if root.Execute() == nil {
			t.Fatal("incomplete start request accepted")
		}
	}
	root := newRootCommand()
	root.SetArgs([]string{"start", "--help"})
	var out bytes.Buffer
	root.SetOut(&out)
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	for _, flag := range []string{"--network", "--config", "--genesis", "--expected-genesis-sha256", "--home", "--local-test-only"} {
		if !strings.Contains(out.String(), flag) {
			t.Fatal("required flag missing", flag)
		}
	}
}
