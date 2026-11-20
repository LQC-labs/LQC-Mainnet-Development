//go:build linux

// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDevnetCLIRejectsInvalidHome(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"missing init home", []string{"devnet", "init"}, "explicit absolute NEW test --home"},
		{"relative init home", []string{"devnet", "init", "--home", "relative"}, "explicit absolute NEW test --home"},
		{"missing opt-in", []string{"start", "--home", missing}, "explicit --test-devnet"},
		{"missing start home", []string{"start", "--test-devnet"}, "explicit absolute existing test --home"},
		{"relative start home", []string{"start", "--test-devnet", "--home", "relative"}, "explicit absolute existing test --home"},
		{"nonexistent start home", []string{"start", "--test-devnet", "--home", missing}, "home"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := newRootCommand()
			root.SetArgs(tc.args)
			if err := root.Execute(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
	if _, err := os.Lstat(missing); !os.IsNotExist(err) {
		t.Fatalf("start must never create a home, got %v", err)
	}
}
