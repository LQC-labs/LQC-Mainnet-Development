// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestCLIScope(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"version"}} {
		root := newRootCommand()
		var output bytes.Buffer
		root.SetOut(&output)
		root.SetArgs(args)
		if err := root.Execute(); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(output.String(), "lqcd") {
			t.Fatal("missing application identity")
		}
	}
	root := newRootCommand()
	root.SetArgs([]string{"keys"})
	if err := root.Execute(); err == nil {
		t.Error("out-of-scope keys command must not be available")
	}
	for _, args := range [][]string{{"init"}, {"init", "--home", t.TempDir(), "--chain-id", "wrong"}, {"genesis", "validate"}} {
		root := newRootCommand()
		root.SetArgs(args)
		if err := root.Execute(); err == nil {
			t.Errorf("invalid arguments accepted: %v", args)
		}
	}
}
