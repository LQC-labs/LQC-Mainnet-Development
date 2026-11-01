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
	for _, command := range []string{"init", "start", "keys", "genesis"} {
		root := newRootCommand()
		root.SetArgs([]string{command})
		if err := root.Execute(); err == nil {
			t.Errorf("out-of-scope command %s must not be available", command)
		}
	}
}
