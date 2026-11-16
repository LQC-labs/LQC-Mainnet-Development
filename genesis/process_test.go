// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

package genesis

import (
	"os"
	"os/exec"
	"regexp"
	"testing"
	"time"
)

// runGenesisTestInSubprocess runs the complete test body in a fresh process.
// App construction and coin initialization set EVM process globals that must
// retain their production one-time guards, including across -count repetitions.
// The parent returns true after checking the child's result; the child returns
// false so that the caller executes all of its original assertions.
func runGenesisTestInSubprocess(t *testing.T) bool {
	t.Helper()
	const childEnv = "LQC_GENESIS_ISOLATED_TEST"
	if os.Getenv(childEnv) == t.Name() {
		return false
	}
	args := []string{"-test.run=^" + regexp.QuoteMeta(t.Name()) + "$", "-test.count=1", "-test.v"}
	if deadline, ok := t.Deadline(); ok {
		args = append(args, "-test.timeout="+time.Until(deadline).String())
	}
	command := exec.CommandContext(t.Context(), os.Args[0], args...)
	command.Env = append(os.Environ(), childEnv+"="+t.Name())
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated genesis test failed: %v\n%s", err, output)
	}
	t.Log(string(output))
	return true
}
