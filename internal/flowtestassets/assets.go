// SPDX-License-Identifier: Apache-2.0

// Package flowtestassets resolves optional, separately supplied FLOW test data.
// It is imported by tests only; the mainnet node never uses this package.
package flowtestassets

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

var ErrUnavailable = errors.New("separate FLOW test assets are not installed")

const marker = "node/testdata/flow-minimal/SOURCE.json"

// Resolve never falls back from an explicitly requested root. A present but
// invalid marker is an error, not a reason to skip or choose different data.
func Resolve(explicit string, candidates []string) (string, error) {
	if explicit != "" {
		if !filepath.IsAbs(explicit) || filepath.Clean(explicit) != explicit {
			return "", fmt.Errorf("LQC_FLOW_ASSET_ROOT requires a clean absolute bundle root")
		}
		if err := checkMarker(explicit); err != nil {
			return "", fmt.Errorf("requested FLOW bundle: %w", err)
		}
		return explicit, nil
	}
	for _, candidate := range candidates {
		root, err := filepath.Abs(candidate)
		if err != nil {
			return "", err
		}
		err = checkMarker(root)
		if err == nil {
			return root, nil
		}
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		return "", err
	}
	return "", ErrUnavailable
}

func checkMarker(root string) error {
	st, err := os.Lstat(filepath.Join(root, marker))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if info, present := os.Lstat(filepath.Join(root, "node/testdata/flow-minimal")); present == nil && info != nil {
				return fmt.Errorf("FLOW asset directory is present but provenance marker is missing")
			}
		}
		return err
	}
	if !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0 || st.Size() > 2<<20 {
		return fmt.Errorf("FLOW provenance marker must be a bounded regular file")
	}
	return nil
}

// Require reports absence as SKIP only for an unrequested optional suite.
// Explicit FLOW requests, missing requested bundles, malformed data and the
// existing downstream hash/ABI assertions still fail closed.
func Require(t testing.TB) string {
	t.Helper()
	root, err := Resolve(os.Getenv("LQC_FLOW_ASSET_ROOT"), []string{".", "..", "../.."})
	if err == nil {
		return root
	}
	requested := os.Getenv("LQC_REQUIRE_FLOW_ASSETS") == "1" || os.Getenv("LQC_RUN_FLOW_MINIMAL") == "1" || os.Getenv("LQC_FLOW_ROOT") != ""
	if errors.Is(err, ErrUnavailable) && !requested {
		t.Skip("FLOW external-data suite NOT RUN: separate assets absent; supply LQC_FLOW_ASSET_ROOT and LQC_REQUIRE_FLOW_ASSETS=1 to require validation")
	}
	t.Fatalf("FLOW assets required or invalid: %v", err)
	return ""
}
