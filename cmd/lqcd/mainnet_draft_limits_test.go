// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadBoundedOfflineFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "input.json")
	if err := os.WriteFile(file, []byte("{}"), 0600); err != nil { t.Fatal(err) }
	if got, err := readBoundedOfflineFile(file); err != nil || string(got) != "{}" {
		t.Fatalf("valid regular input rejected: %q %v", got, err)
	}
	link := filepath.Join(dir, "linked-input.json")
	if err := os.Symlink(file, link); err != nil { t.Fatal(err) }
	if _, err := readBoundedOfflineFile(link); err == nil { t.Fatal("symlink input accepted") }
	linkedDir := filepath.Join(t.TempDir(), "linked-dir")
	if err := os.Symlink(dir, linkedDir); err != nil { t.Fatal(err) }
	if _, err := readBoundedOfflineFile(filepath.Join(linkedDir, "input.json")); err == nil { t.Fatal("symlink parent directory accepted") }
	if _, err := readBoundedOfflineFile(dir); err == nil { t.Fatal("directory accepted") }
	if _, err := readBoundedOfflineFile(filepath.Join(dir, "missing")); err == nil { t.Fatal("missing input accepted") }
	large := filepath.Join(dir, "oversized.json")
	f, err := os.Create(large)
	if err != nil { t.Fatal(err) }
	if err := f.Truncate(maxOfflineDraftBytes+1); err != nil { f.Close(); t.Fatal(err) }
	if err := f.Close(); err != nil { t.Fatal(err) }
	if _, err := readBoundedOfflineFile(large); err == nil { t.Fatal("oversized input accepted") }
}
