// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// This candidate test remains quarantined by the MN-001 execution gate.
func TestReadBoundedOfflineFileFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input.fifo")
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	// No writer is attached. An O_RDONLY open without O_NONBLOCK would hang.
	if _, err := readBoundedOfflineFile(path); err == nil {
		t.Fatal("FIFO input accepted")
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeNamedPipe == 0 {
		t.Fatal("fixture is not a FIFO")
	}
}
