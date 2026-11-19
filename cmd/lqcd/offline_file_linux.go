// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"os"

	"golang.org/x/sys/unix"
)

// openOfflineDraftFile rejects symlinks in every path component atomically.
// Unsupported kernels fail closed; no insecure fallback to os.Open.
func openOfflineDraftFile(path string) (*os.File, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}
