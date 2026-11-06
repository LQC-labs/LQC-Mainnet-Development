//go:build linux

// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

package node

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cometbft/cometbft/crypto/ed25519"
	cmtjson "github.com/cometbft/cometbft/libs/json"
	"github.com/cometbft/cometbft/p2p"
	"github.com/cometbft/cometbft/privval"
	"golang.org/x/sys/unix"
)

// CreateHome exclusively creates a Linux TEST Devnet home with independent
// consensus and P2P keys. It does not create Genesis, open a DB or start a node.
// The parent must already exist. Every path component is opened without
// following symlinks; relative paths and dot components are rejected.
// Failed initialization may leave a partial home for inspection. It is never
// deleted or overwritten: retry using a different new home.
func CreateHome(path string) error {
	if !filepath.IsAbs(path) || path == "/" || strings.HasSuffix(path, "/") || strings.IndexByte(path, 0) >= 0 {
		return fmt.Errorf("new absolute Devnet home required")
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return fmt.Errorf("home path must not contain empty or dot components")
		}
	}
	parent, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open home root: %w", err)
	}
	// Walk by directory descriptors, not resolved path strings. O_NOFOLLOW
	// rejects even symlinks to directories inside the intended parent.
	for _, part := range parts[:len(parts)-1] {
		next, openErr := unix.Openat(parent, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(parent)
		if openErr != nil {
			return fmt.Errorf("open nonsymlink home parent: %w", openErr)
		}
		parent = next
	}
	defer unix.Close(parent)
	name := parts[len(parts)-1]
	if err = unix.Mkdirat(parent, name, 0700); err != nil {
		return fmt.Errorf("create NEW home (existing paths forbidden): %w", err)
	}
	home, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open new home: %w", err)
	}
	defer unix.Close(home)
	if err = unix.Fchmod(home, 0700); err != nil {
		return fmt.Errorf("set home permissions: %w", err)
	}
	for _, dir := range []string{"config", "data"} {
		if err = unix.Mkdirat(home, dir, 0700); err != nil {
			return fmt.Errorf("create %s directory: %w", dir, err)
		}
	}
	config, err := openPrivateDirectory(home, "config")
	if err != nil {
		return err
	}
	defer unix.Close(config)
	data, err := openPrivateDirectory(home, "data")
	if err != nil {
		return err
	}
	defer unix.Close(data)
	consensus := ed25519.GenPrivKey()
	nodeKey := ed25519.GenPrivKey()
	key := privval.FilePVKey{Address: consensus.PubKey().Address(), PubKey: consensus.PubKey(), PrivKey: consensus}
	// Marshal only to private files, never to logs or returned error strings.
	files := []struct {
		directory int
		name      string
		value     interface{}
	}{
		{config, "priv_validator_key.json", key},
		{config, "node_key.json", p2p.NodeKey{PrivKey: nodeKey}},
		{data, "priv_validator_state.json", privval.FilePVLastSignState{}},
	}
	for _, file := range files {
		content, marshalErr := cmtjson.MarshalIndent(file.value, "", "  ")
		if marshalErr != nil {
			return fmt.Errorf("encode %s", file.name)
		}
		if err = writePrivateFile(file.directory, file.name, content); err != nil {
			return err
		}
	}
	for _, fd := range []int{config, data, home, parent} {
		if err = unix.Fsync(fd); err != nil {
			return fmt.Errorf("sync home directory: %w", err)
		}
	}
	return nil
}

func openPrivateDirectory(parent int, name string) (int, error) {
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("open %s directory: %w", name, err)
	}
	if err = unix.Fchmod(fd, 0700); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("set directory permissions: %w", err)
	}
	return fd, nil
}

func writePrivateFile(directory int, name string, content []byte) error {
	fd, err := unix.Openat(directory, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return fmt.Errorf("create %s: %w", name, err)
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	if err = file.Chmod(0600); err != nil {
		return fmt.Errorf("set %s permissions: %w", name, err)
	}
	if _, err = file.Write(content); err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	if err = file.Sync(); err != nil {
		return fmt.Errorf("sync %s: %w", name, err)
	}
	return nil
}
