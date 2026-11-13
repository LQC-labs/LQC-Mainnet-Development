//go:build linux

// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0
//
package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"

	"cosmossdk.io/log/v2"
	sdkserver "github.com/cosmos/cosmos-sdk/server"
	evmflags "github.com/cosmos/evm/server/flags"
)

func TestPersistentQueueCapacities(t *testing.T) {
	if os.Getenv("LQC_QUEUE_CAPACITY_CHILD") != "1" {
		command := exec.Command(os.Args[0], "-test.run=^TestPersistentQueueCapacities$", "-test.v")
		command.Env = append(os.Environ(), "LQC_QUEUE_CAPACITY_CHILD=1")
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("capacity child: %v\n%s", err, output)
		}
		t.Log(string(output))
		return
	}
	opts := persistentOptions()
	if opts.Get(evmflags.EVMMempoolInsertQueueSize) != 128 || opts.Get(sdkserver.FlagMempoolMaxTxs) != 512 {
		t.Fatal("bounded Devnet options missing")
	}
	home := t.TempDir()
	if err := os.Chmod(home, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(home, "data"), 0700); err != nil {
		t.Fatal(err)
	}
	a, err := OpenPersistent(log.NewNopLogger(), home)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	pool := reflect.ValueOf(a.SDK.EVMMempool).Elem()
	for _, name := range []string{"cosmosInsertQueue", "evmInsertQueue"} {
		// Read only an immutable constructor field: no unsafe access or mutation.
		capacity := pool.FieldByName(name).Elem().FieldByName("maxSize").Int()
		if capacity != PersistentInsertQueueCapacity {
			t.Fatalf("%s actual capacity=%d", name, capacity)
		}
		t.Logf("%s actual bounded capacity=%d", name, capacity)
	}
}
