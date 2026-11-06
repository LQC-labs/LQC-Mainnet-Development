//go:build linux

// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0
package node

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	cmtdb "github.com/cometbft/cometbft-db"
	cmtjson "github.com/cometbft/cometbft/libs/json"
	"github.com/cometbft/cometbft/privval"
	cmtstate "github.com/cometbft/cometbft/state"
	cmtstore "github.com/cometbft/cometbft/store"
	evmmempool "github.com/cosmos/evm/mempool"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"golang.org/x/sys/unix"
)

func TestCloseCancelsStartupWithoutHoldingMutex(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	n := &Node{fd: -1, cancel: cancel, startDone: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- n.Close() }()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel startup")
	}
	if !n.mu.TryLock() {
		t.Fatal("Close held lifecycle mutex while waiting for startup")
	}
	n.mu.Unlock()
	close(n.startDone)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not finish")
	}
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
}

// This opt-in integration test creates ONLY a new Linux home, retains its DBs,
// keys and evidence, and launches two independent node processes. Normal unit
// test runs never start consensus. Run explicitly with the environment flag.
func TestPersistentNodeRestartAtHeight11(t *testing.T) {
	if os.Getenv("LQC_RUN_RESTART_REGRESSION") != "1" {
		t.Skip("explicit local-node integration opt-in required")
	}
	root, err := os.MkdirTemp("/tmp", "lqc-restart-regression.")
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "home")
	t.Logf("PRESERVED_RESTART_EVIDENCE=%s", root)
	invokeRestartChild(t, root, "prepare", "^TestNodeFixture$", []string{"LQC_NODE_FIXTURE_HOME=" + home})
	initial := restartFileHashes(t, home)
	invokeRestartChild(t, root, "first", "^TestRestartRuntimeChild$", []string{"LQC_RESTART_HOME=" + home, "LQC_RESTART_TARGET=11"})
	before, err := readRestartEvidence(home)
	if err != nil {
		t.Fatal(err)
	}
	if before.Height != 11 {
		t.Fatalf("regression requires exact committed height 11; got %d", before.Height)
	}
	writeRestartEvidence(t, root, "before.json", before)
	invokeRestartChild(t, root, "restart", "^TestRestartRuntimeChild$", []string{"LQC_RESTART_HOME=" + home, "LQC_RESTART_TARGET=21"})
	after, err := readRestartEvidence(home)
	if err != nil {
		t.Fatal(err)
	}
	writeRestartEvidence(t, root, "after.json", after)
	if after.Height < 21 || after.SignedHeight < before.SignedHeight || after.Block1 != before.Block1 || after.Block11 != before.Block11 || after.PublicKey != before.PublicKey || after.Power != 1 || before.Power != 1 || before.Validators != 1 || after.Validators != 1 {
		t.Fatal("restart did not preserve blocks/validator/signing state or increase height")
	}
	for name, hash := range initial {
		if restartFileHashes(t, home)[name] != hash {
			t.Fatalf("Genesis or key changed: %s", name)
		}
	}
	fd, err := openDevnetHome(home)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal("home lock leaked")
	}
	unix.Flock(fd, unix.LOCK_UN)
	t.Logf("RESTART PASS: height %d -> %d; block1=%s block11=%s; validators=1 power=1; signing %d -> %d; keys/Genesis unchanged; Close and flock PASS", before.Height, after.Height, before.Block1, before.Block11, before.SignedHeight, after.SignedHeight)
}

func invokeRestartChild(t *testing.T, root, name, pattern string, environment []string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run="+pattern, "-test.v")
	command.Env = append(os.Environ(), environment...)
	output, err := command.CombinedOutput()
	if writeErr := os.WriteFile(filepath.Join(root, name+".log"), output, 0600); writeErr != nil {
		t.Fatal(writeErr)
	}
	if err != nil {
		t.Fatalf("%s process failed: %v\n%s", name, err, output)
	}
	t.Log(string(output))
}

func TestRestartRuntimeChild(t *testing.T) {
	home := os.Getenv("LQC_RESTART_HOME")
	if home == "" {
		t.Skip("integration child only")
	}
	target, err := strconv.ParseInt(os.Getenv("LQC_RESTART_TARGET"), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	if err = runRestartChild(home, target); err != nil {
		t.Fatal(err)
	}
}

func runRestartChild(home string, target int64) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	n, err := Open(home)
	if err != nil {
		return err
	}
	defer func() {
		done := make(chan error, 1)
		go func() { done <- n.Close() }()
		select {
		case closeErr := <-done:
			err = errors.Join(err, closeErr)
			if closeErr == nil {
				fmt.Println("NORMAL_CLOSE_PASS")
			}
		case <-time.After(15 * time.Second):
			err = errors.Join(err, fmt.Errorf("normal Close deadline"))
		}
	}()
	if n.application.SDK.LastBlockHeight() > 0 {
		if err = n.application.CheckPersistentMempoolReady(ctx); err != nil {
			return err
		}
		pool := n.application.SDK.EVMMempool.(*evmmempool.Mempool)
		fmt.Printf("MEMPOOL_REAL_RECHECK_READY committed_height=%d evm_head=%d cosmos_evm_recheck_complete=%d\n", n.application.SDK.LastBlockHeight(), pool.GetBlockchain().CurrentBlock().Number.Int64(), n.application.SDK.LastBlockHeight())
	}
	if err = n.Start(ctx); err != nil {
		return err
	}
	client := &http.Client{Timeout: time.Second}
	defer client.CloseIdleConnections()
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var response struct {
			Result struct {
				Info struct {
					Network string `json:"network"`
				} `json:"node_info"`
				Sync struct {
					Height string `json:"latest_block_height"`
				} `json:"sync_info"`
			} `json:"result"`
		}
		r, e := client.Get("http://127.0.0.1:26657/status")
		if e == nil {
			e = json.NewDecoder(r.Body).Decode(&response)
			r.Body.Close()
			if e == nil {
				if response.Result.Info.Network != "lqc-devnet-test-1" {
					return fmt.Errorf("wrong RPC chain")
				}
				height, parseErr := strconv.ParseInt(response.Result.Sync.Height, 10, 64)
				if parseErr != nil {
					return parseErr
				}
				if height >= target {
					fmt.Printf("RPC_TARGET height=%d target=%d\n", height, target)
					return checkRestartSockets()
				}
			}
		}
		time.Sleep(30 * time.Millisecond)
	}
}

func checkRestartSockets() error {
	output, err := exec.Command("ss", "-tanp").Output()
	if err != nil {
		return err
	}
	marker := fmt.Sprintf("pid=%d,", os.Getpid())
	listeners := 0
	for _, line := range strings.Split(string(output), "\n") {
		if !strings.Contains(line, marker) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 || !strings.HasPrefix(fields[3], "127.0.0.1:") || fields[0] != "LISTEN" && !strings.HasPrefix(fields[4], "127.0.0.1:") {
			return fmt.Errorf("nonlocal socket")
		}
		if fields[0] == "LISTEN" {
			listeners++
		}
		fmt.Println("SOCKET", line)
	}
	if listeners != 2 {
		return fmt.Errorf("expected exactly two loopback listeners")
	}
	return nil
}

type restartEvidence struct {
	Height                     int64
	Block1, Block11, PublicKey string
	Validators                 int
	Power, SignedHeight        int64
	Round                      int32
	Step                       int8
}

func readRestartEvidence(home string) (restartEvidence, error) {
	var result restartEvidence
	blocks, err := cmtdb.NewGoLevelDBWithOpts("blockstore", filepath.Join(home, "data"), &opt.Options{ReadOnly: true, ErrorIfMissing: true})
	if err != nil {
		return result, err
	}
	blockStore := cmtstore.NewBlockStore(blocks)
	defer blockStore.Close()
	states, err := cmtdb.NewGoLevelDBWithOpts("state", filepath.Join(home, "data"), &opt.Options{ReadOnly: true, ErrorIfMissing: true})
	if err != nil {
		return result, err
	}
	defer states.Close()
	state, err := cmtstate.NewStore(states, cmtstate.StoreOptions{}).Load()
	if err != nil {
		return result, err
	}
	if state.ChainID != "lqc-devnet-test-1" || state.Validators == nil || state.Validators.Size() != 1 {
		return result, fmt.Errorf("invalid persisted chain/validator set")
	}
	first, eleventh := blockStore.LoadBlock(1), blockStore.LoadBlock(11)
	if first == nil || eleventh == nil || blockStore.Height() != state.LastBlockHeight {
		return result, fmt.Errorf("historical block/height missing")
	}
	validator := state.Validators.Validators[0]
	raw, err := os.ReadFile(filepath.Join(home, "data/priv_validator_state.json"))
	if err != nil {
		return result, err
	}
	var signed privval.FilePVLastSignState
	if cmtjson.Unmarshal(raw, &signed) != nil || !validator.PubKey.VerifySignature(signed.SignBytes, signed.Signature) {
		return result, fmt.Errorf("invalid signing state")
	}
	if signed.Height < state.LastBlockHeight || signed.Height > state.LastBlockHeight+1 {
		return result, fmt.Errorf("signing height inconsistent")
	}
	result = restartEvidence{Height: state.LastBlockHeight, Block1: fmt.Sprintf("%X", first.Hash()), Block11: fmt.Sprintf("%X", eleventh.Hash()), PublicKey: hex.EncodeToString(validator.PubKey.Bytes()), Validators: 1, Power: validator.VotingPower, SignedHeight: signed.Height, Round: signed.Round, Step: signed.Step}
	return result, nil
}

func restartFileHashes(t *testing.T, home string) map[string][32]byte {
	t.Helper()
	hashes := make(map[string][32]byte)
	for _, name := range []string{"config/genesis.json", "config/priv_validator_key.json", "config/node_key.json"} {
		raw, err := os.ReadFile(filepath.Join(home, name))
		if err != nil {
			t.Fatal(err)
		}
		hashes[name] = sha256.Sum256(raw)
	}
	return hashes
}

func writeRestartEvidence(t *testing.T, root, name string, value restartEvidence) {
	t.Helper()
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, name), raw, 0600); err != nil {
		t.Fatal(err)
	}
}
