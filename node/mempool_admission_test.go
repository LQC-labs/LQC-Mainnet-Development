//go:build linux

// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0
package node

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"cosmossdk.io/log/v2"
	"github.com/LQC-labs/LQC-Mainnet-Development/app"
	"github.com/LQC-labs/LQC-Mainnet-Development/genesis"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/client/tx"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/cosmos/evm/crypto/ethsecp256k1"
	evmmempool "github.com/cosmos/evm/mempool"
	"golang.org/x/sys/unix"
)

// Opt-in only: creates and retains a NEW home; never starts an existing fixture.
// Each lifecycle phase is a separate process (including the pending reopen).
func TestPersistentMempoolAdmissionAndRestart(t *testing.T) {
	if os.Getenv("LQC_RUN_ADMISSION_REGRESSION") != "1" {
		t.Skip("explicit localhost integration opt-in required")
	}
	root, err := os.MkdirTemp("/tmp", "lqc-admission-regression.")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("PRESERVED_ADMISSION_EVIDENCE=%s", root)
	home := filepath.Join(root, "home")
	invoke := func(stage string) {
		invokeRestartChild(t, root, stage, "^TestAdmissionRuntimeChild$", []string{"LQC_ADMISSION_ROOT=" + root, "LQC_ADMISSION_STAGE=" + stage})
	}
	invoke("prepare")
	initial := restartFileHashes(t, home)
	invoke("first")
	before, err := readRestartEvidence(home)
	if err != nil {
		t.Fatal(err)
	}
	writeRestartEvidence(t, root, "before.json", before)
	invoke("insert")
	invoke("restart")
	invoke("verify")
	after, err := readRestartEvidence(home)
	if err != nil {
		t.Fatal(err)
	}
	writeRestartEvidence(t, root, "after.json", after)
	if before.Height != 11 || after.Height < 13 || before.Block1 != after.Block1 || before.Block11 != after.Block11 || before.PublicKey != after.PublicKey || after.Validators != 1 || after.Power != 1 || after.SignedHeight < before.SignedHeight {
		t.Fatal("chain/validator/signing continuity failed")
	}
	for name, hash := range initial {
		if restartFileHashes(t, home)[name] != hash {
			t.Fatalf("key or Genesis changed: %s", name)
		}
	}
	t.Logf("ADMISSION_AND_RESUBMISSION_PASS height=%d->%d signing=%d->%d; automatic pending retention UNSUPPORTED (observed 1->0); exact signed tx resubmitted and committed", before.Height, after.Height, before.SignedHeight, after.SignedHeight)
}

func admissionClose(t *testing.T, n *Node) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- n.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Close deadline")
	}
	fd, err := openDevnetHome(n.home)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal("home lock leaked")
	}
	unix.Flock(fd, unix.LOCK_UN)
	fmt.Println("NORMAL_CLOSE_AND_LOCK_RELEASE_PASS")
}

func TestAdmissionRuntimeChild(t *testing.T) {
	root, stage := os.Getenv("LQC_ADMISSION_ROOT"), os.Getenv("LQC_ADMISSION_STAGE")
	if root == "" || stage == "" {
		t.Skip("integration child only")
	}
	home := filepath.Join(root, "home")
	if stage == "prepare" {
		if err := CreateHome(home); err != nil {
			t.Fatal(err)
		}
		fd, err := openDevnetHome(home)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd)
		public, err := loadDevnetKeys(fd)
		if err != nil {
			t.Fatal(err)
		}
		signer, err := ethsecp256k1.GenerateKey()
		if err != nil {
			t.Fatal("generate TEST signer")
		}
		f, err := os.OpenFile(filepath.Join(root, "test-account.key"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.Write(signer.Bytes())
		ce := f.Close()
		if err != nil || ce != nil {
			t.Fatal("store private TEST signer")
		}
		a, err := app.New(log.NewNopLogger(), dbm.NewMemDB(), t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer a.Close()
		raw, err := genesis.NewSingleValidator(a, signer, public)
		if err != nil {
			t.Fatal(err)
		}
		config, err := unix.Openat(fd, "config", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(config)
		if err = writePrivateFile(config, "genesis.json", raw); err != nil {
			t.Fatal(err)
		}
		return
	}
	if stage == "first" {
		if err := runRestartChild(home, 11); err != nil {
			t.Fatal(err)
		}
		return
	}
	n, err := Open(home)
	if err != nil {
		t.Fatal(err)
	}
	defer admissionClose(t, n)
	a := n.application.SDK
	pool := a.EVMMempool.(*evmmempool.Mempool)
	rawKey, err := os.ReadFile(filepath.Join(root, "test-account.key"))
	if err != nil {
		t.Fatal("read TEST signer")
	}
	signer := &ethsecp256k1.PrivKey{Key: rawKey}
	address := sdk.AccAddress(signer.PubKey().Address())
	query, err := a.CreateQueryContext(a.LastBlockHeight(), false)
	if err != nil {
		t.Fatal(err)
	}
	account := a.AccountKeeper.GetAccount(query, address)
	if account == nil {
		t.Fatal("funded account missing")
	}
	insert := func(transaction sdk.Tx) error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return pool.Insert(ctx, transaction)
	}
	if stage == "insert" {
		if a.LastBlockHeight() != 11 || pool.CountTx() != 0 {
			t.Fatal("expected empty pool at height 11")
		}
		sequence := account.GetSequence()
		signed := func(seq uint64, corrupt bool) sdk.Tx {
			builder := a.GetTxConfig().NewTxBuilder()
			if err := builder.SetMsgs(banktypes.NewMsgSend(address, address, sdk.NewCoins(sdk.NewInt64Coin("atest", 1)))); err != nil {
				t.Fatal(err)
			}
			builder.SetGasLimit(200000)
			builder.SetFeeAmount(sdk.NewCoins(sdk.NewInt64Coin("atest", 2000000000000000)))
			sig := signing.SignatureV2{PubKey: signer.PubKey(), Sequence: seq, Data: &signing.SingleSignatureData{SignMode: signing.SignMode_SIGN_MODE_DIRECT}}
			if err := builder.SetSignatures(sig); err != nil {
				t.Fatal(err)
			}
			sig, err = tx.SignWithPrivKey(context.Background(), signing.SignMode_SIGN_MODE_DIRECT, authsigning.SignerData{Address: address.String(), ChainID: "lqc-devnet-test-1", AccountNumber: account.GetAccountNumber(), Sequence: seq, PubKey: signer.PubKey()}, builder, signer, a.GetTxConfig(), seq)
			if err != nil {
				t.Fatal("sign TEST transaction")
			}
			if corrupt {
				sig.Data.(*signing.SingleSignatureData).Signature[0] ^= 0xff
			}
			if err = builder.SetSignatures(sig); err != nil {
				t.Fatal(err)
			}
			return builder.GetTx()
		}
		valid := signed(sequence, false)
		if err = insert(valid); err != nil {
			t.Fatalf("valid signed admission: %v", err)
		}
		if pool.CountTx() != 1 {
			t.Fatal("valid transaction not pending")
		}
		if err = insert(signed(sequence+1, true)); err == nil {
			t.Fatal("bad signature accepted")
		}
		fmt.Println("BAD_SIGNATURE_REJECTED", err)
		if err = insert(valid); err == nil {
			t.Fatal("duplicate accepted")
		}
		fmt.Println("DUPLICATE_REJECTED", err)
		full := 0
		for i := 0; i < 8192; i++ {
			e := pool.InsertAsync(valid)
			if errors.Is(e, evmmempool.ErrQueueFull) {
				full++
			} else if e != nil && !errors.Is(e, sdkerrors.ErrWrongSequence) {
				t.Fatalf("unexpected flood rejection: %v", e)
			}
		}
		if full == 0 {
			t.Fatal("queue overload did not exercise queue-full rejection")
		}
		// FIFO synchronous duplicate drains previously accepted queue entries.
		deadline := time.Now().Add(10 * time.Second)
		for {
			e := insert(valid)
			if !errors.Is(e, evmmempool.ErrQueueFull) {
				if e == nil {
					t.Fatal("duplicate accepted after flood")
				}
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("queue did not drain")
			}
			time.Sleep(time.Millisecond)
		}
		if pool.CountTx() != 1 {
			t.Fatal("rejected transactions changed pool")
		}
		encoded, err := a.GetTxConfig().TxJSONEncoder()(valid)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(root, "signed-tx.json"), encoded, 0600); err != nil {
			t.Fatal(err)
		}
		evidence := map[string]interface{}{"height": a.LastBlockHeight(), "sequence": sequence, "pending_count": pool.CountTx(), "queue_capacity": app.PersistentInsertQueueCapacity, "queue_full_rejections": full}
		raw, _ := json.MarshalIndent(evidence, "", "  ")
		if err = os.WriteFile(filepath.Join(root, "pending-before.json"), raw, 0600); err != nil {
			t.Fatal(err)
		}
		fmt.Printf("SIGNED_ADMISSION_PASS pending=1 height=11 queue_full_rejections=%d; consensus intentionally stopped\n", full)
		return
	}
	raw, err := os.ReadFile(filepath.Join(root, "pending-before.json"))
	if err != nil {
		t.Fatal(err)
	}
	var before struct {
		Height   int64  `json:"height"`
		Sequence uint64 `json:"sequence"`
	}
	if json.Unmarshal(raw, &before) != nil {
		t.Fatal("bad evidence")
	}
	if stage == "verify" {
		if a.LastBlockHeight() < 13 || account.GetSequence() != before.Sequence+1 || pool.CountTx() != 0 {
			t.Fatal("resubmitted transaction did not commit exactly once")
		}
		fmt.Printf("COMMITTED_SEQUENCE_PASS height=%d sequence=%d pending=0\n", a.LastBlockHeight(), account.GetSequence())
		return
	}
	if stage != "restart" {
		t.Fatal("unknown stage")
	}
	if a.LastBlockHeight() != before.Height || account.GetSequence() != before.Sequence {
		t.Fatal("uncommitted transaction changed persistent state")
	}
	observed := pool.CountTx()
	raw, _ = json.MarshalIndent(map[string]interface{}{"before_count": 1, "after_count": observed, "committed_height": a.LastBlockHeight(), "sequence_unchanged": true, "automatic_retention": "unsupported by upstream in-memory Cosmos mempool"}, "", "  ")
	if err = os.WriteFile(filepath.Join(root, "pending-after.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if observed != 0 {
		t.Fatalf("unexpected upstream persistence: inspect instead of assuming unsupported; count=%d", observed)
	}
	fmt.Println("AUTOMATIC_PENDING_RETENTION_UNSUPPORTED observed=1->0; committed height and sequence preserved")
	raw, err = os.ReadFile(filepath.Join(root, "signed-tx.json"))
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := a.GetTxConfig().TxJSONDecoder()(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err = insert(transaction); err != nil {
		t.Fatalf("exact signed tx resubmission: %v", err)
	}
	binary, err := a.GetTxConfig().TxEncoder()(transaction)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(binary)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	if err = n.Start(ctx); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: time.Second}
	defer client.CloseIdleConnections()
	var finalHeight int64
	for {
		if ctx.Err() != nil {
			t.Fatal(ctx.Err())
		}
		response, e := client.Get("http://127.0.0.1:26657/status")
		if e == nil {
			var status struct {
				Result struct {
					Sync struct {
						Height string `json:"latest_block_height"`
					} `json:"sync_info"`
				} `json:"result"`
			}
			e = json.NewDecoder(response.Body).Decode(&status)
			response.Body.Close()
			h, _ := strconv.ParseInt(status.Result.Sync.Height, 10, 64)
			if e == nil && h >= 13 {
				if err = checkRestartSockets(); err != nil {
					t.Fatal(err)
				}
				fmt.Printf("RESUBMITTED_NODE_HEIGHT=%d TX_HASH=%X\n", h, hash)
				finalHeight = h
				break
			}
		}
		time.Sleep(30 * time.Millisecond)
	}
	matches := 0
	for h := int64(12); h <= finalHeight; h++ {
		response, e := client.Get(fmt.Sprintf("http://127.0.0.1:26657/block?height=%d", h))
		if e != nil {
			t.Fatal(e)
		}
		var block struct {
			Result struct {
				Block struct {
					Data struct {
						Txs [][]byte `json:"txs"`
					} `json:"data"`
				} `json:"block"`
			} `json:"result"`
		}
		e = json.NewDecoder(response.Body).Decode(&block)
		response.Body.Close()
		if e != nil {
			t.Fatal(e)
		}
		for _, raw := range block.Result.Block.Data.Txs {
			if bytes.Equal(raw, binary) {
				matches++
				fmt.Printf("EXACT_SIGNED_TX_IN_BLOCK height=%d hash=%X\n", h, hash)
			}
		}
	}
	if matches != 1 {
		t.Fatalf("exact signed transaction must appear once in committed blocks; found %d", matches)
	}
}
