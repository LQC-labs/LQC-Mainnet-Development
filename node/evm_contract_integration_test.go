//go:build linux

// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0
package node

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime/pprof"
	"strings"
	"testing"
	"time"

	cmtlocal "github.com/cometbft/cometbft/rpc/client/local"
	evmtypes "github.com/cosmos/evm/x/vm/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

type contractTxEvidence struct {
	Hash          string                 `json:"hash"`
	Height        int64                  `json:"height"`
	NonceBefore   uint64                 `json:"nonce_before"`
	NonceAfter    uint64                 `json:"nonce_after"`
	BalanceBefore string                 `json:"balance_before"`
	BalanceAfter  string                 `json:"balance_after"`
	GasUsed       uint64                 `json:"gas_used"`
	Fee           string                 `json:"fee"`
	Receipt       map[string]interface{} `json:"receipt"`
}
type contractEvidence struct {
	Address      string                        `json:"address"`
	Runtime      string                        `json:"runtime"`
	Slot         string                        `json:"slot"`
	Value        string                        `json:"value"`
	Sender       string                        `json:"sender"`
	Transactions map[string]contractTxEvidence `json:"transactions"`
	Rejections   map[string]string             `json:"rejections"`
}

func TestEVMContractIntegration(t *testing.T) {
	if os.Getenv("LQC_RUN_EVM_CONTRACT") != "1" {
		t.Skip("explicit localhost contract integration opt-in required")
	}
	root, err := os.MkdirTemp(os.Getenv("LQC_CONTRACT_TEST_PARENT"), "lqc-evm-contract.")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("PRESERVED_CONTRACT_EVIDENCE=%s", root)
	home := filepath.Join(root, "home")
	invokeRestartChild(t, root, "prepare", "^TestAdmissionRuntimeChild$", []string{"LQC_ADMISSION_ROOT=" + root, "LQC_ADMISSION_STAGE=prepare"})
	keys := restartFileHashes(t, home)
	invokeRestartChild(t, root, "first", "^TestEVMContractRuntimeChild$", []string{"LQC_CONTRACT_ROOT=" + root, "LQC_CONTRACT_PHASE=first"})
	before, err := readRestartEvidence(home)
	if err != nil {
		t.Fatal(err)
	}
	writeRestartEvidence(t, root, "before.json", before)
	invokeRestartChild(t, root, "restart", "^TestEVMContractRuntimeChild$", []string{"LQC_CONTRACT_ROOT=" + root, "LQC_CONTRACT_PHASE=restart"})
	after, err := readRestartEvidence(home)
	if err != nil {
		t.Fatal(err)
	}
	writeRestartEvidence(t, root, "after.json", after)
	if before.Height < 15 || after.Height <= before.Height || before.Block1 != after.Block1 || before.Block11 != after.Block11 || before.PublicKey != after.PublicKey || before.Validators != 1 || after.Validators != 1 || before.Power != 1 || after.Power != 1 || after.SignedHeight < before.SignedHeight {
		t.Fatal("contract restart continuity failed")
	}
	for name, hash := range keys {
		if restartFileHashes(t, home)[name] != hash {
			t.Fatalf("key/Genesis changed: %s", name)
		}
	}
	t.Logf("CONTRACT_INTEGRATION_PASS height=%d->%d signing=%d->%d; code/storage/logs/receipts/validator/keys preserved", before.Height, after.Height, before.SignedHeight, after.SignedHeight)
}

func contractWord(value uint64) string { return fmt.Sprintf("0x%064x", value) }
func contractInput(signature string, word bool, value uint64) string {
	selector := hexutil.Encode(crypto.Keccak256([]byte(signature))[:4])
	if word {
		selector += strings.TrimPrefix(contractWord(value), "0x")
	}
	return selector
}
func contractQuery(t *testing.T, c *http.Client, rpc, from, to, input, block string) string {
	t.Helper()
	return evmRPCResult(t, c, rpc, "eth_call", []interface{}{map[string]interface{}{"from": from, "to": to, "data": input, "gas": "0x186a0"}, block})
}

func contractSubmit(t *testing.T, ctx context.Context, n *Node, c *http.Client, rpc string, tx *ethtypes.Transaction, status string) contractTxEvidence {
	t.Helper()
	sender, err := ethtypes.Sender(ethtypes.LatestSignerForChainID(big.NewInt(917001)), tx)
	if err != nil {
		t.Fatal(err)
	}
	before := nativeAmount(t, c, rpc, "eth_getBalance", sender.Hex(), "latest")
	nonce := nativeAmount(t, c, rpc, "eth_getTransactionCount", sender.Hex(), "latest").Uint64()
	if nonce != tx.Nonce() {
		t.Fatal("unexpected pre-transaction nonce")
	}
	raw, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	r := nativeRPC(t, c, rpc, "eth_sendRawTransaction", []interface{}{hexutil.Encode(raw)})
	if r.Error != nil {
		t.Fatalf("contract transaction rejected: %s", r.Error.Message)
	}
	var hash string
	if json.Unmarshal(r.Result, &hash) != nil || hash != tx.Hash().Hex() {
		t.Fatal("wrong contract transaction hash")
	}
	var receipt map[string]interface{}
	for {
		if ctx.Err() != nil {
			t.Fatal(ctx.Err())
		}
		receipt = nativeReceipt(t, c, rpc, hash)
		if receipt != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if receipt["status"] != status {
		t.Fatalf("receipt status=%v expected=%s", receipt["status"], status)
	}
	h := rpcHexHeight(t, fmt.Sprint(receipt["blockNumber"]))
	gas := uint64(rpcHexHeight(t, fmt.Sprint(receipt["gasUsed"])))
	price, ok := new(big.Int).SetString(strings.TrimPrefix(fmt.Sprint(receipt["effectiveGasPrice"]), "0x"), 16)
	if !ok || price.Sign() <= 0 || gas == 0 || gas > tx.Gas() || price.Cmp(tx.GasFeeCap()) > 0 {
		t.Fatal("invalid actual gas accounting")
	}
	fee := new(big.Int).Mul(new(big.Int).SetUint64(gas), price)
	block := fmt.Sprintf("0x%x", h)
	after := nativeAmount(t, c, rpc, "eth_getBalance", sender.Hex(), block)
	nonceAfter := nativeAmount(t, c, rpc, "eth_getTransactionCount", sender.Hex(), block).Uint64()
	spent := new(big.Int).Set(fee)
	if status == "0x1" {
		spent.Add(spent, tx.Value())
	}
	if after.Cmp(new(big.Int).Sub(before, spent)) != 0 || nonceAfter != nonce+1 {
		t.Fatal("contract fee/balance/nonce mismatch")
	}
	local := cmtlocal.New(n.node)
	actual, err := local.Block(ctx, &h)
	if err != nil {
		t.Fatal(err)
	}
	results, err := local.BlockResults(ctx, &h)
	if err != nil {
		t.Fatal(err)
	}
	index := int(rpcHexHeight(t, fmt.Sprint(receipt["transactionIndex"])))
	if index < 0 || index >= len(actual.Block.Txs) || index >= len(results.TxsResults) || results.TxsResults[index].Code != 0 || !strings.EqualFold(common.BytesToHash(actual.Block.Hash()).Hex(), fmt.Sprint(receipt["blockHash"])) {
		t.Fatal("contract receipt not backed by committed block")
	}
	decoded, err := n.application.SDK.GetTxConfig().TxDecoder()(actual.Block.Txs[index])
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, msg := range decoded.GetMsgs() {
		if evm, ok := msg.(*evmtypes.MsgEthereumTx); ok && evm.AsTransaction().Hash() == tx.Hash() {
			found = true
		}
	}
	if !found {
		t.Fatal("signed contract transaction absent from actual block")
	}
	// A VM revert is a valid Cosmos transaction with EVM receipt status 0.
	fmt.Printf("CONTRACT_TX hash=%s height=%d status=%s gas=%d effective_price=%s fee=%s nonce=%d->%d\n", hash, h, status, gas, price, fee, nonce, nonceAfter)
	return contractTxEvidence{hash, h, nonce, nonceAfter, before.String(), after.String(), gas, fee.String(), receipt}
}

func TestEVMContractRuntimeChild(t *testing.T) {
	root, phase := os.Getenv("LQC_CONTRACT_ROOT"), os.Getenv("LQC_CONTRACT_PHASE")
	if root == "" {
		t.Skip("contract integration child only")
	}
	n, err := Open(filepath.Join(root, "home"))
	if err != nil {
		t.Fatal(err)
	}
	defer admissionClose(t, n)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case <-finished:
			return
		case <-time.After(25 * time.Second):
			f, e := os.OpenFile(filepath.Join(root, phase+"-watchdog.stack"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if e == nil {
				pprof.Lookup("goroutine").WriteTo(f, 2)
				f.Close()
			}
		}
	}()
	previous := n.application.SDK.LastBlockHeight()
	if err = n.Start(ctx); err != nil {
		t.Fatal(err)
	}
	opts := RPCBrowserOptions{}
	if os.Getenv("LQC_RUN_RPC_EXPANSION") == "1" {
		opts.AllowedOrigins = []string{"http://localhost:3000"}
	}
	rpc, err := n.StartEVMRPCWithOptions(ctx, "127.0.0.1:0", opts)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("CONTRACT_RUNTIME pid=%d phase=%s previous=%d RPC=%s UTC=%s\n", os.Getpid(), phase, previous, rpc, time.Now().UTC().Format(time.RFC3339Nano))
	c := &http.Client{Timeout: 4 * time.Second}
	defer c.CloseIdleConnections()
	local := cmtlocal.New(n.node)
	for {
		s, e := local.Status(ctx)
		if e == nil && s.SyncInfo.LatestBlockHeight >= 2 && n.application.SDK.LastBlockHeight() >= 2 {
			break
		}
		if ctx.Err() != nil {
			t.Fatal(ctx.Err())
		}
		time.Sleep(25 * time.Millisecond)
	}
	if evmRPCResult(t, c, rpc, "eth_chainId", []interface{}{}) != "0xdfe09" {
		t.Fatal("wrong EVM chain ID")
	}
	height := func() int64 { return rpcHexHeight(t, evmRPCResult(t, c, rpc, "eth_blockNumber", []interface{}{})) }
	wait := func(target int64) {
		last := int64(-1)
		progress := time.Now()
		for {
			if ctx.Err() != nil {
				t.Fatal(ctx.Err())
			}
			h := height()
			if h >= target {
				return
			}
			if h != last {
				last = h
				progress = time.Now()
			}
			if time.Since(progress) > 5*time.Second {
				f, e := os.OpenFile(filepath.Join(root, phase+"-stalled.stack"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
				if e == nil {
					pprof.Lookup("goroutine").WriteTo(f, 2)
					f.Close()
				}
				t.Fatal("contract block progress stalled")
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	check := func(saved contractEvidence) {
		if os.Getenv("LQC_RUN_RPC_EXPANSION") == "1" {
			checkRPCExpansion(t, c, rpc, saved, root, phase)
		}
		if code := evmRPCResult(t, c, rpc, "eth_getCode", []interface{}{saved.Address, "latest"}); code != saved.Runtime {
			t.Fatal("deployed runtime bytecode mismatch")
		}
		if slot := evmRPCResult(t, c, rpc, "eth_getStorageAt", []interface{}{saved.Address, "0x0", "latest"}); slot != saved.Slot {
			t.Fatal("contract slot 0 mismatch")
		}
		if value := contractQuery(t, c, rpc, saved.Sender, saved.Address, contractInput("get()", false, 0), "latest"); value != saved.Value {
			t.Fatal("get() state mismatch")
		}
		for name, tx := range saved.Transactions {
			if receipt := nativeReceipt(t, c, rpc, tx.Hash); !reflect.DeepEqual(receipt, tx.Receipt) {
				t.Fatalf("receipt/logs changed: %s", name)
			}
		}
	}
	if phase == "restart" {
		raw, e := os.ReadFile(filepath.Join(root, "contract.json"))
		if e != nil {
			t.Fatal(e)
		}
		var saved contractEvidence
		if json.Unmarshal(raw, &saved) != nil {
			t.Fatal("invalid public contract evidence")
		}
		wait(previous + 3)
		check(saved)
		last := saved.Transactions["revert"]
		if nativeAmount(t, c, rpc, "eth_getBalance", saved.Sender, "latest").String() != last.BalanceAfter || nativeAmount(t, c, rpc, "eth_getTransactionCount", saved.Sender, "latest").Uint64() != last.NonceAfter {
			t.Fatal("contract account state lost on restart")
		}
		if e = os.WriteFile(filepath.Join(root, "restart-contract.json"), raw, 0600); e != nil {
			t.Fatal(e)
		}
		fmt.Printf("CONTRACT_RESTART_PASS height=%d->%d code/storage/logs/receipts and balance/nonce preserved\n", previous, height())
	} else {
		keyBytes, e := os.ReadFile(filepath.Join(root, "test-account.key"))
		if e != nil {
			t.Fatal("read TEST signer")
		}
		key, e := crypto.ToECDSA(keyBytes)
		if e != nil {
			t.Fatal("decode TEST signer")
		}
		sender := crypto.PubkeyToAddress(key.PublicKey)
		nonce := nativeAmount(t, c, rpc, "eth_getTransactionCount", sender.Hex(), "latest").Uint64()
		sign := func(chain *big.Int, nonce uint64, to *common.Address, data []byte, gas uint64) *ethtypes.Transaction {
			tx, e := ethtypes.SignNewTx(key, ethtypes.LatestSignerForChainID(chain), &ethtypes.DynamicFeeTx{ChainID: chain, Nonce: nonce, To: to, Data: data, Gas: gas, GasFeeCap: big.NewInt(2_000_000_000), GasTipCap: big.NewInt(1_000_000_000)})
			if e != nil {
				t.Fatal("sign TEST contract transaction")
			}
			return tx
		}
		creation, runtime := contractFixtureBytecode()
		deployed := contractSubmit(t, ctx, n, c, rpc, sign(big.NewInt(917001), nonce, nil, creation, 200000), "0x1")
		address := crypto.CreateAddress(sender, nonce)
		if !strings.EqualFold(fmt.Sprint(deployed.Receipt["contractAddress"]), address.Hex()) {
			t.Fatal("deployment contractAddress mismatch")
		}
		if code := evmRPCResult(t, c, rpc, "eth_getCode", []interface{}{address.Hex(), "latest"}); code != hexutil.Encode(runtime) {
			t.Fatal("deployed runtime mismatch")
		}
		if initial := contractQuery(t, c, rpc, sender.Hex(), address.Hex(), contractInput("get()", false, 0), "latest"); initial != contractWord(0) {
			t.Fatal("initial contract state nonzero")
		}
		setData := common.FromHex(contractInput("set(uint256)", true, 42))
		set := contractSubmit(t, ctx, n, c, rpc, sign(big.NewInt(917001), nonce+1, &address, setData, 80000), "0x1")
		logs, ok := set.Receipt["logs"].([]interface{})
		if !ok || len(logs) != 1 {
			t.Fatal("expected one ValueChanged event")
		}
		event, ok := logs[0].(map[string]interface{})
		if !ok {
			t.Fatal("invalid event")
		}
		topics, ok := event["topics"].([]interface{})
		if !ok || len(topics) != 1 || topics[0] != crypto.Keccak256Hash([]byte("ValueChanged(uint256)")).Hex() || event["data"] != contractWord(42) || !strings.EqualFold(fmt.Sprint(event["address"]), address.Hex()) || event["transactionHash"] != set.Hash || event["blockHash"] != set.Receipt["blockHash"] || event["blockNumber"] != set.Receipt["blockNumber"] {
			t.Fatal("event content/inclusion mismatch")
		}
		// eth_call of set(99) must simulate successfully without committing state,
		// consuming a nonce, or charging sender funds.
		if result := contractQuery(t, c, rpc, sender.Hex(), address.Hex(), contractInput("set(uint256)", true, 99), "latest"); result != "0x" {
			t.Fatal("set simulation returned unexpected data")
		}
		if contractQuery(t, c, rpc, sender.Hex(), address.Hex(), contractInput("get()", false, 0), "latest") != contractWord(42) || nativeAmount(t, c, rpc, "eth_getBalance", sender.Hex(), "latest").String() != set.BalanceAfter || nativeAmount(t, c, rpc, "eth_getTransactionCount", sender.Hex(), "latest").Uint64() != set.NonceAfter {
			t.Fatal("eth_call mutated committed state")
		}
		rejections := map[string]string{}
		reject := func(name string, tx *ethtypes.Transaction, reason string) {
			raw, e := tx.MarshalBinary()
			if e != nil {
				t.Fatal(e)
			}
			r := nativeRPC(t, c, rpc, "eth_sendRawTransaction", []interface{}{hexutil.Encode(raw)})
			if r.Error == nil || !strings.Contains(strings.ToLower(r.Error.Message), reason) {
				t.Fatalf("%s not safely rejected: %+v", name, r)
			}
			rejections[name] = r.Error.Message
		}
		reject("wrong_chain", sign(big.NewInt(917033), nonce+2, &address, setData, 80000), "chain")
		reject("duplicate_nonce", sign(big.NewInt(917001), nonce+1, &address, common.FromHex(contractInput("set(uint256)", true, 43)), 80000), "nonce")
		failData := common.FromHex(contractInput("fail()", false, 0))
		call := nativeRPC(t, c, rpc, "eth_call", []interface{}{map[string]interface{}{"from": sender.Hex(), "to": address.Hex(), "data": hexutil.Encode(failData), "gas": "0x186a0"}, "latest"})
		if call.Error == nil || !strings.Contains(strings.ToLower(call.Error.Message), "revert") {
			t.Fatal("reverting eth_call did not return execution error")
		}
		rejections["reverting_call"] = call.Error.Message
		reverted := contractSubmit(t, ctx, n, c, rpc, sign(big.NewInt(917001), nonce+2, &address, failData, 50000), "0x0")
		if failedLogs, ok := reverted.Receipt["logs"].([]interface{}); !ok || len(failedLogs) != 0 {
			t.Fatal("reverted execution retained logs")
		}
		saved := contractEvidence{address.Hex(), hexutil.Encode(runtime), contractWord(42), contractWord(42), sender.Hex(), map[string]contractTxEvidence{"deploy": deployed, "set": set, "revert": reverted}, rejections}
		check(saved)
		// Historical state must still show zero at deployment, then 42 at set.
		if contractQuery(t, c, rpc, sender.Hex(), address.Hex(), contractInput("get()", false, 0), fmt.Sprintf("0x%x", deployed.Height)) != contractWord(0) || contractQuery(t, c, rpc, sender.Hex(), address.Hex(), contractInput("get()", false, 0), fmt.Sprintf("0x%x", set.Height)) != contractWord(42) {
			t.Fatal("historical contract state mismatch")
		}
		wait(15)
		check(saved)
		raw, e := json.MarshalIndent(saved, "", "  ")
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(root, "contract.json"), raw, 0600); e != nil {
			t.Fatal(e)
		}
		fmt.Printf("CONTRACT_DEPLOY_SET_REVERT_PASS address=%s deploy=%s set=%s revert=%s value=42\n", address.Hex(), deployed.Hash, set.Hash, reverted.Hash)
	}
	out, e := exec.Command("ss", "-tanp").Output()
	if e != nil {
		t.Fatal(e)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, fmt.Sprintf("pid=%d,", os.Getpid())) {
			fields := strings.Fields(line)
			if len(fields) < 5 || !strings.HasPrefix(fields[3], "127.0.0.1:") || fields[0] != "LISTEN" && !strings.HasPrefix(fields[4], "127.0.0.1:") {
				t.Fatal("non-loopback socket")
			}
			fmt.Println("SOCKET", line)
		}
	}
}
