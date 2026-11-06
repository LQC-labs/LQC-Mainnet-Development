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
	"runtime/pprof"
	"strings"
	"testing"
	"time"

	cmtlocal "github.com/cometbft/cometbft/rpc/client/local"
	evmmempool "github.com/cosmos/evm/mempool"
	evmtypes "github.com/cosmos/evm/x/vm/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// Explicit opt-in only. Preparation and both node lifecycles are independent
// processes. All keys, DBs and public evidence remain in a NEW Linux directory.
func TestNativeEVMTransactionIntegration(t *testing.T) {
	if os.Getenv("LQC_RUN_NATIVE_EVM") != "1" {
		t.Skip("explicit localhost integration opt-in required")
	}
	root, err := os.MkdirTemp(os.Getenv("LQC_NATIVE_TEST_PARENT"), "lqc-native-evm.")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	t.Logf("PRESERVED_NATIVE_EVM_EVIDENCE=%s", root)
	home := filepath.Join(root, "home")
	invokeRestartChild(t, root, "prepare", "^TestAdmissionRuntimeChild$", []string{"LQC_ADMISSION_ROOT=" + root, "LQC_ADMISSION_STAGE=prepare"})
	initial := restartFileHashes(t, home)
	invokeRestartChild(t, root, "first", "^TestNativeEVMRuntimeChild$", []string{"LQC_NATIVE_ROOT=" + root, "LQC_NATIVE_PHASE=first"})
	before, err := readRestartEvidence(home)
	if err != nil {
		t.Fatal(err)
	}
	writeRestartEvidence(t, root, "before.json", before)
	invokeRestartChild(t, root, "restart", "^TestNativeEVMRuntimeChild$", []string{"LQC_NATIVE_ROOT=" + root, "LQC_NATIVE_PHASE=restart"})
	after, err := readRestartEvidence(home)
	if err != nil {
		t.Fatal(err)
	}
	writeRestartEvidence(t, root, "after.json", after)
	if before.Height < 15 || after.Height <= before.Height || before.Block1 != after.Block1 || before.Block11 != after.Block11 || before.PublicKey != after.PublicKey || before.Validators != 1 || after.Validators != 1 || before.Power != 1 || after.Power != 1 || after.SignedHeight < before.SignedHeight {
		t.Fatal("EVM restart continuity failed")
	}
	for name, hash := range initial {
		if restartFileHashes(t, home)[name] != hash {
			t.Fatalf("Genesis/key changed: %s", name)
		}
	}
	t.Logf("NATIVE_EVM_INTEGRATION_PASS height=%d->%d signing=%d->%d; Genesis, keys, validator and historical block hashes preserved", before.Height, after.Height, before.SignedHeight, after.SignedHeight)
}

type nativeEVMEvidence struct {
	Hash              string                 `json:"hash"`
	Sender            string                 `json:"sender"`
	Recipient         string                 `json:"recipient"`
	BeforeHeight      int64                  `json:"before_height"`
	BlockHeight       int64                  `json:"block_height"`
	SenderBefore      string                 `json:"sender_before"`
	SenderAfter       string                 `json:"sender_after"`
	RecipientBefore   string                 `json:"recipient_before"`
	RecipientAfter    string                 `json:"recipient_after"`
	NonceBefore       uint64                 `json:"nonce_before"`
	NonceAfter        uint64                 `json:"nonce_after"`
	Value             string                 `json:"value"`
	GasUsed           uint64                 `json:"gas_used"`
	EffectiveGasPrice string                 `json:"effective_gas_price"`
	Fee               string                 `json:"fee"`
	Receipt           map[string]interface{} `json:"receipt"`
	Rejections        map[string]string      `json:"rejections"`
}

func nativeRPC(t *testing.T, c *http.Client, address, method string, params interface{}) evmRPCResponse {
	t.Helper()
	raw, err := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	if err != nil {
		t.Fatal(err)
	}
	r, err := c.Post("http://"+address+"/", "application/json", strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	var response evmRPCResponse
	if err = json.NewDecoder(r.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	// Public response only: never log private key bytes or caller raw envelope.
	encoded, _ := json.Marshal(response)
	fmt.Printf("NATIVE_RPC method=%s response=%s\n", method, encoded)
	return response
}

func nativeReceipt(t *testing.T, c *http.Client, address, hash string) map[string]interface{} {
	t.Helper()
	r := nativeRPC(t, c, address, "eth_getTransactionReceipt", []interface{}{hash})
	if r.Error != nil {
		t.Fatalf("receipt error: %s", r.Error.Message)
	}
	if string(r.Result) == "null" {
		return nil
	}
	var receipt map[string]interface{}
	if json.Unmarshal(r.Result, &receipt) != nil {
		t.Fatal("invalid receipt")
	}
	return receipt
}

func nativeAmount(t *testing.T, c *http.Client, address, method, account, block string) *big.Int {
	t.Helper()
	value := evmRPCResult(t, c, address, method, []interface{}{account, block})
	n, ok := new(big.Int).SetString(strings.TrimPrefix(value, "0x"), 16)
	if !ok {
		t.Fatal("invalid RPC quantity")
	}
	return n
}

func TestNativeEVMRuntimeChild(t *testing.T) {
	root, phase := os.Getenv("LQC_NATIVE_ROOT"), os.Getenv("LQC_NATIVE_PHASE")
	if root == "" {
		t.Skip("integration child only")
	}
	home := filepath.Join(root, "home")
	n, err := Open(home)
	if err != nil {
		t.Fatal(err)
	}
	defer admissionClose(t, n)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	// Independent watchdog records stack evidence even if a consensus/RPC call
	// blocks before the progress loop can run. It never alters clock or state.
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
	rpc, err := n.StartEVMRPC(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("NATIVE_RUNTIME pid=%d phase=%s previous=%d UTC=%s RPC=%s\n", os.Getpid(), phase, previous, time.Now().UTC().Format(time.RFC3339Nano), rpc)
	c := &http.Client{Timeout: 4 * time.Second}
	defer c.CloseIdleConnections()
	height := func() int64 { return rpcHexHeight(t, evmRPCResult(t, c, rpc, "eth_blockNumber", []interface{}{})) }
	waitHeight := func(target int64) {
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
				pool := n.application.SDK.EVMMempool.(*evmmempool.Mempool)
				fmt.Printf("STALL sdk=%d evm_head=%s\n", n.application.SDK.LastBlockHeight(), pool.GetBlockchain().CurrentBlock().Number)
				f, e := os.Create(filepath.Join(root, phase+"-stalled.stack"))
				if e == nil {
					pprof.Lookup("goroutine").WriteTo(f, 2)
					f.Close()
				}
				t.Fatal("block progress stalled")
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	// BlockNumber may report not-ready before first Commit. Wait via Comet.
	local := cmtlocal.New(n.node)
	for {
		status, e := local.Status(ctx)
		if e == nil && status.SyncInfo.LatestBlockHeight >= 2 && n.application.SDK.LastBlockHeight() >= 2 {
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
	if phase == "restart" {
		raw, e := os.ReadFile(filepath.Join(root, "transaction.json"))
		if e != nil {
			t.Fatal(e)
		}
		var saved nativeEVMEvidence
		if json.Unmarshal(raw, &saved) != nil {
			t.Fatal("invalid saved public evidence")
		}
		waitHeight(previous + 3)
		receipt := nativeReceipt(t, c, rpc, saved.Hash)
		if receipt == nil {
			t.Fatal("receipt lost on restart")
		}
		for _, field := range []string{"transactionHash", "blockHash", "blockNumber", "status", "from", "to", "gasUsed", "effectiveGasPrice"} {
			if fmt.Sprint(receipt[field]) != fmt.Sprint(saved.Receipt[field]) {
				t.Fatalf("receipt field changed: %s", field)
			}
		}
		block := fmt.Sprintf("0x%x", saved.BlockHeight)
		if nativeAmount(t, c, rpc, "eth_getBalance", saved.Sender, block).String() != saved.SenderAfter || nativeAmount(t, c, rpc, "eth_getBalance", saved.Recipient, block).String() != saved.RecipientAfter || nativeAmount(t, c, rpc, "eth_getTransactionCount", saved.Sender, "latest").Uint64() != saved.NonceAfter {
			t.Fatal("committed EVM state lost")
		}
		fmt.Printf("NATIVE_RESTART_PASS height=%d->%d tx=%s receipt_status=%v\n", previous, height(), saved.Hash, receipt["status"])
	} else {
		keyBytes, e := os.ReadFile(filepath.Join(root, "test-account.key"))
		if e != nil {
			t.Fatal("read disposable TEST signer")
		}
		key, e := crypto.ToECDSA(keyBytes)
		if e != nil {
			t.Fatal("decode disposable TEST signer")
		}
		sender := crypto.PubkeyToAddress(key.PublicKey)
		recipient := common.HexToAddress("0x1000000000000000000000000000000000000001")
		beforeHeight := height()
		block := fmt.Sprintf("0x%x", beforeHeight)
		sb := nativeAmount(t, c, rpc, "eth_getBalance", sender.Hex(), block)
		rb := nativeAmount(t, c, rpc, "eth_getBalance", recipient.Hex(), block)
		nonce := nativeAmount(t, c, rpc, "eth_getTransactionCount", sender.Hex(), block).Uint64()
		value := big.NewInt(1_000_000_000_000_000)
		sign := func(chain *big.Int, n uint64, v *big.Int) *ethtypes.Transaction {
			tx, e := ethtypes.SignNewTx(key, ethtypes.LatestSignerForChainID(chain), &ethtypes.DynamicFeeTx{ChainID: chain, Nonce: n, To: &recipient, Value: v, Gas: 21000, GasFeeCap: big.NewInt(2_000_000_000), GasTipCap: big.NewInt(1_000_000_000)})
			if e != nil {
				t.Fatal("sign TEST EVM envelope")
			}
			return tx
		}
		send := func(tx *ethtypes.Transaction) evmRPCResponse {
			raw, e := tx.MarshalBinary()
			if e != nil {
				t.Fatal(e)
			}
			return nativeRPC(t, c, rpc, "eth_sendRawTransaction", []interface{}{hexutil.Encode(raw)})
		}
		rejections := map[string]string{}
		rejected := map[string]string{}
		reject := func(name string, tx *ethtypes.Transaction, reason string) {
			r := send(tx)
			if r.Error == nil || !strings.Contains(strings.ToLower(r.Error.Message), reason) {
				t.Fatalf("%s not rejected for %s: %+v", name, reason, r)
			}
			rejections[name] = r.Error.Message
			rejected[name] = tx.Hash().Hex()
		}
		reject("wrong_chain", sign(big.NewInt(917033), nonce, value), "chain")
		badSignature := ethtypes.NewTx(&ethtypes.DynamicFeeTx{ChainID: big.NewInt(917001), Nonce: nonce, To: &recipient, Value: value, Gas: 21000, GasFeeCap: big.NewInt(2_000_000_000), GasTipCap: big.NewInt(1_000_000_000)})
		reject("bad_signature", badSignature, "signature")
		reject("insufficient_balance", sign(big.NewInt(917001), nonce, new(big.Int).Mul(sb, big.NewInt(100))), "insufficient")
		valid := sign(big.NewInt(917001), nonce, value)
		r := send(valid)
		if r.Error != nil {
			t.Fatalf("valid EVM admission failed: %s", r.Error.Message)
		}
		var hash string
		if json.Unmarshal(r.Result, &hash) != nil || hash != valid.Hash().Hex() {
			t.Fatal("wrong accepted transaction hash")
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
		if receipt["status"] != "0x1" || !strings.EqualFold(fmt.Sprint(receipt["from"]), sender.Hex()) || !strings.EqualFold(fmt.Sprint(receipt["to"]), recipient.Hex()) || receipt["transactionHash"] != hash {
			t.Fatalf("failed/mismatched receipt: %+v", receipt)
		}
		h := rpcHexHeight(t, fmt.Sprint(receipt["blockNumber"]))
		gas := uint64(rpcHexHeight(t, fmt.Sprint(receipt["gasUsed"])))
		price, ok := new(big.Int).SetString(strings.TrimPrefix(fmt.Sprint(receipt["effectiveGasPrice"]), "0x"), 16)
		if !ok || gas != 21000 || price.Sign() <= 0 {
			t.Fatal("invalid actual gas accounting")
		}
		fee := new(big.Int).Mul(new(big.Int).SetUint64(gas), price)
		block = fmt.Sprintf("0x%x", h)
		sa := nativeAmount(t, c, rpc, "eth_getBalance", sender.Hex(), block)
		ra := nativeAmount(t, c, rpc, "eth_getBalance", recipient.Hex(), block)
		na := nativeAmount(t, c, rpc, "eth_getTransactionCount", sender.Hex(), block).Uint64()
		if sa.Cmp(new(big.Int).Sub(new(big.Int).Sub(new(big.Int).Set(sb), value), fee)) != 0 || ra.Cmp(new(big.Int).Add(rb, value)) != 0 || na != nonce+1 {
			t.Fatalf("state/fee mismatch sender=%s->%s receiver=%s->%s nonce=%d->%d fee=%s", sb, sa, rb, ra, nonce, na, fee)
		}
		actual, e := local.Block(ctx, &h)
		if e != nil {
			t.Fatal(e)
		}
		results, e := local.BlockResults(ctx, &h)
		if e != nil {
			t.Fatal(e)
		}
		index := int(rpcHexHeight(t, fmt.Sprint(receipt["transactionIndex"])))
		if index >= len(actual.Block.Txs) || index >= len(results.TxsResults) || results.TxsResults[index].Code != 0 || !strings.EqualFold(common.BytesToHash(actual.Block.Hash()).Hex(), fmt.Sprint(receipt["blockHash"])) {
			t.Fatal("receipt not backed by successful committed block")
		}
		decoded, e := n.application.SDK.GetTxConfig().TxDecoder()(actual.Block.Txs[index])
		if e != nil {
			t.Fatal(e)
		}
		found := false
		for _, msg := range decoded.GetMsgs() {
			if evm, ok := msg.(*evmtypes.MsgEthereumTx); ok && evm.AsTransaction().Hash() == valid.Hash() {
				found = true
			}
		}
		if !found {
			t.Fatal("signed EVM transaction absent from actual block")
		}
		reject("duplicate_nonce", sign(big.NewInt(917001), nonce, new(big.Int).Add(value, big.NewInt(1))), "nonce")
		waitHeight(15)
		for name, hash := range rejected {
			if nativeReceipt(t, c, rpc, hash) != nil {
				t.Fatalf("rejected %s has receipt", name)
			}
		}
		if nativeReceipt(t, c, rpc, common.Hash{}.Hex()) != nil {
			t.Fatal("unknown hash has receipt")
		}
		evidence := nativeEVMEvidence{hash, sender.Hex(), recipient.Hex(), beforeHeight, h, sb.String(), sa.String(), rb.String(), ra.String(), nonce, na, value.String(), gas, price.String(), fee.String(), receipt, rejections}
		raw, e := json.MarshalIndent(evidence, "", "  ")
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(root, "transaction.json"), raw, 0600); e != nil {
			t.Fatal(e)
		}
		fmt.Printf("NATIVE_TRANSFER_PASS hash=%s block=%d status=1 value=%s gas=%d gas_price=%s fee=%s nonce=%d->%d\n", hash, h, value, gas, price, fee, nonce, na)
	}
	// Inspect all process-owned TCP sockets, not just configured addresses.
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
