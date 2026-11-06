//go:build linux

// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0
package node

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/pprof"
	"strconv"
	"strings"
	"testing"
	"time"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/ethereum/go-ethereum/common"
)

func TestEVMRPCPreflight(t *testing.T) {
	for _, address := range []string{"0.0.0.0:8545", ":8545", "localhost:8545", "[::]:8545", "192.168.1.1:8545", "127.0.0.1:-1", "127.0.0.1:65536", "127.0.0.1:not-a-port"} {
		if validateEVMRPCAddress(address) == nil {
			t.Fatalf("unsafe address accepted: %s", address)
		}
	}
	if err := validateEVMRPCAddress("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	good := big.NewInt(917001)
	if err := validateEVMRPCIdentity("lqc-devnet-test-1", 917001, good); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []struct {
		cosmos  string
		evm     uint64
		runtime *big.Int
	}{{"wrong-chain", 917001, good}, {"lqc-devnet-test-1", 1, good}, {"lqc-devnet-test-1", 917001, big.NewInt(1)}, {"lqc-devnet-test-1", 917001, nil}} {
		if validateEVMRPCIdentity(bad.cosmos, bad.evm, bad.runtime) == nil {
			t.Fatal("wrong chain identity accepted")
		}
	}
	n := &Node{}
	if _, err := n.StartEVMRPC(context.Background(), "127.0.0.1:0"); err == nil {
		t.Fatal("unstarted node accepted")
	}
	if _, err := n.StartEVMRPC(nil, "127.0.0.1:0"); err == nil {
		t.Fatal("nil context accepted")
	}
}

// Explicit opt-in only: retains a NEW home and runs node/RPC in independent
// processes before and after shutdown. Ordinary go test never starts a node.
func TestEVMRPCPersistentIntegration(t *testing.T) {
	if os.Getenv("LQC_RUN_EVMRPC_INTEGRATION") != "1" {
		t.Skip("explicit localhost node/RPC opt-in required")
	}
	root, err := os.MkdirTemp("/tmp", "lqc-evmrpc-integration.")
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "home")
	t.Logf("PRESERVED_EVMRPC_EVIDENCE=%s", root)
	invokeRestartChild(t, root, "prepare", "^TestNodeFixture$", []string{"LQC_NODE_FIXTURE_HOME=" + home})
	initial := restartFileHashes(t, home)
	invokeRestartChild(t, root, "first", "^TestEVMRPCRuntimeChild$", []string{"LQC_EVMRPC_HOME=" + home, "LQC_EVMRPC_ROOT=" + root, "LQC_EVMRPC_STAGE=first"})
	before, err := readRestartEvidence(home)
	if err != nil {
		t.Fatal(err)
	}
	writeRestartEvidence(t, root, "before.json", before)
	invokeRestartChild(t, root, "restart", "^TestEVMRPCRuntimeChild$", []string{"LQC_EVMRPC_HOME=" + home, "LQC_EVMRPC_ROOT=" + root, "LQC_EVMRPC_STAGE=restart"})
	after, err := readRestartEvidence(home)
	if err != nil {
		t.Fatal(err)
	}
	writeRestartEvidence(t, root, "after.json", after)
	if after.Height <= before.Height || before.Block1 != after.Block1 || before.Block11 != after.Block11 || before.PublicKey != after.PublicKey || after.Validators != 1 || after.Power != 1 || after.SignedHeight < before.SignedHeight {
		t.Fatal("restart continuity failed")
	}
	for name, hash := range initial {
		if restartFileHashes(t, home)[name] != hash {
			t.Fatalf("Genesis/key changed: %s", name)
		}
	}
	t.Logf("EVMRPC_INTEGRATION_PASS heights=%d->%d signing=%d->%d; historical blocks, keys and validator unchanged", before.Height, after.Height, before.SignedHeight, after.SignedHeight)
}

type evmRPCResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func evmRPCCall(t *testing.T, client *http.Client, address, payload string) evmRPCResponse {
	t.Helper()
	response, err := client.Post("http://"+address+"/", "application/json", strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024))
	if err != nil {
		t.Fatal(err)
	}
	var result evmRPCResponse
	if err = json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("RPC response invalid: status=%d body=%s", response.StatusCode, raw)
	}
	fmt.Printf("RPC request=%s response=%s\n", payload, bytes.TrimSpace(raw))
	return result
}
func evmRPCResult(t *testing.T, client *http.Client, address, method string, params interface{}) string {
	t.Helper()
	raw, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	response := evmRPCCall(t, client, address, string(raw))
	if response.Error != nil {
		t.Fatalf("%s: code=%d %s", method, response.Error.Code, response.Error.Message)
	}
	var value string
	if json.Unmarshal(response.Result, &value) != nil {
		t.Fatalf("%s did not return string", method)
	}
	return value
}
func rpcHexHeight(t *testing.T, value string) int64 {
	t.Helper()
	number, err := strconv.ParseInt(strings.TrimPrefix(value, "0x"), 16, 64)
	if err != nil {
		t.Fatal(err)
	}
	return number
}

func TestEVMRPCRuntimeChild(t *testing.T) {
	home, root, stage := os.Getenv("LQC_EVMRPC_HOME"), os.Getenv("LQC_EVMRPC_ROOT"), os.Getenv("LQC_EVMRPC_STAGE")
	if home == "" {
		t.Skip("integration child only")
	}
	n, err := Open(home)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	var rpcAddress string
	var rpcCancel context.CancelFunc
	defer func() {
		admissionClose(t, n)
		if rpcCancel != nil {
			rpcCancel()
		}
		if rpcAddress != "" {
			listener, err := net.Listen("tcp4", rpcAddress)
			if err != nil {
				t.Fatal("RPC listener leaked")
			}
			listener.Close()
		}
	}()
	previousHeight := n.application.SDK.LastBlockHeight()
	if err = n.Start(ctx); err != nil {
		t.Fatal(err)
	}
	occupied, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, err = n.StartEVMRPC(ctx, occupied.Addr().String())
	occupied.Close()
	if err == nil {
		t.Fatal("occupied RPC port accepted")
	}
	rpcCtx, rpcCancel := context.WithCancel(ctx)
	rpcAddress, err = n.StartEVMRPC(rpcCtx, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = n.StartEVMRPC(ctx, "127.0.0.1:0"); err == nil {
		t.Fatal("duplicate RPC start accepted")
	}
	fmt.Printf("RPC_LISTENER=%s phase=%s previous_height=%d\n", rpcAddress, stage, previousHeight)
	client := &http.Client{Timeout: 4 * time.Second}
	defer client.CloseIdleConnections()
	// Wait for the first actual committed block; queries before InitChain/Commit
	// are allowed to report not-ready rather than returning synthetic state.
	var first int64
	for {
		if ctx.Err() != nil {
			t.Fatal(ctx.Err())
		}
		status, err := client.Get("http://127.0.0.1:26657/status")
		if err == nil {
			var body struct {
				Result struct {
					Sync struct {
						Height string `json:"latest_block_height"`
					} `json:"sync_info"`
				} `json:"result"`
			}
			json.NewDecoder(status.Body).Decode(&body)
			status.Body.Close()
			h, _ := strconv.ParseInt(body.Result.Sync.Height, 10, 64)
			if h > previousHeight {
				first = h
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if value := evmRPCResult(t, client, rpcAddress, "eth_chainId", []interface{}{}); value != "0xdfe09" {
		t.Fatalf("wrong chain ID %s", value)
	}
	h1 := rpcHexHeight(t, evmRPCResult(t, client, rpcAddress, "eth_blockNumber", []interface{}{}))
	if h1 < first {
		t.Fatal("RPC behind committed height")
	}
	// Compare to both endpoints around the EVM query to tolerate a concurrent
	// commit without pretending that two HTTP requests form an atomic snapshot.
	cometHeight := func() int64 {
		response, err := client.Get("http://127.0.0.1:26657/status")
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		var body struct {
			Result struct {
				Sync struct {
					Height string `json:"latest_block_height"`
				} `json:"sync_info"`
			} `json:"result"`
		}
		if json.NewDecoder(response.Body).Decode(&body) != nil {
			t.Fatal("bad Comet status")
		}
		h, err := strconv.ParseInt(body.Result.Sync.Height, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	target := int64(11)
	if previousHeight > 0 {
		target = previousHeight + 3
	}
	var h2 int64
	progressAt := time.Now()
	lastHeight := int64(-1)
	for {
		if ctx.Err() != nil {
			t.Fatal(ctx.Err())
		}
		low := cometHeight()
		sdkLow := n.application.SDK.LastBlockHeight()
		h2 = rpcHexHeight(t, evmRPCResult(t, client, rpcAddress, "eth_blockNumber", []interface{}{}))
		sdkHigh := n.application.SDK.LastBlockHeight()
		high := cometHeight()
		// Comet saves a block before FinalizeBlock/Commit. Its status may therefore
		// lead committed application state by one during a concurrent commit.
		if h2 < sdkLow || h2 > sdkHigh || h2 < low-1 || h2 > high+1 {
			t.Fatalf("RPC height=%d SDK=[%d,%d] Comet=[%d,%d]", h2, sdkLow, sdkHigh, low, high)
		}
		fmt.Printf("HEIGHT_CORRELATION RPC=%d SDK=[%d,%d] Comet=[%d,%d]\n", h2, sdkLow, sdkHigh, low, high)
		if h2 >= target && h2 > h1 {
			break
		}
		time.Sleep(200 * time.Millisecond)
		if h2 != lastHeight {
			lastHeight = h2
			progressAt = time.Now()
		}
		if time.Since(progressAt) > 5*time.Second {
			file, err := os.OpenFile(filepath.Join(root, stage+"-stalled.stack"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err == nil {
				pprof.Lookup("goroutine").WriteTo(file, 2)
				file.Close()
			}
			t.Fatalf("block progress stalled after RPC queries: sdk=%d comet=%d RPC=%d stack=%s", n.application.SDK.LastBlockHeight(), cometHeight(), h2, filepath.Join(root, stage+"-stalled.stack"))
		}
	}
	// Extract the funded Genesis address; never retain or log an account key.
	raw, err := os.ReadFile(filepath.Join(home, "config/genesis.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		AppState struct {
			Bank struct {
				Balances []struct {
					Address string `json:"address"`
				} `json:"balances"`
			} `json:"bank"`
		} `json:"app_state"`
	}
	if json.Unmarshal(raw, &doc) != nil || len(doc.AppState.Bank.Balances) != 1 {
		t.Fatal("funded fixture address missing")
	}
	accountAddress, err := sdk.AccAddressFromBech32(doc.AppState.Bank.Balances[0].Address)
	if err != nil {
		t.Fatal(err)
	}
	ethAddress := common.BytesToAddress(accountAddress).Hex()
	height := fmt.Sprintf("0x%x", h2)
	balance := evmRPCResult(t, client, rpcAddress, "eth_getBalance", []interface{}{ethAddress, height})
	nonce := evmRPCResult(t, client, rpcAddress, "eth_getTransactionCount", []interface{}{ethAddress, height})
	query, err := n.application.SDK.CreateQueryContext(h2, false)
	if err != nil {
		t.Fatal(err)
	}
	expectedBalance := n.application.SDK.BankKeeper.GetBalance(query, accountAddress, "atest").Amount.BigInt()
	account := n.application.SDK.AccountKeeper.GetAccount(query, accountAddress)
	if account == nil {
		t.Fatal("funded account missing")
	}
	if balance != "0x"+expectedBalance.Text(16) || nonce != fmt.Sprintf("0x%x", account.GetSequence()) || expectedBalance.Sign() <= 0 || account.GetSequence() != 1 {
		t.Fatalf("state query mismatch: balance=%s nonce=%s", balance, nonce)
	}
	for _, method := range []string{"eth_getBalance", "eth_getTransactionCount"} {
		if evmRPCResult(t, client, rpcAddress, method, []interface{}{common.Address{}.Hex(), "latest"}) != "0x0" {
			t.Fatal("unknown account nonzero")
		}
	}
	for _, test := range []struct {
		request string
		code    int
	}{{`{"jsonrpc":"2.0","id":2,"method":"missing_method","params":[]}`, -32601}, {`{"jsonrpc":"2.0","id":2,"method":"eth_getBalance","params":["bad","latest"]}`, -32602}, {`{"jsonrpc":"2.0","id":2,"method":"eth_getBalance","params":[]}`, -32602}, {`{broken`, -32700}, {`{"jsonrpc":"2.0","id":2,"method":"eth_chainId","params":["wrong-chain"]}`, -32602}, {`{"jsonrpc":"2.0","id":2,"method":"eth_sendTransaction","params":[]}`, -32601}} {
		response := evmRPCCall(t, client, rpcAddress, test.request)
		if response.Error == nil || response.Error.Code != test.code {
			t.Fatalf("wrong RPC error for %s: %+v", test.request, response)
		}
	}
	// Inspect EVERY process-owned socket, including accepted connections.
	output, err := exec.Command("ss", "-tanp").Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(output), "\n") {
		if strings.Contains(line, fmt.Sprintf("pid=%d,", os.Getpid())) {
			fields := strings.Fields(line)
			if len(fields) < 5 || !strings.HasPrefix(fields[3], "127.0.0.1:") || fields[0] != "LISTEN" && !strings.HasPrefix(fields[4], "127.0.0.1:") {
				t.Fatal("nonloopback socket")
			}
			fmt.Println("SOCKET", line)
		}
	}
	evidence := map[string]interface{}{"phase": stage, "address": rpcAddress, "chain_id": "0xdfe09", "h1": h1, "h2": h2, "funded_address": ethAddress, "balance": balance, "nonce": nonce, "expected_balance": expectedBalance.String(), "sdk_account_sequence": account.GetSequence()}
	encoded, _ := json.MarshalIndent(evidence, "", "  ")
	if err = os.WriteFile(filepath.Join(root, stage+"-rpc.json"), encoded, 0600); err != nil {
		t.Fatal(err)
	}
	if stage == "first" {
		// Cancellation closes only RPC; consensus remains managed by Node.Close.
		rpcCancel()
		select {
		case <-n.evmRPC.done:
		case <-time.After(2 * time.Second):
			t.Fatal("RPC cancellation watcher failed to close listener")
		}
		if err = n.evmRPC.Close(); err != nil {
			t.Fatal(err)
		}
		listener, err := net.Listen("tcp4", rpcAddress)
		if err != nil {
			t.Fatal("canceled RPC listener leaked")
		}
		listener.Close()
		fmt.Println("RPC_CANCEL_CLEANUP_PASS")
	}
	fmt.Printf("RPC_STATE_PASS chain=0xdfe09 heights=%d->%d balance=%s nonce=%s\n", h1, h2, balance, nonce)
	// Home flock is checked after Close by admissionClose, then a new process
	// proves application/Comet DB locks and both server lifecycles can reopen.
}
