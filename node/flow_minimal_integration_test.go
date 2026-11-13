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
	"strings"
	"testing"
	"time"

	"github.com/LQC-labs/LQC-Mainnet-Development/internal/flowtestassets"
	cmtlocal "github.com/cometbft/cometbft/rpc/client/local"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

func TestFlowMinimalArtifacts(t *testing.T) {
	flowtestassets.Require(t)
	raw, e := os.ReadFile(flowFixturePath(t, "SOURCE.json"))
	if e != nil {
		t.Fatal(e)
	}
	var source struct {
		Commit            string
		OriginalSources   map[string]struct{ SHA256 string }
		CompiledArtifacts map[string]struct{ SHA256 string }
		PatchedSources    map[string]struct{ SHA256, UpstreamCopy, UpstreamSHA256 string }
	}
	// Underscored provenance keys are decoded explicitly to retain exact schema.
	var doc map[string]json.RawMessage
	if json.Unmarshal(raw, &doc) != nil {
		t.Fatal("bad source record")
	}
	if json.Unmarshal(doc["commit"], &source.Commit) != nil || source.Commit != "8db16368b3e09a94bfd500a17e33e3e9ef62ed51" {
		t.Fatal("Flow pin mismatch")
	}
	json.Unmarshal(doc["original_sources"], &source.OriginalSources)
	json.Unmarshal(doc["compiledArtifacts"], &source.CompiledArtifacts)
	json.Unmarshal(doc["patched_sources"], &source.PatchedSources)
	if len(source.OriginalSources)+len(source.PatchedSources) != 11 || len(source.CompiledArtifacts) != 7 {
		t.Fatal("Flow closure/artifacts missing")
	}
	for path, entry := range source.OriginalSources {
		b, e := os.ReadFile(flowFixturePath(t, path))
		if e != nil || flowHash(b) != "sha256:"+entry.SHA256 {
			t.Fatalf("pinned Flow source changed: %s", path)
		}
	}
	for path, entry := range source.PatchedSources {
		patched, e := os.ReadFile(flowFixturePath(t, path))
		if e != nil || flowHash(patched) != "sha256:"+entry.SHA256 {
			t.Fatal("Router patch provenance mismatch")
		}
		original, e := os.ReadFile(flowFixturePath(t, entry.UpstreamCopy))
		if e != nil || flowHash(original) != "sha256:"+entry.UpstreamSHA256 {
			t.Fatal("upstream Router provenance mismatch")
		}
	}
	for name, entry := range source.CompiledArtifacts {
		b, e := os.ReadFile(flowFixturePath(t, "artifacts", name+".json"))
		if e != nil || flowHash(b) != "sha256:"+entry.SHA256 {
			t.Fatal("artifact provenance mismatch")
		}
		a, parsed := readFlowArtifact(t, name)
		if a.Compiler != "0.8.30+commit.73712a01" || len(a.Bytecode) < 4 || len(parsed.Methods) == 0 {
			t.Fatal("missing compiled ABI/bytecode")
		}
	}
}

func flowChild(t *testing.T, root, phase string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestFlowMinimalRuntimeChild$", "-test.v")
	cmd.Env = append(os.Environ(), "LQC_FLOW_ROOT="+root, "LQC_FLOW_PHASE="+phase)
	out, e := cmd.CombinedOutput()
	if err := os.WriteFile(filepath.Join(root, phase+".log"), out, 0600); err != nil {
		t.Fatal(err)
	}
	if e != nil {
		t.Fatalf("Flow %s child: %v\n%s", phase, e, out)
	}
	t.Log(string(out))
}
func TestFlowMinimalIntegration(t *testing.T) {
	if os.Getenv("LQC_RUN_FLOW_MINIMAL") != "1" {
		t.Skip("explicit new-home localhost Flow integration opt-in required")
	}
	flowtestassets.Require(t) // Validate availability before keys, HOME, DB or node creation.
	root, e := os.MkdirTemp(os.Getenv("LQC_FLOW_TEST_PARENT"), "lqc-flow-minimal.")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	t.Logf("PRESERVED_FLOW_EVIDENCE=%s", root)
	home := filepath.Join(root, "home")
	invokeRestartChild(t, root, "prepare", "^TestAdmissionRuntimeChild$", []string{"LQC_ADMISSION_ROOT=" + root, "LQC_ADMISSION_STAGE=prepare"})
	keys := restartFileHashes(t, home)
	flowChild(t, root, "first")
	before, e := readRestartEvidence(home)
	if e != nil {
		t.Fatal(e)
	}
	writeRestartEvidence(t, root, "before.json", before)
	flowChild(t, root, "restart")
	after, e := readRestartEvidence(home)
	if e != nil {
		t.Fatal(e)
	}
	writeRestartEvidence(t, root, "after.json", after)
	if before.Height < 15 || after.Height <= before.Height || before.Block1 != after.Block1 || before.Block11 != after.Block11 || before.PublicKey != after.PublicKey || before.Validators != 1 || after.Validators != 1 || before.Power != 1 || after.Power != 1 || after.SignedHeight < before.SignedHeight {
		t.Fatal("Flow restart continuity failed")
	}
	for path, hash := range keys {
		if restartFileHashes(t, home)[path] != hash {
			t.Fatalf("key/Genesis changed %s", path)
		}
	}
	t.Logf("FLOW_MINIMAL_PASS height=%d->%d signing=%d->%d original Factory/Pair + min-guard-patched Router, balances/reserves/code/receipts preserved", before.Height, after.Height, before.SignedHeight, after.SignedHeight)
}
func flowUnits(n int64, decimals int64) *big.Int {
	return new(big.Int).Mul(big.NewInt(n), new(big.Int).Exp(big.NewInt(10), big.NewInt(decimals), nil))
}
func (h *flowHarness) balances(contracts map[string]string) map[string]string {
	a := func(name string) common.Address { return common.HexToAddress(contracts[name]) }
	out := map[string]string{}
	for _, token := range []string{"token18", "token6"} {
		for _, owner := range []string{"sender", "recipient", "pair", "router"} {
			out[token+"-"+owner] = h.uint("LQCTestToken", a(token), "balanceOf", a(owner)).String()
		}
		out[token+"-supply"] = h.uint("LQCTestToken", a(token), "totalSupply").String()
		out[token+"-router-allowance"] = h.uint("LQCTestToken", a(token), "allowance", h.sender, a("router")).String()
	}
	out["wrapper-supply"] = h.uint("MockWBNB", a("wrapper"), "totalSupply").String()
	out["wrapper-user"] = h.uint("MockWBNB", a("wrapper"), "balanceOf", h.sender).String()
	out["wrapper-backing"] = nativeAmount(h.t, h.c, h.rpc, "eth_getBalance", a("wrapper").Hex(), "latest").String()
	if contracts["probe"] != "" {
		out["wrapper-probe"] = h.uint("MockWBNB", a("wrapper"), "balanceOf", a("probe")).String()
		out["probe-native"] = nativeAmount(h.t, h.c, h.rpc, "eth_getBalance", a("probe").Hex(), "latest").String()
		out["probe-blocked"] = fmt.Sprint(h.call("FlowWithdrawalProbe", a("probe"), "blocked")[0])
		out["callback-blocked"] = fmt.Sprint(h.call("FlowCallbackToken", a("callback"), "blocked")[0])
		for i, r := range h.reserves(a("attackPair")) {
			out[fmt.Sprintf("attack-reserve-%d", i)] = r
		}
	}
	return out
}
func (h *flowHarness) assertUnchanged(contracts map[string]string, before map[string]string, reserves []string) {
	h.t.Helper()
	if !reflect.DeepEqual(before, h.balances(contracts)) || !reflect.DeepEqual(reserves, h.reserves(common.HexToAddress(contracts["pair"]))) {
		h.t.Fatal("failed Flow execution changed token/reserve/allowance state")
	}
}

func TestFlowMinimalRuntimeChild(t *testing.T) {
	root, phase := os.Getenv("LQC_FLOW_ROOT"), os.Getenv("LQC_FLOW_PHASE")
	if root == "" {
		t.Skip("isolated Flow child only")
	}
	flowtestassets.Require(t)
	n, e := Open(filepath.Join(root, "home"))
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	defer admissionClose(t, n)
	previous := n.application.SDK.LastBlockHeight()
	if e = n.Start(ctx); e != nil {
		t.Fatal(e)
	}
	rpc, e := n.StartEVMRPCWithOptions(ctx, "127.0.0.1:0", RPCBrowserOptions{AllowedOrigins: []string{"http://localhost:3000"}})
	if e != nil {
		t.Fatal(e)
	}
	c := &http.Client{Timeout: 4 * time.Second}
	defer c.CloseIdleConnections()
	height := func() int64 { return rpcHexHeight(t, evmRPCResult(t, c, rpc, "eth_blockNumber", []interface{}{})) }
	wait := func(target int64) {
		for height() < target {
			if ctx.Err() != nil {
				t.Fatal(ctx.Err())
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	// The RPC correctly rejects height-zero queries until the first commit.
	// Observe consensus readiness before asking state-backed Ethereum methods.
	local := cmtlocal.New(n.node)
	for {
		status, err := local.Status(ctx)
		if err == nil && status.SyncInfo.LatestBlockHeight >= 2 && n.application.SDK.LastBlockHeight() >= 2 {
			break
		}
		if ctx.Err() != nil {
			t.Fatal(ctx.Err())
		}
		time.Sleep(25 * time.Millisecond)
	}
	if evmRPCResult(t, c, rpc, "eth_chainId", []interface{}{}) != "0xdfe09" {
		t.Fatal("Flow chain identity")
	}
	h := &flowHarness{t: t, ctx: ctx, n: n, c: c, rpc: rpc, root: root, txs: map[string]contractTxEvidence{}}
	statePath := filepath.Join(root, "flow-state.json")
	if phase == "restart" {
		raw, e := os.ReadFile(statePath)
		if e != nil {
			t.Fatal(e)
		}
		var saved flowSnapshot
		if json.Unmarshal(raw, &saved) != nil {
			t.Fatal("bad saved public state")
		}
		h.sender = common.HexToAddress(saved.Contracts["sender"])
		wait(previous + 3)
		for name, hash := range saved.CodeHashes {
			if flowHash(h.code(common.HexToAddress(saved.Contracts[name]))) != hash {
				t.Fatalf("code changed %s", name)
			}
		}
		if !reflect.DeepEqual(saved.Balances, h.balances(saved.Contracts)) || !reflect.DeepEqual(saved.Reserves, h.reserves(common.HexToAddress(saved.Contracts["pair"]))) {
			t.Fatal("Flow balances/reserves lost on restart")
		}
		for name, tx := range saved.Receipts {
			if !reflect.DeepEqual(nativeReceipt(t, c, rpc, tx.Hash), tx.Receipt) {
				t.Fatalf("Flow receipt changed %s", name)
			}
		}
		h.assertLogs("restart-swap", saved.Receipts["swap"], common.HexToAddress(saved.Contracts["pair"]), "Swap", "LQCFlowPair")
		if e = os.WriteFile(filepath.Join(root, "restart-flow-state.json"), raw, 0600); e != nil {
			t.Fatal(e)
		}
		runFlowManifestCheck(t, root, rpc, saved, phase)
	} else {
		keyData, e := os.ReadFile(filepath.Join(root, "test-account.key"))
		if e != nil {
			t.Fatal("read isolated TEST signer")
		}
		h.key, e = crypto.ToECDSA(keyData)
		if e != nil {
			t.Fatal("decode TEST signer")
		}
		h.sender = crypto.PubkeyToAddress(h.key.PublicKey)
		a := h.deploy("token18", "LQCTestToken", "Local Flow Test 18", "LF18", uint8(18), h.sender)
		b := h.deploy("token6", "LQCTestToken", "Local Flow Test 6", "LF6", uint8(6), h.sender)
		wrapper := h.deploy("wrapper", "MockWBNB")
		factory := h.deploy("factory", "LQCFlowFactory", h.sender)
		router := h.deploy("router", "LQCFlowRouter", factory, wrapper)
		if h.uint("LQCTestToken", a, "decimals").Int64() != 18 || h.uint("LQCTestToken", b, "decimals").Int64() != 6 {
			t.Fatal("token decimals")
		}
		if h.call("LQCFlowRouter", router, "factory")[0].(common.Address) != factory || h.call("LQCFlowRouter", router, "WBNB")[0].(common.Address) != wrapper || h.call("LQCFlowFactory", factory, "owner")[0].(common.Address) != h.sender {
			t.Fatal("constructor immutable wiring")
		}
		h.transact("mint18", "LQCTestToken", a, "mint", "0x1", h.sender, flowUnits(10000, 18))
		h.transact("mint6", "LQCTestToken", b, "mint", "0x1", h.sender, flowUnits(20000, 6))
		recipient := common.HexToAddress("0x1000000000000000000000000000000000000011")
		transferred := h.transact("transfer18", "LQCTestToken", a, "transfer", "0x1", recipient, flowUnits(1, 18))
		h.assertLogs("transfer", transferred, a, "Transfer", "LQCTestToken")
		h.transact("transfer6", "LQCTestToken", b, "transfer", "0x1", recipient, flowUnits(1, 6))
		if h.uint("LQCTestToken", a, "balanceOf", recipient).Cmp(flowUnits(1, 18)) != 0 || h.uint("LQCTestToken", b, "balanceOf", recipient).Cmp(flowUnits(1, 6)) != 0 {
			t.Fatal("token transfer units")
		}
		h.transact("zero-recipient", "LQCTestToken", a, "transfer", "0x0", common.Address{}, big.NewInt(1))
		h.transact("insufficient-balance", "LQCTestToken", a, "transfer", "0x0", recipient, flowUnits(100000, 18))
		h.transact("insufficient-allowance", "LQCTestToken", a, "transferFrom", "0x0", h.sender, recipient, big.NewInt(1))
		deposit := flowUnits(1, 16)
		h.submit("wrap-deposit", &wrapper, h.input("MockWBNB", "deposit"), deposit, 300000, "0x1")
		if h.uint("MockWBNB", wrapper, "totalSupply").Cmp(deposit) != 0 || nativeAmount(t, c, rpc, "eth_getBalance", wrapper.Hex(), "latest").Cmp(deposit) != 0 {
			t.Fatal("wrapper collateral mismatch")
		}
		h.transact("wrap-withdraw", "MockWBNB", wrapper, "withdraw", "0x1", new(big.Int).Div(new(big.Int).Set(deposit), big.NewInt(2)))
		if h.uint("MockWBNB", wrapper, "totalSupply").Cmp(nativeAmount(t, c, rpc, "eth_getBalance", wrapper.Hex(), "latest")) != 0 || h.uint("MockWBNB", wrapper, "balanceOf", h.sender).Cmp(h.uint("MockWBNB", wrapper, "totalSupply")) != 0 {
			t.Fatal("wrapper supply/backing/user invariant")
		}
		deadline := new(big.Int).SetUint64(uint64(time.Now().Unix() + 300))
		h.transact("guard-approve-A", "LQCTestToken", a, "approve", "0x1", router, flowUnits(1000, 18))
		h.transact("guard-approve-B", "LQCTestToken", b, "approve", "0x1", router, flowUnits(2000, 6))
		flowMinimumFailures(h, a, b, factory, router, deadline, "missing")
		created := h.transact("create-pair", "LQCFlowFactory", factory, "createPair", "0x1", a, b)
		pair := h.call("LQCFlowFactory", factory, "getPair", a, b)[0].(common.Address)
		h.checkCode("LQCFlowPair", pair)
		h.assertLogs("createPair", created, factory, "PairCreated", "LQCFlowFactory")
		if h.call("LQCFlowPair", pair, "factory")[0].(common.Address) != factory {
			t.Fatal("pair factory mismatch")
		}
		contracts := map[string]string{"sender": h.sender.Hex(), "recipient": recipient.Hex(), "token18": a.Hex(), "token6": b.Hex(), "wrapper": wrapper.Hex(), "factory": factory.Hex(), "pair": pair.Hex(), "router": router.Hex()}
		h.transact("approve18", "LQCTestToken", a, "approve", "0x1", router, flowUnits(1000, 18))
		h.transact("approve6", "LQCTestToken", b, "approve", "0x1", router, flowUnits(2000, 6))
		if h.uint("LQCTestToken", a, "allowance", h.sender, router).Cmp(flowUnits(1000, 18)) != 0 || h.uint("LQCTestToken", b, "allowance", h.sender, router).Cmp(flowUnits(2000, 6)) != 0 {
			t.Fatal("exact approval mismatch")
		}
		flowMinimumFailures(h, a, b, factory, router, deadline, "empty")
		liquidity := h.transact("add-liquidity", "LQCFlowRouter", router, "addLiquidity", "0x1", a, b, flowUnits(1000, 18), flowUnits(2000, 6), flowUnits(1000, 18), flowUnits(2000, 6), h.sender, deadline)
		h.assertLogs("mint", liquidity, pair, "Mint", "LQCFlowPair")
		token0 := h.call("LQCFlowPair", pair, "token0")[0].(common.Address)
		reserves := h.reserves(pair)
		rA, rB := reserves[0], reserves[1]
		if token0 != a {
			rA, rB = rB, rA
		}
		if rA != flowUnits(1000, 18).String() || rB != flowUnits(2000, 6).String() || h.uint("LQCFlowPair", pair, "balanceOf", h.sender).Sign() <= 0 {
			t.Fatal("real reserves/liquidity mismatch")
		}
		rootK := new(big.Int).Sqrt(new(big.Int).Mul(flowUnits(1000, 18), flowUnits(2000, 6)))
		if h.uint("LQCFlowPair", pair, "totalSupply").Cmp(rootK) != 0 || h.uint("LQCFlowPair", pair, "balanceOf", h.sender).Cmp(new(big.Int).Sub(new(big.Int).Set(rootK), big.NewInt(1000))) != 0 {
			t.Fatal("LP share/locked-liquidity invariant")
		}
		flowMinimumFailures(h, a, b, factory, router, deadline, "existing")
		amount := flowUnits(1, 18)
		path := []common.Address{a, b}
		quote := h.call("LQCFlowRouter", router, "getAmountsOut", amount, path)[0].([]*big.Int)[1]
		numerator := new(big.Int).Mul(new(big.Int).Mul(new(big.Int).Set(amount), big.NewInt(9970)), flowUnits(2000, 6))
		denominator := new(big.Int).Add(new(big.Int).Mul(flowUnits(1000, 18), big.NewInt(10000)), new(big.Int).Mul(new(big.Int).Set(amount), big.NewInt(9970)))
		if quote.Cmp(new(big.Int).Div(numerator, denominator)) != 0 {
			t.Fatal("Flow constant-product quote mismatch")
		}
		h.transact("approve-swap", "LQCTestToken", a, "approve", "0x1", router, amount)
		beforeBalance := h.uint("LQCTestToken", b, "balanceOf", h.sender)
		beforeInput := h.uint("LQCTestToken", a, "balanceOf", h.sender)
		swap := h.transact("swap", "LQCFlowRouter", router, "swapExactTokensForTokens", "0x1", amount, new(big.Int).Div(new(big.Int).Mul(new(big.Int).Set(quote), big.NewInt(99)), big.NewInt(100)), path, h.sender, deadline)
		if new(big.Int).Sub(h.uint("LQCTestToken", b, "balanceOf", h.sender), beforeBalance).Cmp(quote) != 0 || h.uint("LQCTestToken", a, "allowance", h.sender, router).Sign() != 0 {
			t.Fatal("swap output/exact allowance mismatch")
		}
		afterReserves := h.reserves(pair)
		afterA, afterB := afterReserves[0], afterReserves[1]
		if token0 != a {
			afterA, afterB = afterB, afterA
		}
		wantA := new(big.Int).Add(flowUnits(1000, 18), amount)
		wantB := new(big.Int).Sub(flowUnits(2000, 6), quote)
		if afterA != wantA.String() || afterB != wantB.String() || h.uint("LQCTestToken", a, "balanceOf", pair).Cmp(wantA) != 0 || h.uint("LQCTestToken", b, "balanceOf", pair).Cmp(wantB) != 0 || h.uint("LQCTestToken", a, "balanceOf", h.sender).Cmp(new(big.Int).Sub(beforeInput, amount)) != 0 {
			t.Fatal("swap reserve/actual token conservation")
		}
		h.assertLogs("swap", swap, pair, "Swap", "LQCFlowPair")
		// Failures must revert token transfers, allowance consumption and reserves.
		h.transact("approve-negative", "LQCTestToken", a, "approve", "0x1", router, amount)
		for _, failure := range []struct {
			name     string
			minimum  *big.Int
			route    []common.Address
			to       common.Address
			deadline *big.Int
		}{
			{"slippage", flowUnits(1000000, 6), path, h.sender, deadline}, {"expired", big.NewInt(0), path, h.sender, big.NewInt(0)},
			{"invalid-path", big.NewInt(0), []common.Address{a, common.Address{}}, h.sender, deadline}, {"invalid-swap-recipient", big.NewInt(0), path, common.Address{}, deadline},
		} {
			balances, reserves := h.balances(contracts), h.reserves(pair)
			failed := h.transact(failure.name, "LQCFlowRouter", router, "swapExactTokensForTokens", "0x0", amount, failure.minimum, failure.route, failure.to, failure.deadline)
			if len(failed.Receipt["logs"].([]interface{})) != 0 {
				t.Fatal("reverted Flow retained events")
			}
			h.assertUnchanged(contracts, balances, reserves)
		}
		h.transact("clear-allowance", "LQCTestToken", a, "approve", "0x1", router, big.NewInt(0))
		balances := h.balances(contracts)
		reserves = h.reserves(pair)
		h.transact("unapproved-swap", "LQCFlowRouter", router, "swapExactTokensForTokens", "0x0", amount, big.NewInt(0), path, h.sender, deadline)
		h.assertUnchanged(contracts, balances, reserves)
		wrong := h.sign(big.NewInt(97), &router, h.input("LQCFlowRouter", "swapExactTokensForTokens", amount, big.NewInt(0), path, h.sender, deadline), big.NewInt(0), 500000)
		raw, _ := wrong.MarshalBinary()
		if nativeRPC(t, c, rpc, "eth_sendRawTransaction", []interface{}{hexutil.Encode(raw)}).Error == nil {
			t.Fatal("BSC signature accepted on LQC")
		}
		flowSecurityChecks(h, contracts, deadline)
		wait(15)
		saved := flowSnapshot{Contracts: contracts, CodeHashes: map[string]string{}, Balances: h.balances(contracts), Reserves: h.reserves(pair), Receipts: h.txs}
		for name, address := range contracts {
			if name != "sender" && name != "recipient" {
				saved.CodeHashes[name] = flowHash(h.code(common.HexToAddress(address)))
			}
		}
		raw, e = json.MarshalIndent(saved, "", "  ")
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(statePath, raw, 0600); e != nil {
			t.Fatal(e)
		}
		runFlowManifestCheck(t, root, rpc, saved, phase)
		fmt.Printf("FLOW_SWAP_PASS factory=%s pair=%s router=%s hash=%s output6=%s\n", factory, pair, router, swap.Hash, quote)
	}
	out, e := exec.Command("ss", "-tanp").Output()
	if e != nil {
		t.Fatal(e)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, fmt.Sprintf("pid=%d,", os.Getpid())) {
			f := strings.Fields(line)
			if len(f) < 5 || !strings.HasPrefix(f[3], "127.0.0.1:") || f[0] != "LISTEN" && !strings.HasPrefix(f[4], "127.0.0.1:") {
				t.Fatal("nonlocal Flow socket")
			}
			fmt.Println("FLOW_SOCKET", line)
		}
	}
	fmt.Printf("FLOW_RUNTIME_PASS phase=%s height=%d->%d\n", phase, previous, height())
}
