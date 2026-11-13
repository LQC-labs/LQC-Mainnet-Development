//go:build linux

// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0
package node

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
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
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

type flowArtifact struct {
	ContractName        string
	Compiler            string
	SourceName          string
	ABI                 json.RawMessage
	Bytecode            string
	DeployedBytecode    string
	ImmutableReferences map[string][]struct {
		Start  int
		Length int
	}
}

func flowSecurityChecks(h *flowHarness, contracts map[string]string, deadline *big.Int) {
	h.t.Helper()
	a := common.HexToAddress(contracts["token18"])
	wrapper := common.HexToAddress(contracts["wrapper"])
	router := common.HexToAddress(contracts["router"])
	factory := common.HexToAddress(contracts["factory"])
	probe := h.deploy("withdrawal-probe", "FlowWithdrawalProbe", wrapper)
	contracts["probe"] = probe.Hex()
	supply := h.uint("MockWBNB", wrapper, "totalSupply")
	h.submit("withdrawal-reentry", &probe, h.input("FlowWithdrawalProbe", "exercise"), flowUnits(1, 15), 800000, "0x1")
	if h.call("FlowWithdrawalProbe", probe, "attempted")[0] != true || h.call("FlowWithdrawalProbe", probe, "blocked")[0] != true {
		h.t.Fatal("wrapper over-withdraw reentry was not rejected")
	}
	if h.uint("MockWBNB", wrapper, "totalSupply").Cmp(supply) != 0 || h.uint("MockWBNB", wrapper, "balanceOf", probe).Sign() != 0 || nativeAmount(h.t, h.c, h.rpc, "eth_getBalance", probe.Hex(), "latest").Cmp(flowUnits(1, 15)) != 0 {
		h.t.Fatal("wrapper reentry broke backing/balance")
	}
	attack := h.deploy("callback-token", "FlowCallbackToken")
	contracts["callback"] = attack.Hex()
	h.transact("mint-callback", "FlowCallbackToken", attack, "mint", "0x1", h.sender, flowUnits(1000, 18))
	h.transact("approve-callback", "FlowCallbackToken", attack, "approve", "0x1", router, flowUnits(1000, 18))
	h.transact("approve-reentry-pool", "LQCTestToken", a, "approve", "0x1", router, flowUnits(1000, 18))
	h.transact("add-reentry-liquidity", "LQCFlowRouter", router, "addLiquidity", "0x1", a, attack, flowUnits(1000, 18), flowUnits(1000, 18), flowUnits(1000, 18), flowUnits(1000, 18), h.sender, deadline)
	pair := h.call("LQCFlowFactory", factory, "getPair", a, attack)[0].(common.Address)
	contracts["attackPair"] = pair.Hex()
	h.checkCode("LQCFlowPair", pair)
	h.transact("arm-callback", "FlowCallbackToken", attack, "arm", "0x1", pair)
	h.transact("approve-reentry-swap", "LQCTestToken", a, "approve", "0x1", router, flowUnits(1, 18))
	path := []common.Address{a, attack}
	quote := h.call("LQCFlowRouter", router, "getAmountsOut", flowUnits(1, 18), path)[0].([]*big.Int)[1]
	tx := h.transact("pair-reentry-swap", "LQCFlowRouter", router, "swapExactTokensForTokens", "0x1", flowUnits(1, 18), quote, path, h.sender, deadline)
	if h.call("FlowCallbackToken", attack, "attempted")[0] != true || h.call("FlowCallbackToken", attack, "blocked")[0] != true {
		h.t.Fatal("Pair callback reentry not blocked")
	}
	actual := h.call("FlowCallbackToken", attack, "rejection")[0].([4]byte)
	want := crypto.Keccak256([]byte("Locked()"))
	if !bytes.Equal(actual[:], want[:4]) {
		h.t.Fatal("callback failed for a reason other than Pair Locked")
	}
	h.assertLogs("pair-reentry", tx, pair, "Swap", "LQCFlowPair")
}

func runFlowManifestCheck(t *testing.T, root, rpc string, state flowSnapshot, phase string) {
	t.Helper()
	// Only public evidence is passed to this read-only Core 3/3 preflight.
	request := map[string]interface{}{"root": root, "rpc": "http://" + rpc, "phase": phase, "state": state}
	raw, e := json.MarshalIndent(request, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(root, phase+"-manifest-input.json")
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	script := flowMainnetScript(t, "flow-minimal-preflight.mjs")
	cmd := exec.CommandContext(ctx, "/opt/node-v22.16.0/bin/node", script, path)
	out, e := cmd.CombinedOutput()
	if e != nil {
		t.Fatalf("Core3/3 actual deployment preflight: %v\n%s", e, out)
	}
	if e = os.WriteFile(filepath.Join(root, phase+"-manifest-check.json"), out, 0600); e != nil {
		t.Fatal(e)
	}
	t.Log(string(out))
}
func flowFixturePath(t *testing.T, parts ...string) string {
	t.Helper()
	root := flowtestassets.Require(t)
	return filepath.Join(append([]string{root, "node/testdata/flow-minimal"}, parts...)...)
}

// The first-party integration script stays in this repository. The external
// bundle supplies data only, never a script to execute.
func flowMainnetScript(t *testing.T, name string) string {
	t.Helper()
	for _, base := range []string{"scripts", "../scripts"} {
		path := filepath.Join(base, name)
		if info, err := os.Lstat(path); err == nil && info.Mode().IsRegular() {
			return path
		}
	}
	t.Fatal("mainnet integration script missing")
	return ""
}
func readFlowArtifact(t *testing.T, name string) (flowArtifact, abi.ABI) {
	t.Helper()
	raw, e := os.ReadFile(flowFixturePath(t, "artifacts", name+".json"))
	if e != nil {
		t.Fatal(e)
	}
	var a flowArtifact
	if json.Unmarshal(raw, &a) != nil {
		t.Fatal("bad compiled Flow artifact")
	}
	parsed, e := abi.JSON(bytes.NewReader(a.ABI))
	if e != nil {
		t.Fatal(e)
	}
	return a, parsed
}

type flowSnapshot struct {
	Contracts  map[string]string
	CodeHashes map[string]string
	Balances   map[string]string
	Reserves   []string
	Receipts   map[string]contractTxEvidence
}
type flowHarness struct {
	t         *testing.T
	ctx       context.Context
	n         *Node
	c         *http.Client
	rpc, root string
	key       *ecdsa.PrivateKey
	sender    common.Address
	txs       map[string]contractTxEvidence
}

func (h *flowHarness) input(contract, method string, args ...interface{}) []byte {
	h.t.Helper()
	_, a := readFlowArtifact(h.t, contract)
	data, e := a.Pack(method, args...)
	if e != nil {
		h.t.Fatal(e)
	}
	return data
}
func (h *flowHarness) call(contract string, to common.Address, method string, args ...interface{}) []interface{} {
	h.t.Helper()
	data := h.input(contract, method, args...)
	r := nativeRPC(h.t, h.c, h.rpc, "eth_call", []interface{}{map[string]interface{}{"from": h.sender.Hex(), "to": to.Hex(), "data": hexutil.Encode(data), "gas": "0x989680"}, "latest"})
	if r.Error != nil {
		h.t.Fatalf("Flow call %s: %s", method, r.Error.Message)
	}
	var result string
	if json.Unmarshal(r.Result, &result) != nil {
		h.t.Fatal("bad call hex")
	}
	_, a := readFlowArtifact(h.t, contract)
	values, e := a.Unpack(method, common.FromHex(result))
	if e != nil {
		h.t.Fatal(e)
	}
	return values
}
func (h *flowHarness) uint(contract string, to common.Address, method string, args ...interface{}) *big.Int {
	h.t.Helper()
	v := h.call(contract, to, method, args...)[0]
	switch n := v.(type) {
	case *big.Int:
		return n
	case uint8:
		return new(big.Int).SetUint64(uint64(n))
	default:
		h.t.Fatalf("unexpected numeric %T", v)
		return nil
	}
}
func (h *flowHarness) sign(chain *big.Int, to *common.Address, data []byte, value *big.Int, gas uint64) *ethtypes.Transaction {
	h.t.Helper()
	nonce := nativeAmount(h.t, h.c, h.rpc, "eth_getTransactionCount", h.sender.Hex(), "latest").Uint64()
	tx, e := ethtypes.SignNewTx(h.key, ethtypes.LatestSignerForChainID(chain), &ethtypes.DynamicFeeTx{ChainID: chain, Nonce: nonce, To: to, Data: data, Value: value, Gas: gas, GasFeeCap: big.NewInt(2_000_000_000), GasTipCap: big.NewInt(1_000_000_000)})
	if e != nil {
		h.t.Fatal("sign isolated TEST transaction")
	}
	return tx
}
func (h *flowHarness) submit(name string, to *common.Address, data []byte, value *big.Int, gas uint64, status string) contractTxEvidence {
	h.t.Helper()
	tx := h.sign(big.NewInt(917001), to, data, value, gas)
	result := contractSubmit(h.t, h.ctx, h.n, h.c, h.rpc, tx, status)
	h.txs[name] = result
	return result
}
func (h *flowHarness) transact(name, contract string, to common.Address, method string, status string, args ...interface{}) contractTxEvidence {
	if contract == "MockWBNB" && method == "withdraw" && status == "0x1" {
		return h.withdraw(name, to, h.input(contract, method, args...), args[0].(*big.Int))
	}
	gas := uint64(1_000_000)
	if contract == "LQCFlowFactory" && method == "createPair" || contract == "LQCFlowRouter" && method == "addLiquidity" {
		gas = 3_000_000
	}
	return h.submit(name, &to, h.input(contract, method, args...), big.NewInt(0), gas, status)
}
func (h *flowHarness) withdraw(name string, to common.Address, data []byte, credit *big.Int) contractTxEvidence {
	h.t.Helper()
	before := nativeAmount(h.t, h.c, h.rpc, "eth_getBalance", h.sender.Hex(), "latest")
	tx := h.sign(big.NewInt(917001), &to, data, big.NewInt(0), 1_000_000)
	nonce := tx.Nonce()
	raw, e := tx.MarshalBinary()
	if e != nil {
		h.t.Fatal(e)
	}
	sent := nativeRPC(h.t, h.c, h.rpc, "eth_sendRawTransaction", []interface{}{hexutil.Encode(raw)})
	if sent.Error != nil {
		h.t.Fatal(sent.Error.Message)
	}
	var hash string
	if json.Unmarshal(sent.Result, &hash) != nil || hash != tx.Hash().Hex() {
		h.t.Fatal("withdraw transaction hash")
	}
	var receipt map[string]interface{}
	for receipt == nil {
		if h.ctx.Err() != nil {
			h.t.Fatal(h.ctx.Err())
		}
		receipt = nativeReceipt(h.t, h.c, h.rpc, hash)
		if receipt == nil {
			time.Sleep(100 * time.Millisecond)
		}
	}
	if receipt["status"] != "0x1" {
		h.t.Fatal("wrapper withdraw failed")
	}
	height := rpcHexHeight(h.t, fmt.Sprint(receipt["blockNumber"]))
	gas := uint64(rpcHexHeight(h.t, fmt.Sprint(receipt["gasUsed"])))
	price, e := hexutil.DecodeBig(fmt.Sprint(receipt["effectiveGasPrice"]))
	if e != nil || price.Sign() <= 0 || gas == 0 || gas > tx.Gas() || price.Cmp(tx.GasFeeCap()) > 0 {
		h.t.Fatal("withdraw gas accounting")
	}
	fee := new(big.Int).Mul(new(big.Int).SetUint64(gas), price)
	after := nativeAmount(h.t, h.c, h.rpc, "eth_getBalance", h.sender.Hex(), fmt.Sprintf("0x%x", height))
	afterNonce := nativeAmount(h.t, h.c, h.rpc, "eth_getTransactionCount", h.sender.Hex(), fmt.Sprintf("0x%x", height)).Uint64()
	expected := new(big.Int).Sub(new(big.Int).Add(new(big.Int).Set(before), credit), fee)
	if after.Cmp(expected) != 0 || afterNonce != nonce+1 {
		h.t.Fatal("wrapper native return/fee/nonce mismatch")
	}
	indexed := nativeRPC(h.t, h.c, h.rpc, "eth_getTransactionByHash", []interface{}{hash})
	var actual map[string]interface{}
	if indexed.Error != nil || json.Unmarshal(indexed.Result, &actual) != nil || actual["hash"] != hash || actual["blockHash"] != receipt["blockHash"] {
		h.t.Fatal("withdraw inclusion mismatch")
	}
	result := contractTxEvidence{Hash: hash, Height: height, NonceBefore: nonce, NonceAfter: afterNonce, BalanceBefore: before.String(), BalanceAfter: after.String(), GasUsed: gas, Fee: fee.String(), Receipt: receipt}
	h.txs[name] = result
	return result
}
func (h *flowHarness) deploy(name, contract string, args ...interface{}) common.Address {
	h.t.Helper()
	artifact, a := readFlowArtifact(h.t, contract)
	constructor, e := a.Pack("", args...)
	if e != nil {
		h.t.Fatal(e)
	}
	receipt := h.submit("deploy-"+name, nil, append(common.FromHex(artifact.Bytecode), constructor...), big.NewInt(0), 6_000_000, "0x1")
	address := common.HexToAddress(fmt.Sprint(receipt.Receipt["contractAddress"]))
	if address == (common.Address{}) {
		h.t.Fatal("missing deployed address")
	}
	h.checkCode(contract, address)
	return address
}
func (h *flowHarness) code(to common.Address) []byte {
	return common.FromHex(evmRPCResult(h.t, h.c, h.rpc, "eth_getCode", []interface{}{to.Hex(), "latest"}))
}
func (h *flowHarness) checkCode(contract string, to common.Address) {
	h.t.Helper()
	artifact, _ := readFlowArtifact(h.t, contract)
	actual := h.code(to)
	want := common.FromHex(artifact.DeployedBytecode)
	if len(actual) == 0 || len(actual) != len(want) {
		h.t.Fatalf("%s runtime length mismatch", contract)
	}
	// Constructor immutables differ from the compiler template. Only compiler-
	// declared immutable positions may differ; values are checked via getters.
	actual = bytes.Clone(actual)
	want = bytes.Clone(want)
	for _, refs := range artifact.ImmutableReferences {
		for _, ref := range refs {
			if ref.Start < 0 || ref.Length < 1 || ref.Start+ref.Length > len(actual) {
				h.t.Fatal("invalid immutable range")
			}
			clear(actual[ref.Start : ref.Start+ref.Length])
			clear(want[ref.Start : ref.Start+ref.Length])
		}
	}
	if !bytes.Equal(actual, want) {
		h.t.Fatalf("%s runtime differs from compiled Flow source", contract)
	}
}
func flowHash(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func (h *flowHarness) reserves(pair common.Address) []string {
	v := h.call("LQCFlowPair", pair, "getReserves")
	return []string{v[0].(*big.Int).String(), v[1].(*big.Int).String(), fmt.Sprint(v[2])}
}
func (h *flowHarness) assertLogs(name string, tx contractTxEvidence, to common.Address, event string, contract string) {
	h.t.Helper()
	_, a := readFlowArtifact(h.t, contract)
	topic := a.Events[event].ID.Hex()
	r := nativeRPC(h.t, h.c, h.rpc, "eth_getLogs", []interface{}{map[string]interface{}{"blockHash": tx.Receipt["blockHash"], "address": to.Hex(), "topics": []string{topic}}})
	if r.Error != nil {
		h.t.Fatal(r.Error.Message)
	}
	var got []interface{}
	if json.Unmarshal(r.Result, &got) != nil {
		h.t.Fatal("bad logs")
	}
	want := []interface{}{}
	for _, item := range tx.Receipt["logs"].([]interface{}) {
		l := item.(map[string]interface{})
		topics := l["topics"].([]interface{})
		if strings.EqualFold(fmt.Sprint(l["address"]), to.Hex()) && len(topics) > 0 && topics[0] == topic {
			want = append(want, item)
		}
	}
	if len(got) == 0 || !reflect.DeepEqual(got, want) {
		h.t.Fatalf("%s log/receipt mismatch", name)
	}
	for _, item := range got {
		l := item.(map[string]interface{})
		if _, e := a.Events[event].Inputs.NonIndexed().Unpack(common.FromHex(fmt.Sprint(l["data"]))); e != nil {
			h.t.Fatal(e)
		}
	}
}

// Capture contract state separately from native gas/nonce, which a reverted
// signed transaction is allowed to consume.
func (h *flowHarness) liquidityState(a, b, factory, router common.Address) map[string]interface{} {
	pair := h.call("LQCFlowFactory", factory, "getPair", a, b)[0].(common.Address)
	nonce := nativeAmount(h.t, h.c, h.rpc, "eth_getTransactionCount", factory.Hex(), "latest").Uint64()
	result := map[string]interface{}{
		"pairAB": pair.Hex(), "pairBA": h.call("LQCFlowFactory", factory, "getPair", b, a)[0].(common.Address).Hex(),
		"pairCount": h.uint("LQCFlowFactory", factory, "allPairsLength").String(), "factoryNonce": nonce,
		"nextPairCode": flowHash(h.code(crypto.CreateAddress(factory, nonce))),
	}
	for name, token := range map[string]common.Address{"A": a, "B": b} {
		result[name+"-sender"] = h.uint("LQCTestToken", token, "balanceOf", h.sender).String()
		result[name+"-router"] = h.uint("LQCTestToken", token, "balanceOf", router).String()
		result[name+"-allowance"] = h.uint("LQCTestToken", token, "allowance", h.sender, router).String()
		result[name+"-supply"] = h.uint("LQCTestToken", token, "totalSupply").String()
		if pair != (common.Address{}) {
			result[name+"-pair"] = h.uint("LQCTestToken", token, "balanceOf", pair).String()
		}
	}
	if pair != (common.Address{}) {
		result["reserves"] = h.reserves(pair)
		result["LP-supply"] = h.uint("LQCFlowPair", pair, "totalSupply").String()
		result["LP-user"] = h.uint("LQCFlowPair", pair, "balanceOf", h.sender).String()
	}
	return result
}

func flowMinimumFailures(h *flowHarness, a, b, factory, router common.Address, deadline *big.Int, stage string) {
	h.t.Helper()
	desiredA, desiredB := flowUnits(1000, 18), flowUnits(2000, 6)
	for name, token := range map[string]common.Address{"A": a, "B": b} {
		desired := desiredA
		if name == "B" {
			desired = desiredB
		}
		if h.uint("LQCTestToken", token, "allowance", h.sender, router).Cmp(desired) < 0 {
			h.transact("minimum-"+stage+"-approval-"+name, "LQCTestToken", token, "approve", "0x1", router, desired)
		}
		if h.uint("LQCTestToken", token, "balanceOf", h.sender).Cmp(desired) < 0 {
			h.t.Fatal("minimum test lacks token funds")
		}
	}

	for _, which := range []string{"A", "B", "both"} {
		minA, minB := new(big.Int).Set(desiredA), new(big.Int).Set(desiredB)
		if which == "A" || which == "both" {
			minA.Add(minA, big.NewInt(1))
		}
		if which == "B" || which == "both" {
			minB.Add(minB, big.NewInt(1))
		}
		before := h.liquidityState(a, b, factory, router)
		baseline := os.Getenv("LQC_FLOW_MIN_BASELINE") == "1"
		expected := "0x0"
		if baseline {
			expected = "0x1"
		}
		name := "liquidity-min-" + stage + "-" + which
		if !baseline {
			payload, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": 1, "method": "eth_call", "params": []interface{}{map[string]interface{}{"from": h.sender.Hex(), "to": router.Hex(), "data": hexutil.Encode(h.input("LQCFlowRouter", "addLiquidity", a, b, desiredA, desiredB, minA, minB, h.sender, deadline)), "gas": "0x2dc6c0"}, "latest"}})
			req, err := http.NewRequestWithContext(h.ctx, "POST", "http://"+h.rpc+"/", bytes.NewReader(payload))
			if err != nil {
				h.t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			response, err := h.c.Do(req)
			if err != nil {
				h.t.Fatal(err)
			}
			var reply struct {
				Error *struct {
					Code    int
					Message string
					Data    string
				}
			}
			err = json.NewDecoder(response.Body).Decode(&reply)
			response.Body.Close()
			expectedSelector := hexutil.Encode(crypto.Keccak256([]byte("InsufficientAmount()"))[:4])
			if err != nil || reply.Error == nil || reply.Error.Data != expectedSelector {
				h.t.Fatalf("minimum rejected for wrong reason: %+v decode=%v", reply, err)
			}
		}

		tx := h.transact(name, "LQCFlowRouter", router, "addLiquidity", expected, a, b, desiredA, desiredB, minA, minB, h.sender, deadline)
		after := h.liquidityState(a, b, factory, router)
		evidence := map[string]interface{}{"case": name, "desiredA": desiredA.String(), "desiredB": desiredB.String(), "amountAMin": minA.String(), "amountBMin": minB.String(), "before": before, "after": after, "receipt": tx.Receipt, "transactionHash": tx.Hash, "stateUnchanged": reflect.DeepEqual(before, after)}
		raw, e := json.MarshalIndent(evidence, "", "  ")
		if e != nil {
			h.t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(h.root, name+".json"), raw, 0600); e != nil {
			h.t.Fatal(e)
		}
		if baseline {
			h.t.Fatalf("UNPATCHED_MIN_GUARD_REPRODUCED case=%s tx=%s status=0x1", name, tx.Hash)
		}
		if !reflect.DeepEqual(before, after) || len(tx.Receipt["logs"].([]interface{})) != 0 {
			h.t.Fatalf("liquidity minimum failure not atomic: %s", name)
		}
		h.t.Logf("LIQUIDITY_MIN_ATOMIC_PASS case=%s tx=%s status=0x0", name, tx.Hash)
	}
}
