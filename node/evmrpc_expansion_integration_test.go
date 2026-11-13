//go:build linux

package node

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestEVMRPCExpansionIntegration(t *testing.T) {
	if os.Getenv("LQC_RUN_RPC_EXPANSION") != "1" {
		t.Skip("explicit new-home localhost opt-in required")
	}
	t.Setenv("LQC_RUN_EVM_CONTRACT", "1")
	TestEVMContractIntegration(t)
}

// Runs in both independent contract child processes, before and after restart.
// All saved evidence is public chain data; account/validator keys are not read.
func checkRPCExpansion(t *testing.T, c *http.Client, rpc string, saved contractEvidence, root, phase string) {
	t.Helper()
	evidence := map[string]interface{}{}
	query := func(method string, args []interface{}) json.RawMessage {
		r := nativeRPC(t, c, rpc, method, args)
		if r.Error != nil {
			t.Fatalf("%s: %s", method, r.Error.Message)
		}
		evidence[method] = r.Result
		return r.Result
	}
	requireError := func(method string, args []interface{}) {
		r := nativeRPC(t, c, rpc, method, args)
		if r.Error == nil {
			t.Fatalf("invalid %s accepted", method)
		}
		evidence[method+"-rejection"] = r.Error
	}
	var price, tip string
	if json.Unmarshal(query("eth_gasPrice", nil), &price) != nil || rpcHexHeight(t, price) <= 0 {
		t.Fatal("gas price")
	}
	if json.Unmarshal(query("eth_maxPriorityFeePerGas", nil), &tip) != nil {
		t.Fatal("tip")
	}
	transfer := map[string]interface{}{"from": saved.Sender, "to": "0x0000000000000000000000000000000000000001", "value": "0x1"}
	var gas string
	if json.Unmarshal(query("eth_estimateGas", []interface{}{transfer}), &gas) != nil || rpcHexHeight(t, gas) < 21000 || rpcHexHeight(t, gas) > int64(rpcGasCap) {
		t.Fatal("gas estimate")
	}
	query("eth_estimateGas", []interface{}{transfer, "pending"})
	transfer["gas"] = "0x989681"
	requireError("eth_estimateGas", []interface{}{transfer})
	delete(transfer, "gas")
	requireError("eth_estimateGas", []interface{}{map[string]interface{}{"from": saved.Sender, "to": saved.Address, "data": contractInput("fail()", false, 0)}, "latest"})
	requireError("eth_getBlockByNumber", []interface{}{"not-a-block", false})
	if string(query("eth_getBlockByNumber", []interface{}{"0x7fffffffffffffff", false})) != "null" {
		t.Fatal("future block not null")
	}
	for _, selector := range []string{"earliest", "latest", "safe", "finalized", "pending"} {
		query("eth_getBlockByNumber", []interface{}{selector, false})
	}
	if string(query("eth_getTransactionByHash", []interface{}{"0x" + strings.Repeat("00", 32)})) != "null" {
		t.Fatal("unknown tx not null")
	}
	// A nonce-gap transaction remains in the actual EVM pool, independently of
	// Comet's pool. It must be queryable with null inclusion fields. Pool entries
	// are intentionally volatile, and must not be mistaken for committed state.
	pendingPath := filepath.Join(root, "rpc-pending-hash.txt")
	pendingRaw, readErr := os.ReadFile(pendingPath)
	if phase == "first" && os.IsNotExist(readErr) {
		keyBytes, e := os.ReadFile(filepath.Join(root, "test-account.key"))
		if e != nil {
			t.Fatal("read TEST signer")
		}
		key, e := crypto.ToECDSA(keyBytes)
		if e != nil {
			t.Fatal("decode TEST signer")
		}
		to := common.HexToAddress(saved.Sender)
		tx, e := ethtypes.SignNewTx(key, ethtypes.LatestSignerForChainID(big.NewInt(917001)), &ethtypes.DynamicFeeTx{ChainID: big.NewInt(917001), Nonce: saved.Transactions["revert"].NonceAfter + 10, To: &to, Gas: 21000, GasFeeCap: big.NewInt(2_000_000_000), GasTipCap: big.NewInt(1_000_000_000)})
		if e != nil {
			t.Fatal("sign TEST pending transaction")
		}
		raw, _ := tx.MarshalBinary()
		query("eth_sendRawTransaction", []interface{}{hexutil.Encode(raw)})
		pendingRaw = []byte(tx.Hash().Hex())
		if e = os.WriteFile(pendingPath, pendingRaw, 0600); e != nil {
			t.Fatal(e)
		}
	} else if readErr != nil {
		t.Fatal(readErr)
	}
	pending := query("eth_getTransactionByHash", []interface{}{string(pendingRaw)})
	if phase == "first" {
		var tx map[string]interface{}
		if json.Unmarshal(pending, &tx) != nil || tx == nil || tx["blockHash"] != nil || tx["blockNumber"] != nil {
			t.Fatalf("pending lookup missing/included: %s", pending)
		}
	} else if string(pending) != "null" {
		t.Fatal("unexpected durable pending pool")
	}
	evidence["pending-after-restart-durability"] = "unsupported: in-memory EVM pool; no automatic resubmission"
	set := saved.Transactions["set"]
	for name, tx := range saved.Transactions {
		var block map[string]interface{}
		raw := query("eth_getBlockByNumber", []interface{}{fmt.Sprintf("0x%x", tx.Height), true})
		if json.Unmarshal(raw, &block) != nil {
			t.Fatal("block JSON")
		}
		if block["hash"] != tx.Receipt["blockHash"] || block["number"] != tx.Receipt["blockNumber"] {
			t.Fatal("block receipt mismatch")
		}
		query("eth_getBlockByNumber", []interface{}{fmt.Sprintf("0x%x", tx.Height), false})
		var transaction map[string]interface{}
		if json.Unmarshal(query("eth_getTransactionByHash", []interface{}{tx.Hash}), &transaction) != nil || transaction["hash"] != tx.Hash || transaction["blockHash"] != tx.Receipt["blockHash"] {
			t.Fatal("indexed tx mismatch")
		}
		evidence[name+"-block"] = block
		evidence[name+"-transaction"] = transaction
	}
	var logs []interface{}
	filter := map[string]interface{}{"blockHash": set.Receipt["blockHash"], "address": saved.Address}
	if json.Unmarshal(query("eth_getLogs", []interface{}{filter}), &logs) != nil || !reflect.DeepEqual(logs, set.Receipt["logs"]) {
		t.Fatalf("log receipt mismatch got=%v want=%v", logs, set.Receipt["logs"])
	}
	filter = map[string]interface{}{"fromBlock": fmt.Sprintf("0x%x", set.Height), "toBlock": fmt.Sprintf("0x%x", set.Height), "address": saved.Address}
	query("eth_getLogs", []interface{}{filter})
	filter["topics"] = []interface{}{nil}
	query("eth_getLogs", []interface{}{filter})
	filter["address"] = "0x0000000000000000000000000000000000000001"
	if string(query("eth_getLogs", []interface{}{filter})) != "[]" {
		t.Fatal("wrong address matched")
	}
	filter["address"] = saved.Address
	filter["topics"] = []interface{}{"0x" + strings.Repeat("00", 32)}
	if string(query("eth_getLogs", []interface{}{filter})) != "[]" {
		t.Fatal("wrong topic matched")
	}
	requireError("eth_getLogs", []interface{}{map[string]interface{}{"fromBlock": "pending"}})
	requireError("eth_getLogs", []interface{}{map[string]interface{}{"fromBlock": "0x1", "toBlock": "0x100"}})
	requireError("eth_getLogs", []interface{}{map[string]interface{}{"fromBlock": "0x1", "blockHash": set.Receipt["blockHash"]}})
	// Browser-like JSON-RPC POST and preflight against the actual listener.
	for _, tc := range []struct {
		origin, host, method, pre string
		want                      int
	}{
		{"http://localhost:3000", "", "POST", "", 200},
		{"http://localhost:3000", "", "OPTIONS", "POST", 204},
		{"http://localhost:3001", "", "POST", "", 403},
		{"http://evil.example", "", "POST", "", 403},
		{"http://localhost:3000", "evil.example", "POST", "", 403},
		{"http://localhost:3000", "", "OPTIONS", "GET", 403},
	} {
		req, _ := http.NewRequest(tc.method, "http://"+rpc+"/", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}`))
		req.Header.Set("Origin", tc.origin)
		req.Header.Set("Content-Type", "application/json")
		if tc.host != "" {
			req.Host = tc.host
		}
		if tc.pre != "" {
			req.Header.Set("Access-Control-Request-Method", tc.pre)
			req.Header.Set("Access-Control-Request-Headers", "content-type")
		}
		res, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != tc.want {
			res.Body.Close()
			t.Fatalf("browser %+v status=%d", tc, res.StatusCode)
		}
		if tc.want == 200 {
			var body struct{ Result string }
			if json.NewDecoder(res.Body).Decode(&body) != nil || body.Result != "0xdfe09" {
				t.Fatal("browser RPC identity")
			}
		}
		if tc.want < 300 && res.Header.Get("Access-Control-Allow-Origin") != tc.origin {
			t.Fatal("missing exact CORS Origin")
		}
		res.Body.Close()
	}
	raw, _ := json.MarshalIndent(evidence, "", "  ")
	if err := os.WriteFile(filepath.Join(root, phase+"-rpc-expansion.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("RPC_EXPANSION_PASS phase=%s gasPrice=%s tip=%s estimate=%s logs/transactions/blocks/browser/revert verified", phase, price, tip, gas)
}
