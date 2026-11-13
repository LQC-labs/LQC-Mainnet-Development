//go:build linux

package node

import (
	"context"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth/filters"
)

func TestRPCBrowserBoundary(t *testing.T) {
	for _, origin := range []string{"*", "null", "https://evil.example", "http://localhost.evil:3000", "http://user@localhost:3000", "http://localhost:3000/", "http://localhost:0", "http://localhost:3000?x=y", "http://localhost:", "http://localhost?"} {
		if _, e := browserOrigins(RPCBrowserOptions{[]string{origin}}); e == nil {
			t.Fatalf("unsafe Origin accepted %s", origin)
		}
	}
	origins, e := browserOrigins(RPCBrowserOptions{[]string{"http://localhost:3000"}})
	if e != nil {
		t.Fatal(e)
	}
	handler := localRPCHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }), origins)
	for _, tc := range []struct {
		origin, host, method, pre, headers string
		want                               int
	}{
		{"http://localhost:3000", "127.0.0.1:8545", "POST", "", "", 200},
		{"http://localhost:3001", "localhost:8545", "POST", "", "", 403},
		{"null", "localhost:8545", "POST", "", "", 403},
		{"", "evil.example", "POST", "", "", 403},
		{"", "localhost:8545", "POST", "", "", 200},
		{"http://localhost:3000", "localhost:8545", "OPTIONS", "POST", "Content-Type", 204},
		{"http://localhost:3000", "localhost:8545", "OPTIONS", "GET", "", 403},
		{"http://localhost:3000", "localhost:8545", "OPTIONS", "POST", "Authorization", 403},
		{"", "localhost:8545", "OPTIONS", "POST", "", 403},
	} {
		r := httptest.NewRequest(tc.method, "http://localhost/", nil)
		r.Host = tc.host
		if tc.origin != "" {
			r.Header.Set("Origin", tc.origin)
		}
		r.Header.Set("Access-Control-Request-Method", tc.pre)
		r.Header.Set("Access-Control-Request-Headers", tc.headers)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("%+v got %d", tc, w.Code)
		}
		if w.Header().Get("Access-Control-Allow-Origin") == "*" {
			t.Fatal("wildcard CORS")
		}
		if tc.want == 403 && w.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatal("denied Origin authorized")
		}
	}
	// Keep no-Origin default, and reject malformed/duplicate Origin fields.
	for _, duplicate := range []bool{false, true} {
		r := httptest.NewRequest("POST", "http://localhost/", nil)
		r.Header.Set("Origin", "http://localhost:3000")
		h := localRPCHandler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("unauthorized request reached RPC") }), nil)
		if duplicate {
			r.Header.Add("Origin", "http://localhost:3000")
			h = handler
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal("Origin accepted")
		}
	}
}

func TestRPCTransportLimitsAndCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server, err := openEVMRPC(ctx, "127.0.0.1:0", &evmReadAPI{})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client := &http.Client{Timeout: 4 * time.Second}
	defer client.CloseIdleConnections()
	call := `{"jsonrpc":"2.0","id":1,"method":"eth_notExposed","params":[]}`
	for _, body := range []string{strings.Repeat(" ", 1024*1024) + call, "[" + strings.Repeat(call+",", 16) + call + "]"} {
		response, e := client.Post("http://"+server.address+"/", "application/json", strings.NewReader(body))
		if e != nil {
			t.Fatal(e)
		}
		data, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode < 400 {
			var r struct {
				Error *struct {
					Code    int
					Message string
				}
			}
			var batch []struct {
				Error *struct {
					Code    int
					Message string
				}
			}
			valid := json.Unmarshal(data, &r) == nil && r.Error != nil && strings.Contains(strings.ToLower(r.Error.Message), "batch")
			if json.Unmarshal(data, &batch) == nil && len(batch) == 1 && batch[0].Error != nil && strings.Contains(strings.ToLower(batch[0].Error.Message), "batch") {
				valid = true
			}
			if !valid {
				t.Fatalf("body/batch limit not enforced: status=%d data=%s", response.StatusCode, data)
			}
		}
	}
	cancel()
	if err = server.Close(); err != nil {
		t.Fatal(err)
	}
	response, e := client.Post("http://"+server.address+"/", "application/json", strings.NewReader(call))
	if e == nil {
		response.Body.Close()
		t.Fatal("listener survives cancellation")
	}
}

func TestRPCConcurrentRequestLimit(t *testing.T) {
	entered := make(chan struct{}, 8)
	release := make(chan struct{})
	h := localRPCHandler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { entered <- struct{}{}; <-release }), nil)
	done := make(chan struct{}, 8)
	for i := 0; i < 8; i++ {
		go func() {
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "http://localhost/", nil))
			done <- struct{}{}
		}()
	}
	for i := 0; i < 8; i++ {
		<-entered
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "http://localhost/", nil))
	close(release)
	for i := 0; i < 8; i++ {
		<-done
	}
	if w.Code != 503 {
		t.Fatal("concurrency not bounded")
	}
}

func TestRPCLogFilterSemantics(t *testing.T) {
	a := common.HexToAddress("0x1")
	topic := common.HexToHash("0x1")
	l := &ethtypes.Log{Address: a, Topics: []common.Hash{topic}}
	if !matchesLog(l, filters.FilterCriteria{Addresses: []common.Address{a}, Topics: [][]common.Hash{{topic}}}) {
		t.Fatal("matching log excluded")
	}
	if matchesLog(l, filters.FilterCriteria{Topics: [][]common.Hash{{common.HexToHash("0x2")}}}) {
		t.Fatal("wrong topic matched")
	}
	if !matchesLog(l, filters.FilterCriteria{Topics: [][]common.Hash{nil}}) {
		t.Fatal("wildcard topic failed")
	}
	if _, e := logHeight(new(big.Int).Lsh(big.NewInt(1), 100), 11); e == nil {
		t.Fatal("height overflow")
	}
	if _, e := logHeight(big.NewInt(-1), 11); e == nil {
		t.Fatal("pending log accepted")
	}
	if e := validateLogCriteria(filters.FilterCriteria{BlockHash: &topic, FromBlock: big.NewInt(1)}); e == nil {
		t.Fatal("hash/range accepted")
	}
	if e := validateLogCriteria(filters.FilterCriteria{Topics: make([][]common.Hash, 5)}); e == nil {
		t.Fatal("topic cap")
	}
	if !strings.Contains(rpcInputError("bad").Error(), "bad") || rpcInputError("").ErrorCode() != -32602 {
		t.Fatal("invalid parameter code")
	}
}
