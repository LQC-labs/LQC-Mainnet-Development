// SPDX-License-Identifier: Apache-2.0
package securityaudit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func hasRule(report Report, rule string) bool {
	for _, finding := range report.Findings {
		if finding.Rule == rule {
			return true
		}
	}
	return false
}

func TestHistoricalFixturesDetectedWithoutExecutingSDK(t *testing.T) {
	var origins map[string]struct{ Source, SHA256 string }
	data, err := os.ReadFile("testdata/legacy/origins.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &origins); err != nil {
		t.Fatal(err)
	}
	for name, required := range map[string][]string{
		"adapter.go.txt":   {"sdk-import", "raw-kv", "sdk-write-operation", "txn-unproven"},
		"api_probe.go.txt": {"sdk-import", "raw-kv", "sdk-write-operation", "txn-write"},
	} {
		t.Run(name, func(t *testing.T) {
			source, err := os.ReadFile(filepath.Join("testdata", "legacy", name))
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(source)
			if origin, ok := origins[name]; !ok || origin.Source == "" || hex.EncodeToString(sum[:]) != origin.SHA256 {
				t.Fatal("historical fixture differs from recorded source SHA-256")
			}
			report, err := ScanFile(strings.TrimSuffix(name, ".txt"), source)
			if err != nil {
				t.Fatal(err)
			}
			for _, rule := range required {
				if !hasRule(report, rule) {
					t.Errorf("historical bypass missed rule %q: %+v", rule, report.Findings)
				}
			}
			for _, finding := range report.Findings {
				t.Log(finding.String())
			}
			// Reintroduce the exact historical bytes as ordinary production Go in
			// a disposable tree; exercise the same directory scanner as the root gate.
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, strings.TrimSuffix(name, ".txt")), source, 0600); err != nil {
				t.Fatal(err)
			}
			reintroduced, err := ScanDir(root)
			if err != nil {
				t.Fatal(err)
			}
			for _, rule := range required {
				if !hasRule(reintroduced, rule) {
					t.Errorf("production reintroduction missed %q", rule)
				}
			}
		})
	}
}

func TestSDKPatternsAndReadOnlyClassification(t *testing.T) {
	cases := []struct {
		name, source, transaction string
		rules                     []string
	}{
		{"default import", `package p; import "go.etcd.io/etcd/client/v3"; func f(kv clientv3.KV){ kv.Txn(nil).Then(clientv3.OpPut("k","v")).Commit() }`, "write", []string{"sdk-import", "raw-kv", "sdk-write-operation", "txn-write"}},
		{"renamed import", `package p; import e "go.etcd.io/etcd/client/v3"; var raw e.KV; func f(){raw.Txn(nil).Then(e.OpDelete("k")).Commit()}`, "write", []string{"sdk-import", "raw-kv", "sdk-write-operation", "txn-write"}},
		{"read-only chain stays SDK denied", `package p; import e "go.etcd.io/etcd/client/v3"; func f(kv *e.Client){kv.Txn(nil).If().Then(e.OpGet("a")).Else(e.OpGet("b")).Commit()}`, "read-only", []string{"sdk-import"}},
		{"else write", `package p; import e "go.etcd.io/etcd/client/v3"; func f(kv e.KV){kv.Txn(nil).Then(e.OpGet("a")).Else(e.OpPut("b","c")).Commit()}`, "write", []string{"txn-write", "sdk-write-operation"}},
		{"opaque ops", `package p; import e "go.etcd.io/etcd/client/v3"; func f(kv e.KV, ops []e.Op){kv.Txn(nil).Then(ops...).Commit()}`, "unproven", []string{"sdk-import", "txn-unproven"}},
		{"mutable slice is not proven read-only", `package p; import e "go.etcd.io/etcd/client/v3"; func f(kv e.KV){ops:=[]e.Op{e.OpGet("k")}; mutate(ops); kv.Txn(nil).Then(ops...).Commit()}`, "unproven", []string{"txn-unproven"}},
		{"split builder", `package p; import e "go.etcd.io/etcd/client/v3"; func f(kv e.KV){tx:=kv.Txn(nil); tx.Then(e.OpPut("k","v")); tx.Commit()}`, "unproven", []string{"sdk-import", "sdk-write-operation", "txn-unproven"}},
		{"factory and method value", `package p; import e "go.etcd.io/etcd/client/v3"; var factory=e.New; var write=e.OpPut`, "", []string{"sdk-import", "client-constructor", "sdk-write-operation"}},
		{"client creation", `package p; import e "go.etcd.io/etcd/client/v3"; func f(){e.New(e.Config{});e.NewKVFromKVClient(nil,nil)}`, "", []string{"client-constructor", "sdk-import"}},
		{"direct mutations", `package p; import e "go.etcd.io/etcd/client/v3"; func f(kv e.KV){kv.Put(nil,"k","v");kv.Delete(nil,"k");kv.Do(nil,e.OpGet("k"))}`, "", []string{"raw-kv", "unproven-write-operation"}},
		{"raw RPC client", `package p; import pb "go.etcd.io/etcd/api/v3/etcdserverpb"; func f(){pb.NewKVClient(nil);_ = pb.PutRequest{}}`, "", []string{"sdk-import", "client-constructor", "sdk-write-operation"}},
		{"dot import", `package p; import . "go.etcd.io/etcd/client/v3"; var raw KV`, "", []string{"sdk-import", "opaque-sdk-import"}},
		{"blank import", `package p; import _ "go.etcd.io/etcd/client/v3"`, "", []string{"sdk-import", "opaque-sdk-import"}},
		{"legacy v2 client", `package p; import e "github.com/coreos/etcd/client"; var factory=e.New`, "", []string{"sdk-import", "client-constructor"}},
		{"legacy SDK", `package p; import e "github.com/coreos/etcd/clientv3"; var raw e.KV`, "", []string{"sdk-import", "raw-kv"}},
		{"other build target", "//go:build windows\n\npackage p\nimport e \"go.etcd.io/etcd/client/v3\"\nvar write=e.OpPut", "", []string{"sdk-import", "sdk-write-operation"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			report, err := ScanFile("production.go", []byte(tc.source))
			if err != nil {
				t.Fatal(err)
			}
			for _, rule := range tc.rules {
				if !hasRule(report, rule) {
					t.Errorf("missed rule %s: %+v", rule, report)
				}
			}
			if tc.transaction != "" {
				if len(report.Transactions) != 1 || report.Transactions[0].Kind != tc.transaction {
					t.Errorf("transaction classification: want %s, got %+v", tc.transaction, report.Transactions)
				}
				if tc.transaction == "read-only" && (hasRule(report, "txn-write") || hasRule(report, "txn-unproven") || hasRule(report, "sdk-write-operation")) {
					t.Fatal("read-only transaction misclassified as a write")
				}
			}
		})
	}
}

func TestMemoryAdaptersAreTestOnly(t *testing.T) {
	source := []byte(`package p; import e "go.etcd.io/etcd/client/v3"; func fixture(kv e.KV){kv.Txn(nil).Then(e.OpPut("k","v")).Commit()}`)
	test, err := ScanFile("adapter_test.go", source)
	if err != nil || len(test.Findings) != 0 || len(test.TestFiles) != 1 {
		t.Fatal("test-only fixture not separated", test, err)
	}
	production, err := ScanFile("adapter.go", source)
	if err != nil || !hasRule(production, "raw-kv") || !hasRule(production, "txn-write") {
		t.Fatal("renaming a test adapter into production escaped detection", production, err)
	}
}

func TestNoNameOnlyFalsePositives(t *testing.T) {
	report, err := ScanFile("production.go", []byte(`package p; import "database/sql"; const text="clientv3.OpPut Txn().Commit()"; func f(tx *sql.Tx){tx.Commit()}`))
	if err != nil || len(report.Findings) != 0 || len(report.Transactions) != 0 {
		t.Fatal("unrelated commit or string literal treated as SDK", report, err)
	}
	report, err = ScanFile("shadow.go", []byte(`package p; import e "go.etcd.io/etcd/client/v3"; func f(){e:=local; e.OpPut("k","v")}`))
	if err != nil || !hasRule(report, "sdk-import") || hasRule(report, "sdk-write-operation") {
		t.Fatal("shadowed identifier treated as SDK symbol", report, err)
	}
}

func TestDirectoryScanFailsClosedAndCoversNestedModules(t *testing.T) {
	t.Run("nested module and testdata", func(t *testing.T) {
		root := t.TempDir()
		for _, dir := range []string{"nested", "testdata", "vendor"} {
			if err := os.Mkdir(filepath.Join(root, dir), 0700); err != nil {
				t.Fatal(err)
			}
		}
		for name, content := range map[string]string{
			"vendor/wrapper.go":      `package p; import e "go.etcd.io/etcd/client/v3"; var factory=e.New`,
			"go.mod":                 "module example.invalid/audit\n",
			"nested/go.mod":          "module example.invalid/nested\n",
			"nested/adapter.go":      `package p; import e "go.etcd.io/etcd/client/v3"; var raw e.KV`,
			"adapter_test.go":        `package p; import e "go.etcd.io/etcd/client/v3"; var raw e.KV`,
			"testdata/not-source.go": "deliberately invalid Go fixture",
		} {
			if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
		}
		report, err := ScanDir(root)
		if err != nil || !hasRule(report, "raw-kv") || !hasRule(report, "client-constructor") || report.GoFiles != 2 || len(report.TestFiles) != 1 {
			t.Fatal("nested module skipped or test fixture included", report, err)
		}
	})
	t.Run("testdata import", func(t *testing.T) {
		report, err := ScanFile("production.go", []byte(`package p; import _ "example.invalid/module/testdata/adapter"`))
		if err != nil || !hasRule(report, "excluded-package-import") {
			t.Fatal("testdata import escaped policy", report, err)
		}
	})
	t.Run("parse failure", func(t *testing.T) {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "broken.go"), []byte("package {"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := ScanDir(root); err == nil {
			t.Fatal("malformed production source silently skipped")
		}
	})
	t.Run("symlink", func(t *testing.T) {
		root := t.TempDir()
		if err := os.Symlink("missing", filepath.Join(root, "hidden.go")); err != nil {
			t.Fatal(err)
		}
		if _, err := ScanDir(root); err == nil {
			t.Fatal("symlinked source silently skipped")
		}
	})
}
