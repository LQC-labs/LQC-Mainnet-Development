// SPDX-License-Identifier: Apache-2.0
// Package securityaudit enforces the current no-SDK production boundary.
// It is a source-level regression guard, not an authorization or RBAC service.
package securityaudit

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type Finding struct {
	File, Rule, Detail string
	Line               int
}

func (f Finding) String() string {
	return fmt.Sprintf("%s:%d: %s: %s", f.File, f.Line, f.Rule, f.Detail)
}

type Transaction struct {
	File, Kind string // read-only, write, or unproven
	Line       int
}

type Report struct {
	Findings     []Finding
	Transactions []Transaction
	TestFiles    []string
	GoFiles      int
}

func sdkImport(path string) bool {
	return strings.HasPrefix(path, "go.etcd.io/etcd/") ||
		path == "github.com/coreos/etcd/client" ||
		path == "github.com/coreos/etcd/clientv3" ||
		strings.HasPrefix(path, "github.com/coreos/etcd/clientv3/") ||
		strings.HasPrefix(path, "github.com/coreos/etcd/client/")
}

func importName(path string) string {
	if path == "go.etcd.io/etcd/client/v3" || path == "github.com/coreos/etcd/clientv3" {
		return "clientv3"
	}
	return filepath.Base(path)
}

// ScanFile rejects every etcd SDK import in production, including read-only SDK
// use. This deliberately stronger rule also catches method values, aliases and
// split builder chains that a syntactic write-call inventory cannot fully trace.
// Read-only classification is diagnostic, never an exception to that policy.
func ScanFile(name string, source []byte) (Report, error) {
	var report Report
	if strings.HasSuffix(name, "_test.go") {
		report.TestFiles = append(report.TestFiles, name)
		return report, nil
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, name, source, 0)
	if err != nil {
		return report, fmt.Errorf("parse %s: %w", name, err)
	}
	report.GoFiles = 1
	aliases := make(map[string]bool)
	add := func(pos token.Pos, rule, detail string) {
		report.Findings = append(report.Findings, Finding{name, rule, detail, fset.Position(pos).Line})
	}
	for _, spec := range file.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			return report, err
		}
		if strings.Contains("/"+path+"/", "/testdata/") {
			add(spec.Pos(), "excluded-package-import", "production must not import excluded testdata packages")
		}
		if !sdkImport(path) {
			continue
		}
		add(spec.Pos(), "sdk-import", "etcd SDK is not approved in the production module: "+path)
		alias := importName(path)
		if spec.Name != nil {
			alias = spec.Name.Name
		}
		aliases[alias] = true
		if alias == "." || alias == "_" {
			add(spec.Pos(), "opaque-sdk-import", "dot/blank SDK imports cannot create a policy exception")
		}
	}
	if len(aliases) == 0 {
		return report, nil
	}
	qualified := func(expr ast.Expr) (*ast.SelectorExpr, bool) {
		sel, ok := expr.(*ast.SelectorExpr)
		if !ok {
			return nil, false
		}
		id, ok := sel.X.(*ast.Ident)
		// Local shadowing must not be mistaken for an SDK symbol.
		return sel, ok && id.Obj == nil && aliases[id.Name]
	}
	unparen := func(expr ast.Expr) ast.Expr {
		for {
			p, ok := expr.(*ast.ParenExpr)
			if !ok {
				return expr
			}
			expr = p.X
		}
	}
	merge := func(a, b string) string {
		if a == "write" || b == "write" {
			return "write"
		}
		if a == "unproven" || b == "unproven" {
			return "unproven"
		}
		return "read-only"
	}
	var operation func(ast.Expr, int) string
	operation = func(expr ast.Expr, depth int) string {
		if depth > 12 {
			return "unproven"
		}
		expr = unparen(expr)
		if call, ok := expr.(*ast.CallExpr); ok {
			if sel, ok := qualified(unparen(call.Fun)); ok {
				switch sel.Sel.Name {
				case "OpGet":
					return "read-only"
				case "OpPut", "OpDelete":
					return "write"
				}
			}
		}
		if list, ok := expr.(*ast.CompositeLit); ok {
			kind := "read-only"
			for _, item := range list.Elts {
				kind = merge(kind, operation(item, depth+1))
			}
			return kind
		}
		return "unproven"
	}
	ast.Inspect(file, func(node ast.Node) bool {
		if sel, ok := node.(*ast.SelectorExpr); ok {
			if sdk, ok := qualified(sel); ok {
				switch sdk.Sel.Name {
				case "KV":
					add(sel.Pos(), "raw-kv", "raw SDK KV type/argument/field crosses the boundary")
				case "OpPut", "OpDelete", "PutRequest", "DeleteRangeRequest":
					add(sel.Pos(), "sdk-write-operation", sdk.Sel.Name)
				case "New", "NewFromURL", "NewCtxClient", "NewKV", "NewKVFromKVClient", "NewKVClient":
					add(sel.Pos(), "client-constructor", "unapproved SDK/client constructor: "+sdk.Sel.Name)
				}
			}
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if sel.Sel.Name == "Put" || sel.Sel.Name == "Delete" || sel.Sel.Name == "Do" {
			add(call.Pos(), "unproven-write-operation", "SDK-bearing file invokes "+sel.Sel.Name)
		}
		if sel.Sel.Name != "Commit" {
			return true
		}
		kind, hasTxn, hasOps := "read-only", false, false
		cursor := sel.X
		for depth := 0; depth < 24; depth++ {
			step, ok := cursor.(*ast.CallExpr)
			if !ok {
				kind = merge(kind, "unproven")
				break
			}
			method, ok := step.Fun.(*ast.SelectorExpr)
			if !ok {
				kind = merge(kind, "unproven")
				break
			}
			if method.Sel.Name == "Txn" {
				hasTxn = true
				break
			}
			switch method.Sel.Name {
			case "Then", "Else":
				hasOps = true
				for _, arg := range step.Args {
					kind = merge(kind, operation(arg, 0))
				}
			case "If":
			default:
				kind = merge(kind, "unproven")
			}
			cursor = method.X
		}
		if !hasTxn || !hasOps {
			kind = merge(kind, "unproven")
		}
		report.Transactions = append(report.Transactions, Transaction{name, kind, fset.Position(call.Pos()).Line})
		if kind != "read-only" {
			add(call.Pos(), "txn-"+kind, "Commit is "+kind+"; no operational exception is approved")
		}
		return true
	})
	return report, nil
}

// ScanDir checks all platform/build-tag variants and nested modules. Test files
// and testdata trees are excluded. Vendored source is scanned conservatively.
// Importing testdata is itself rejected; symlinks and parse/I/O failures fail closed.
func ScanDir(root string) (Report, error) {
	var report Report
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("unreviewed symlink: %s", path)
		}
		if entry.IsDir() {
			if path != root && (entry.Name() == ".git" || entry.Name() == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("non-regular Go source: %s", path)
		}
		name, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if strings.HasSuffix(path, "_test.go") {
			report.TestFiles = append(report.TestFiles, name)
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		r, err := ScanFile(name, data)
		if err != nil {
			return err
		}
		report.GoFiles += r.GoFiles
		report.Findings = append(report.Findings, r.Findings...)
		report.Transactions = append(report.Transactions, r.Transactions...)
		return nil
	})
	sort.Slice(report.Findings, func(i, j int) bool {
		a, b := report.Findings[i], report.Findings[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Rule < b.Rule
	})
	return report, err
}
