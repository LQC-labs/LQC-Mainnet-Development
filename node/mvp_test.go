//go:build linux

package node

import (
	"github.com/LQC-labs/LQC-Mainnet-Development/genesis"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"testing"
)

func TestMVPOptInBeforeHomeAccess(t *testing.T) {
	if _, e := OpenMVP("/must-not-access", genesis.MVPOptions{}); e == nil {
		t.Fatal("default options accepted")
	}
	t.Log("MVP opt-in rejection occurs before openValidated/home/key/DB access")
}
func TestMVPDefaultDispatchUnchanged(t *testing.T) {
	raw, e := os.ReadFile("node.go")
	if e != nil {
		t.Fatal(e)
	}
	file, e := parser.ParseFile(token.NewFileSet(), "node.go", raw, 0)
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, decl := range file.Decls {
		f, ok := decl.(*ast.FuncDecl)
		if !ok || f.Name.Name != "Open" {
			continue
		}
		if len(f.Body.List) != 1 {
			t.Fatal("unexpected default Open")
		}
		ret, ok := f.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			t.Fatal("dispatch")
		}
		call, ok := ret.Results[0].(*ast.CallExpr)
		if !ok || len(call.Args) != 2 {
			t.Fatal("dispatch args")
		}
		fn, ok := call.Fun.(*ast.Ident)
		if !ok || fn.Name != "openValidated" {
			t.Fatal("default target")
		}
		validator, ok := call.Args[1].(*ast.Ident)
		if !ok || validator.Name != "validateDevnetGenesis" {
			t.Fatal("default validator changed")
		}
		found = true
	}
	if !found {
		t.Fatal("Open not found")
	}
	t.Log("default Open statically dispatches to unchanged legacy validator; no runtime Open called")
}
