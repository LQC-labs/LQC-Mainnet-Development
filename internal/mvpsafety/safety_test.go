package mvpsafety

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/LQC-labs/LQC-Mainnet-Development/internal/flowtestassets"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func config(t *testing.T) Config {
	t.Helper()
	root := flowtestassets.Require(t)
	c, e := LoadConfig(root)
	if e != nil {
		t.Fatal(e)
	}
	return c
}

type fakeFS map[string]PathInfo

func (f fakeFS) Inspect(p string) (PathInfo, error) { return f[p], nil }
func plan(t *testing.T, p Policy) Plan {
	t.Helper()
	v, e := MakePlan(p, "offline123", fakeFS{"/": {Exists: true}, "/tmp": {Exists: true}})
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func intent(kind, amount string) Intent {
	return Intent{ID: "one", Kind: kind, FromRole: "deployer", Amount: amount, GasLimit: 5000000, GasEstimate: 100000, MaxFeePerGas: "2000000000", ChainID: EVMID}
}
func TestIntegerAndFundingGuards(t *testing.T) {
	for _, s := range []string{"-1", "+1", "1.0", "01", "1e18", "", strings.Repeat("9", 79)} {
		t.Run("invalid_"+s, func(t *testing.T) {
			if _, e := Units(s); e == nil {
				t.Fatal("accepted")
			}
		})
	}
	for name, change := range map[string]func(*Policy){"total_over": func(p *Policy) { p.GenesisTotal = "101000000000000000000" }, "negative": func(p *Policy) { p.Allocations[0].Amount = "-1" }, "duplicate": func(p *Policy) { p.Allocations[1].Role = "deployer" }, "chain56": func(p *Policy) { p.EVMChainID = 56 }, "chain97": func(p *Policy) { p.EVMChainID = 97 }, "cosmos": func(p *Policy) { p.CosmosChainID = "other" }, "old_key": func(p *Policy) { s := "/old/key"; p.Accounts[0].KeyPath = &s }, "enabled": func(p *Policy) { p.AllowNode = true }, "runtime": func(p *Policy) { p.TotalSeconds = 241 }} {
		t.Run(name, func(t *testing.T) {
			p := config(t).Policy
			change(&p)
			if p.Validate() == nil {
				t.Fatal("accepted")
			}
		})
	}
	t.Run("gross_and_bond", func(t *testing.T) {
		p := config(t).Policy
		v := plan(t, p)
		if v.Gross["deployer"] != "30000000000000000000" || v.PostBond["deployer"] != "29000000000000000000" || v.Bonded != "1000000000000000000" {
			t.Fatal(v)
		}
		if _, e := Units("0"); e != nil {
			t.Fatal(e)
		}
	})
}
func TestBudgetGuards(t *testing.T) {
	for _, tc := range []struct {
		name, kind, amount string
		change             func(*Intent)
	}{
		{"mintA_over", "mintA", "1000000000000000000001", nil}, {"mintB_over", "mintB", "1000000001", nil}, {"wrapper_over", "deposit", "10000000000000000001", nil}, {"negative", "mintA", "-1", nil}, {"gas_over", "deploy", "0", func(i *Intent) { i.GasLimit = 5000001 }}, {"estimate_over", "deploy", "0", func(i *Intent) { i.GasEstimate = 5000001 }}, {"missing_estimate", "deploy", "0", func(i *Intent) { i.GasEstimate = 0 }}, {"bad_chain", "deploy", "0", func(i *Intent) { i.ChainID = 97 }}, {"old_account", "deploy", "0", func(i *Intent) { i.UseExistingAccount = true }}, {"fee_over", "deploy", "0", func(i *Intent) { i.MaxFeePerGas = "2000000001" }}, {"unknown", "whatever", "0", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, _ := NewBudget(config(t).Policy)
			i := intent(tc.kind, tc.amount)
			if tc.change != nil {
				tc.change(&i)
			}
			if b.Reserve(i) == nil {
				t.Fatal("accepted")
			}
			j := intent("deploy", "0")
			j.ID = "next"
			if !errors.Is(b.Reserve(j), ErrBlocked) {
				t.Fatal("continuation allowed")
			}
		})
	}
	for _, tc := range []struct{ kind, cap string }{{"mintA", "1000000000000000000000"}, {"mintB", "1000000000"}, {"deposit", "10000000000000000000"}} {
		t.Run(tc.kind+"_cumulative", func(t *testing.T) {
			b, _ := NewBudget(config(t).Policy)
			if e := b.Reserve(intent(tc.kind, tc.cap)); e != nil {
				t.Fatal(e)
			}
			i := intent(tc.kind, "1")
			i.ID = "two"
			if b.Reserve(i) == nil {
				t.Fatal("over cap")
			}
		})
	}
	t.Run("duplicate", func(t *testing.T) {
		b, _ := NewBudget(config(t).Policy)
		i := intent("mintA", "1")
		if e := b.Reserve(i); e != nil {
			t.Fatal(e)
		}
		if b.Reserve(i) == nil || b.Totals()["mintA"] != "1" {
			t.Fatal("duplicate counted")
		}
	})
}
func TestFreshPlanGuards(t *testing.T) {
	for _, name := range []string{"existing_root", "existing_home", "symlink", "home_overlap", "key_overlap", "home_ancestor"} {
		t.Run(name, func(t *testing.T) {
			p := config(t).Policy
			f := fakeFS{"/": {Exists: true}, "/tmp": {Exists: true}}
			root := "/tmp/lqc-stage7-offline123"
			switch name {
			case "existing_root":
				f[root] = PathInfo{Exists: true}
			case "existing_home":
				f[root+"/home"] = PathInfo{Exists: true}
			case "symlink":
				f[root+"/keys"] = PathInfo{Exists: true, Symlink: true}
			case "home_overlap":
				p.ExistingHomes = append(p.ExistingHomes, root+"/old")
			case "key_overlap":
				p.ExistingKeyPaths = append(p.ExistingKeyPaths, root+"/keys/a")
			case "home_ancestor":
				f["/tmp/config/genesis.json"] = PathInfo{Exists: true}
			}
			if _, e := MakePlan(p, "offline123", f); e == nil {
				t.Fatal("accepted")
			}
		})
	}
	t.Run("tamper", func(t *testing.T) {
		p := config(t).Policy
		v := plan(t, p)
		v.Home = "/old"
		if _, e := NewCoordinator(p, v, &sink{}); e == nil {
			t.Fatal("tampered plan accepted")
		}
	})
}
func TestStrictJSON(t *testing.T) {
	for _, raw := range []string{`{"a":1,"A":2}`, `{"a":1} {}`, `{"unknown":1}`} {
		t.Run(raw, func(t *testing.T) {
			var v struct{ A int }
			if DecodeStrict([]byte(raw), &v) == nil {
				t.Fatal("accepted")
			}
		})
	}
}

type sink struct {
	err   error
	saved Report
}

func (s *sink) Save(_ context.Context, r Report) (string, error) {
	s.saved = r
	if s.err != nil {
		return "", s.err
	}
	h := sha256.Sum256([]byte("offline-evidence"))
	return hex.EncodeToString(h[:]), nil
}

type resource struct {
	label               string
	closeErr, verifyErr error
	closed, verified    int
}

func (r *resource) Name() string                       { return r.label }
func (r *resource) Close(context.Context) error        { r.closed++; return r.closeErr }
func (r *resource) VerifyClosed(context.Context) error { r.verified++; return r.verifyErr }
func coordinator(t *testing.T) (*Coordinator, *sink) {
	t.Helper()
	p := config(t).Policy
	s := &sink{}
	c, e := NewCoordinator(p, plan(t, p), s)
	if e != nil {
		t.Fatal(e)
	}
	c.limits = timing{time.Second, 30 * time.Millisecond, 300 * time.Millisecond, 30 * time.Millisecond, 30 * time.Millisecond}
	return c, s
}
func TestCleanupAndCancellation(t *testing.T) {
	for _, name := range []string{"normal", "cancel", "timeout", "child_termination_failure", "rpc_still_open", "db_lock_retained", "home_lock_retained", "evidence_failure"} {
		t.Run(name, func(t *testing.T) {
			c, s := coordinator(t)
			r := &resource{label: "fake-node"}
			if e := c.Register(r); e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			run := func(context.Context) error { return nil }
			switch name {
			case "cancel":
				cancel()
			case "timeout":
				run = func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }
			case "child_termination_failure":
				r.closeErr = errors.New("fake child not reaped")
			case "rpc_still_open", "db_lock_retained", "home_lock_retained":
				r.verifyErr = errors.New(name)
			case "evidence_failure":
				s.err = errors.New("disk evidence failed")
			}
			next := false
			steps := []Step{{Name: "step", Run: run}}
			if name == "timeout" || name == "cancel" {
				steps = append(steps, Step{Name: "forbidden_next", Run: func(context.Context) error { next = true; return nil }})
			}
			report, e := c.Run(ctx, steps)
			if name == "normal" {
				if e != nil || report.Status != "PASS" || s.saved.Status != "CHECKS_COMPLETE" {
					t.Fatal(report, e)
				}
			} else {
				if e == nil || report.Status != "BLOCKED" {
					t.Fatal(report, e)
				}
			}
			if r.closed != 1 || r.verified != 1 || next {
				t.Fatal("cleanup/continuation", r, next)
			}
			if _, e = c.Run(context.Background(), nil); e == nil {
				t.Fatal("second run allowed")
			}
			t.Logf("status=%s cleanup=%d verify=%d next=%v events=%v errors=%v", report.Status, r.closed, r.verified, next, report.Events, report.Errors)
		})
	}
}
func TestChildCancellationReaps(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	child, e := StartChild(ctx, "/bin/sleep", []string{"30"}, 20*time.Millisecond)
	if e != nil {
		cancel()
		t.Fatal(e)
	}
	cancel()
	clean, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if e = child.Close(clean); e != nil {
		t.Fatal(e)
	}
	if e = child.VerifyClosed(clean); e != nil {
		t.Fatal(e)
	}
	t.Log("benign sleep process group terminated; cmd.Wait completed/reaped; no node started")
}
func TestEvidenceExclusiveAndHashed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.json")
	s := FileEvidenceSink{path: path}
	h, e := s.Save(context.Background(), Report{Status: "CHECKS_COMPLETE"})
	if e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(raw)
	if h != hex.EncodeToString(sum[:]) {
		t.Fatal("hash")
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0600 {
		t.Fatal("mode")
	}
	if _, e = s.Save(context.Background(), Report{}); e == nil {
		t.Fatal("overwritten")
	}
	t.Log("evidence fsync/hash/0600/exclusive create PASS")
}

func TestCancellationDuringStep(t *testing.T) {
	c, _ := coordinator(t)
	ctx, cancel := context.WithCancel(context.Background())
	r := &resource{label: "fake"}
	if e := c.Register(r); e != nil {
		t.Fatal(e)
	}
	next := false
	report, e := c.Run(ctx, []Step{{Name: "cancel-midstep", Run: func(ctx context.Context) error { cancel(); <-ctx.Done(); return ctx.Err() }}, {Name: "next", Run: func(context.Context) error { next = true; return nil }}})
	if e == nil || report.Status != "BLOCKED" || next || r.closed != 1 || r.verified != 1 {
		t.Fatal(report, e, r, next)
	}
}
func TestUnjoinedCleanupBlocksContinuation(t *testing.T) {
	c, _ := coordinator(t)
	release := make(chan struct{})
	joined := make(chan struct{})
	resource := &blockingResource{release: release, joined: joined}
	if e := c.Register(resource); e != nil {
		t.Fatal(e)
	}
	r, e := c.Run(context.Background(), nil)
	close(release)
	select {
	case <-joined:
	case <-time.After(time.Second):
		t.Fatal("test fake callback leaked")
	}
	if e == nil || r.Status != "BLOCKED" || !r.UnjoinedCallback {
		t.Fatal(r, e)
	}
	if _, e = c.Run(context.Background(), nil); e == nil {
		t.Fatal("continued")
	}
	t.Log("noncooperative fake close hit bounded deadline; PASS denied; next run blocked; fake released/joined by test")
}

type blockingResource struct{ release, joined chan struct{} }

func (b *blockingResource) Name() string                       { return "noncooperative-fake" }
func (b *blockingResource) Close(context.Context) error        { <-b.release; close(b.joined); return nil }
func (b *blockingResource) VerifyClosed(context.Context) error { return errors.New("cleanup unproven") }
func TestTransactionCountCap(t *testing.T) {
	p := config(t).Policy
	p.MaxTransactions = 1
	b, _ := NewBudget(p)
	i := intent("deploy", "0")
	if e := b.Reserve(i); e != nil {
		t.Fatal(e)
	}
	i.ID = "two"
	if b.Reserve(i) == nil {
		t.Fatal("transaction cap exceeded")
	}
}
