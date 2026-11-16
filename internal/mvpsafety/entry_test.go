package mvpsafety

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cosmos/cosmos-sdk/types/bech32"
)

func entryRequest(t *testing.T) MVPRequest {
	t.Helper()
	cfg := config(t)
	co, _ := coordinator(t)
	a := GoAdapter{Config: cfg}
	request, e := a.PrepareMVP(context.Background(), co, co.plan, true, mvpPublicAccounts(t, co.plan.RunID), &fakeMVPBoundary{})
	if e != nil {
		t.Fatal(e)
	}
	return request
}
func entryState(r MVPRequest) EntryState {
	key := strings.Repeat("12", 32)
	s := EntryState{CosmosChainID: CosmosID, EVMChainID: EVMID, Denom: "atest", Supply: r.Options.Total, BondedBalance: r.Policy.ValidatorBond}
	var deployer string
	for _, v := range r.Options.Accounts {
		amount := v.Amount
		if v.Role == "deployer" {
			amount = "29000000000000000000"
			deployer = v.Address
		}
		s.Accounts = append(s.Accounts, EntryAccount{Role: v.Role, Address: v.Address, PublicKeyHex: v.PublicKeyHex, Balance: amount})
	}
	_, raw, _ := bech32.DecodeAndConvert(deployer)
	operator, _ := bech32.ConvertAndEncode("lqctestvaloper", raw)
	s.Validators = []EntryValidator{{Operator: operator, PublicKeyHex: key, Tokens: r.Policy.ValidatorBond, Shares: "1000000000000000000.000000000000000000", Power: 1, Bonded: true}}
	s.Updates = []EntryValidator{{PublicKeyHex: key, Power: 1}}
	s.Delegations = []EntryDelegation{{Delegator: deployer, Operator: operator, Shares: s.Validators[0].Shares}}
	return s
}

type fakeEntry struct {
	calls        []string
	state        EntryState
	badSignature bool
	cancel       context.CancelFunc
}

func (f *fakeEntry) VerifySignedGenesis(context.Context, MVPRequest, []byte) error {
	f.calls = append(f.calls, "fake-validate-signed-input")
	if f.badSignature {
		return errors.New("fake invalid signature")
	}
	if f.cancel != nil {
		f.cancel()
	}
	return nil
}
func (f *fakeEntry) InitAndObserve(context.Context, MVPRequest, []byte) (EntryState, error) {
	f.calls = append(f.calls, "fake-InitChain-and-query")
	return f.state, nil
}
func TestEntryRuntimeBoundaryOffline(t *testing.T) {
	for _, name := range []string{"valid_fake_only", "signature_rejected", "cancel_after_signature", "supply", "deployer_liquid", "other_balance", "account_key", "duplicate_account", "bond", "wrong_chain", "wrong_denom", "validator_key", "power", "jailed", "delegation", "zero_shares", "committed", "height"} {
		t.Run(name, func(t *testing.T) {
			r := entryRequest(t)
			s := entryState(r)
			f := &fakeEntry{state: s}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch name {
			case "signature_rejected":
				f.badSignature = true
			case "cancel_after_signature":
				f.cancel = cancel
			case "supply":
				f.state.Supply = "101000000000000000000"
			case "deployer_liquid":
				f.state.Accounts[0].Balance = "30000000000000000000"
			case "other_balance":
				f.state.Accounts[1].Balance = "1"
			case "account_key":
				f.state.Accounts[1].PublicKeyHex = "bad"
			case "duplicate_account":
				f.state.Accounts[1] = f.state.Accounts[0]
			case "bond":
				f.state.BondedBalance = "0"
			case "wrong_chain":
				f.state.EVMChainID = 97
			case "wrong_denom":
				f.state.Denom = "stake"
			case "validator_key":
				f.state.Validators[0].PublicKeyHex = strings.Repeat("34", 32)
			case "power":
				f.state.Updates[0].Power = 2
			case "jailed":
				f.state.Validators[0].Jailed = true
			case "delegation":
				f.state.Delegations[0].Delegator = "other"
			case "zero_shares":
				f.state.Validators[0].Shares = "0"
				f.state.Delegations[0].Shares = "0"
			case "committed":
				f.state.VersionAfter = 1
			case "height":
				f.state.Height = 1
			}
			_, e := VerifyMVPEntry(ctx, r, []byte("FAKE-NOT-SIGNED-GENESIS"), strings.Repeat("12", 32), f)
			if (e == nil) != (name == "valid_fake_only") {
				t.Fatal(e)
			}
			if (name == "signature_rejected" || name == "cancel_after_signature") && len(f.calls) != 1 {
				t.Fatal("InitChain boundary reached")
			}
			t.Logf("fakeCalls=%v result=%v; real gentx/InitChain/Open calls=0", f.calls, e)
		})
	}
}

type entryProbe struct {
	fail  string
	calls []string
}

func (p *entryProbe) ListenerClosed(context.Context, string) error {
	p.calls = append(p.calls, "rpc")
	if p.fail == "rpc" {
		return errors.New("fake listener present")
	}
	return nil
}
func (p *entryProbe) DBsClosed(context.Context, string) error {
	p.calls = append(p.calls, "db")
	if p.fail == "db" {
		return errors.New("fake DB lock retained")
	}
	return nil
}
func (p *entryProbe) HomeUnlocked(context.Context, string) error {
	p.calls = append(p.calls, "home")
	if p.fail == "home" {
		return errors.New("fake home lock retained")
	}
	return nil
}
func TestEntryCleanupObservationOffline(t *testing.T) {
	for _, name := range []string{"normal", "rpc", "db", "home", "node_close_failure", "child_wait_failure", "child_group_present"} {
		t.Run(name, func(t *testing.T) {
			co, _ := coordinator(t)
			owner := &resource{label: "fake-Core"}
			child := &resource{label: "fake-child"}
			probe := &entryProbe{fail: name}
			groupCalled := 0
			group := func(context.Context) error {
				groupCalled++
				if name == "child_group_present" {
					return errors.New("fake child group remains")
				}
				return nil
			}
			if name == "node_close_failure" {
				owner.closeErr = errors.New("fake Core Close error")
			}
			if name == "child_wait_failure" {
				child.verifyErr = errors.New("fake unreaped child")
			}
			ob, e := NewCleanupObservation(co.plan, "127.0.0.1:8545", owner, probe, []Resource{ProcessObservation{Owned: child, GroupGone: group}})
			if e != nil {
				t.Fatal(e)
			}
			if e = co.Register(ob); e != nil {
				t.Fatal(e)
			}
			report, e := co.Run(context.Background(), []Step{{Name: "offline-observation", Run: func(context.Context) error { return nil }}})
			if (e == nil) != (name == "normal") {
				t.Fatal(report, e)
			}
			if len(probe.calls) != 3 || groupCalled != 1 || owner.closed != 1 || child.closed != 1 {
				t.Fatal("independent cleanup probes missing", probe.calls, groupCalled)
			}
			trace := ob.Trace()
			if len(trace) != 7 {
				t.Fatal(trace)
			}
			for i := 1; i < len(trace); i++ {
				if trace[i].ElapsedNS < trace[i-1].ElapsedNS {
					t.Fatal("monotonic trace")
				}
			}
			if _, e = co.Run(context.Background(), nil); e == nil {
				t.Fatal("continuation allowed")
			}
			t.Logf("status=%s independentProbes=%v trace=%+v", report.Status, probe.calls, trace)
		})
	}
}
func TestEntryDefaultRealBackendBlocked(t *testing.T) {
	b := SDKEntryBackend{}
	if b.VerifySignedGenesis(context.Background(), MVPRequest{}, nil) == nil {
		t.Fatal("unapproved backend activated")
	}
	if _, e := b.InitAndObserve(context.Background(), MVPRequest{}, nil); e == nil {
		t.Fatal("unapproved InitChain activated")
	}
	t.Log("default real backend rejects before app/signature/InitChain access")
}
func TestEntryCleanupExternalAddressRejected(t *testing.T) {
	co, _ := coordinator(t)
	if _, e := NewCleanupObservation(co.plan, "0.0.0.0:8545", &resource{label: "fake"}, &entryProbe{}, nil); e == nil {
		t.Fatal("external listener probe accepted")
	}
}

func TestEntryCoordinatorConnectionOffline(t *testing.T) {
	for _, name := range []string{"normal", "timeout", "policy_mismatch"} {
		t.Run(name, func(t *testing.T) {
			co, _ := coordinator(t)
			cfg := config(t)
			a := GoAdapter{Config: cfg}
			r, e := a.PrepareMVP(context.Background(), co, co.plan, true, mvpPublicAccounts(t, co.plan.RunID), &fakeMVPBoundary{})
			if e != nil {
				t.Fatal(e)
			}
			owner := &resource{label: "fake-memory-app"}
			if e = co.Register(owner); e != nil {
				t.Fatal(e)
			}
			base := &fakeEntry{state: entryState(r)}
			backend := &deadlineEntry{fakeEntry: base, wait: name == "timeout"}
			if name == "policy_mismatch" {
				r.Policy.MaxGasPerTx = 4999999
			}
			step, e := MVPEntryStep(co, r, []byte("FAKE"), strings.Repeat("12", 32), backend)
			if name == "policy_mismatch" {
				if e == nil {
					t.Fatal("mismatched policy accepted")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			start := time.Now()
			report, e := co.Run(context.Background(), []Step{step})
			if (e == nil) != (name == "normal") || owner.closed != 1 || owner.verified != 1 {
				t.Fatal(report, e)
			}
			if name == "timeout" && time.Since(start) > time.Second {
				t.Fatal("unbounded fake wait")
			}
			t.Logf("coordinator=%s close=%d verify=%d fakeCalls=%v elapsed=%s", report.Status, owner.closed, owner.verified, base.calls, time.Since(start))
		})
	}
}

type deadlineEntry struct {
	*fakeEntry
	wait bool
}

func (d *deadlineEntry) InitAndObserve(ctx context.Context, r MVPRequest, raw []byte) (EntryState, error) {
	if _, ok := ctx.Deadline(); !ok {
		return EntryState{}, errors.New("missing step timeout")
	}
	if d.wait {
		<-ctx.Done()
		return EntryState{}, ctx.Err()
	}
	return d.fakeEntry.InitAndObserve(ctx, r, raw)
}
