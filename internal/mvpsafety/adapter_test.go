package mvpsafety

import (
	"bytes"
	"context"
	"errors"
	"math/big"
	"strings"
	"testing"

	corenode "github.com/LQC-labs/LQC-Mainnet-Development/node"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
)

func TestConfigAndEndpointGuards(t *testing.T) {
	for name, change := range map[string]func(*Config){"chain": func(c *Config) { c.Profile.Network.ChainID = 97 }, "external_rpc": func(c *Config) { c.Profile.Network.RPCURLs = []string{"http://8.8.8.8:8545"} }, "router2_namespace": func(c *Config) { c.Manifest.InterfaceFamily = "router2" }, "production": func(c *Config) { c.Profile.Source.ProductionApproved = true }, "BSC_asset": func(c *Config) {
		a := c.Profile.Assets["tokenA"]
		s := "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c"
		a.Address = &s
		c.Profile.Assets["tokenA"] = a
	}} {
		t.Run(name, func(t *testing.T) {
			c := config(t)
			change(&c)
			if c.Validate() == nil {
				t.Fatal("accepted")
			}
		})
	}
	for _, s := range []string{"https://127.0.0.1:8545", "http://localhost:8545", "http://127.0.0.1:8545?x=1", "http://user@127.0.0.1:8545", "http://0.0.0.0:8545"} {
		t.Run(s, func(t *testing.T) {
			if _, e := LocalRPC(s); e == nil {
				t.Fatal("accepted")
			}
		})
	}
	for s := range bsc {
		t.Run("reject_"+s, func(t *testing.T) {
			if _, e := LocalAddress(s); e == nil {
				t.Fatal("accepted")
			}
		})
	}
}
func bindings(p Plan) FreshBindings {
	return FreshBindings{ChainID: EVMID, RunID: p.RunID, NewlyGenerated: true, Addresses: map[string]string{"deployer": "0x0000000000000000000000000000000000000011", "mvp.factory": "0x0000000000000000000000000000000000000022", "mvp.tokenA": "0x0000000000000000000000000000000000000033", "mvp.tokenB": "0x0000000000000000000000000000000000000044", "mvp.wrappedNative": "0x0000000000000000000000000000000000000055"}}
}
func TestConstructorAndOrder(t *testing.T) {
	c := config(t)
	p := plan(t, c.Policy)
	steps, e := c.DeploymentPlan()
	if e != nil {
		t.Fatal(e)
	}
	if len(steps) != 7 {
		t.Fatal(steps)
	}
	for i, id := range IDs {
		if steps[i].ID != id {
			t.Fatal("order")
		}
		op, e := c.EncodeStep(p, id, bindings(p))
		if e != nil {
			t.Fatal(id, e)
		}
		if op.ChainID != EVMID || op.GasLimit > 5000000 || op.ProductionApproved || len(op.Data) == 0 {
			t.Fatal(op)
		}
		if strings.HasPrefix(id, "mvp.pair") != (op.To != nil) {
			t.Fatal("Pair must be Factory internal CREATE")
		}
		t.Logf("%s artifact=%s constructor=%v refs=%v unsignedBytes=%d", id, steps[i].Artifact, steps[i].ConstructorTypes, steps[i].References, len(op.Data))
	}
}
func TestConstructorGasAndBindingRejection(t *testing.T) {
	for _, name := range []string{"gas_too_small", "old_account", "router2", "wrong_chain"} {
		t.Run(name, func(t *testing.T) {
			c := config(t)
			p := plan(t, c.Policy)
			b := bindings(p)
			switch name {
			case "gas_too_small":
				c.Policy.MaxGasPerTx = 1
			case "old_account":
				c.Policy.ExistingAccounts = []string{b.Addresses["deployer"]}
			case "router2":
				b.Addresses["quoteRouter"] = b.Addresses["mvp.factory"]
			case "wrong_chain":
				b.ChainID = 56
			}
			if _, e := c.EncodeStep(p, "mvp.router", b); e == nil {
				t.Fatal("accepted")
			}
		})
	}
}

type fakeNode struct {
	started, rpc, closed int
	failStart            bool
}

func (n *fakeNode) Start(context.Context) error {
	n.started++
	if n.failStart {
		return errors.New("fake start failure")
	}
	return nil
}
func (n *fakeNode) StartEVMRPCWithOptions(_ context.Context, addr string, o corenode.RPCBrowserOptions) (string, error) {
	n.rpc++
	if len(o.AllowedOrigins) != 1 || o.AllowedOrigins[0] != "http://localhost:3000" {
		return "", errors.New("origin")
	}
	return addr, nil
}
func (n *fakeNode) Close() error { n.closed++; return nil }

type factory struct {
	n       *fakeNode
	opens   int
	fundErr error
}

func (f *factory) SupportsFunding(Policy) error     { return f.fundErr }
func (f *factory) Open(string) (NodeRuntime, error) { f.opens++; return f.n, nil }

type probe struct {
	rpc, db, lock int
	lockErr       error
}

func (p *probe) ListenerClosed(context.Context, string) error { p.rpc++; return nil }
func (p *probe) DBsClosed(context.Context, string) error      { p.db++; return nil }
func (p *probe) HomeUnlocked(context.Context, string) error   { p.lock++; return p.lockErr }
func TestGoHarnessAdapterFakeLifecycle(t *testing.T) {
	for _, name := range []string{"normal", "start_failure", "lock_retained", "not_authorized", "funding_incompatible"} {
		t.Run(name, func(t *testing.T) {
			c := config(t)
			co, s := coordinator(t)
			n := &fakeNode{}
			f := &factory{n: n}
			p := &probe{}
			a := GoAdapter{c, f, p}
			auth := Authorization{ApprovedLocalNode: true, RunID: co.plan.RunID}
			switch name {
			case "start_failure":
				n.failStart = true
			case "lock_retained":
				p.lockErr = errors.New("lock retained")
			case "not_authorized":
				auth.ApprovedLocalNode = false
			case "funding_incompatible":
				f.fundErr = CoreNodeFactory{}.SupportsFunding(c.Policy)
			}
			r, e := co.Run(context.Background(), []Step{{Name: "fake-Core-API", Run: func(ctx context.Context) error { return a.OpenAndStart(ctx, co, co.plan, auth) }}})
			if name == "normal" {
				if e != nil || r.Status != "PASS" || n.closed != 1 || p.lock != 1 || p.db != 1 || p.rpc != 1 {
					t.Fatal(r, e, n, p)
				}
			} else if e == nil || r.Status != "BLOCKED" {
				t.Fatal(r, e)
			}
			if name == "not_authorized" || name == "funding_incompatible" {
				if f.opens != 0 {
					t.Fatal("Open reached")
				}
			}
			t.Logf("status=%s Open=%d Start=%d RPC=%d Close=%d listenerProof=%d DBproof=%d lockProof=%d saved=%s", r.Status, f.opens, n.started, n.rpc, n.closed, p.rpc, p.db, p.lock, s.saved.Status)
		})
	}
}
func TestActualCoreFundingGate(t *testing.T) {
	if !errors.Is((CoreNodeFactory{}).SupportsFunding(config(t).Policy), ErrLegacyGenesis) {
		t.Fatal("unsupported Genesis allowed")
	}
	t.Log("100 TEST/three-account plan rejected before actual Core node.Open; legacy 3 TEST validation preserved")
}

type fakeChain struct {
	endpoint            string
	chain               uint64
	receipt             *ethtypes.Receipt
	factory, pair, a, b common.Address
	fi, pi              abi.ABI
	codes               map[common.Address][]byte
	badMapping          bool
}

func (f *fakeChain) Endpoint() string                        { return f.endpoint }
func (f *fakeChain) ChainID(context.Context) (uint64, error) { return f.chain, nil }
func (f *fakeChain) Receipt(context.Context, common.Hash) (*ethtypes.Receipt, error) {
	return f.receipt, nil
}
func (f *fakeChain) Destination(context.Context, common.Hash) (common.Address, error) {
	return f.factory, nil
}
func (f *fakeChain) Code(_ context.Context, a common.Address) ([]byte, error) { return f.codes[a], nil }
func (f *fakeChain) Call(_ context.Context, to common.Address, data []byte) ([]byte, error) {
	parsed := f.pi
	if to == f.factory {
		parsed = f.fi
	}
	m, e := parsed.MethodById(data[:4])
	if e != nil {
		return nil, e
	}
	var v common.Address
	switch m.Name {
	case "getPair":
		v = f.pair
		if f.badMapping {
			v = common.Address{}
		}
	case "factory":
		v = f.factory
	case "token0":
		v = f.a
	case "token1":
		v = f.b
	default:
		return nil, errors.New("unexpected call")
	}
	return m.Outputs.Pack(v)
}
func fakePair(t *testing.T, c Config) *fakeChain {
	t.Helper()
	f := &fakeChain{endpoint: c.Profile.Network.RPCURLs[0], chain: EVMID, factory: common.HexToAddress("0x22"), pair: common.HexToAddress("0x66"), a: common.HexToAddress("0x33"), b: common.HexToAddress("0x44"), codes: map[common.Address][]byte{}}
	var e error
	f.fi, e = abi.JSON(bytes.NewReader(c.Artifacts["LQCFlowFactory"].ABI))
	if e != nil {
		t.Fatal(e)
	}
	f.pi, e = abi.JSON(bytes.NewReader(c.Artifacts["LQCFlowPair"].ABI))
	if e != nil {
		t.Fatal(e)
	}
	values := map[string]common.Address{"factory": f.factory, "token0": f.a, "token1": f.b}
	for addr, name := range map[common.Address]string{f.factory: "LQCFlowFactory", f.pair: "LQCFlowPair"} {
		f.codes[addr], e = runtime(c.Artifacts[name], values)
		if e != nil {
			t.Fatal(e)
		}
	}
	ev := f.fi.Events["PairCreated"]
	data, e := ev.Inputs.NonIndexed().Pack(f.pair, big.NewInt(1))
	if e != nil {
		t.Fatal(e)
	}
	f.receipt = &ethtypes.Receipt{Status: 1, TxHash: common.HexToHash("0x1234"), BlockHash: common.HexToHash("0x5678"), BlockNumber: big.NewInt(1), Logs: []*ethtypes.Log{{Address: f.factory, Topics: []common.Hash{ev.ID, common.BytesToHash(f.a.Bytes()), common.BytesToHash(f.b.Bytes())}, Data: data}}}
	return f
}
func TestPairObservationProofs(t *testing.T) {
	for _, name := range []string{"normal", "wrong_chain", "mapping", "runtime_immutable", "event_missing", "external_rpc"} {
		t.Run(name, func(t *testing.T) {
			c := config(t)
			f := fakePair(t, c)
			switch name {
			case "wrong_chain":
				f.chain = 97
			case "mapping":
				f.badMapping = true
			case "runtime_immutable":
				f.codes[f.pair][0] ^= 1
			case "event_missing":
				f.receipt.Logs = nil
			case "external_rpc":
				f.endpoint = "http://8.8.8.8:8545"
			}
			got, e := VerifyPair(context.Background(), c, f, f.factory, f.a, f.b, f.receipt.TxHash)
			if name == "normal" {
				if e != nil || got != f.pair {
					t.Fatal(got, e)
				}
				t.Log("fake Factory event + bidirectional getPair + runtime/immutable + getters verified; zero RPC transport")
			} else if e == nil {
				t.Fatal("accepted")
			}
		})
	}
}
