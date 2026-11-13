package mvpsafety

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

var ErrBlocked = errors.New("safety gate blocked")
var ErrLegacyGenesis = errors.New("BLOCKED: existing signed-gentx backend supports 3 test/one account, not 100 test/three accounts")

const CosmosID = "lqc-devnet-test-1"
const EVMID uint64 = 917001
const CoreCommit = "b79394246a8819a7651275bd07c88b83bccdd8df"
const FlowCommit = "013d159f05ed6a924ee965ec41ef193a069da122"

var unitsRE = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

type Allocation struct {
	Role   string
	Amount string
}
type AccountSpec struct {
	Role     string
	Creation string
	Address  *string
	KeyPath  *string
}
type Policy struct {
	CosmosChainID         string
	EVMChainID            uint64
	EVMChainIDHex         string
	GenesisTotal          string
	Allocations           []Allocation
	Accounts              []AccountSpec
	MintACap              string
	MintBCap              string
	WrapperDepositCap     string
	ValidatorBond         string
	BondSource            string
	MaxGasPerTx           uint64
	MaxFeePerGas          string
	MaxTransactions       uint64
	TotalSeconds          int
	StepSeconds           int
	CleanupReserveSeconds int
	CloseSeconds          int
	ChildTermGraceMS      int
	EvidenceSeconds       int
	NewRunParent          string
	ExistingHomes         []string
	ExistingKeyPaths      []string
	ExistingAccounts      []string
	AllowNode             bool
	AllowDeploy           bool
	AllowMint             bool
	AllowTransactions     bool
}

func Units(s string) (*big.Int, error) {
	if len(s) > 78 || !unitsRE.MatchString(s) {
		return nil, fmt.Errorf("canonical nonnegative base-unit integer required")
	}
	n, ok := new(big.Int).SetString(s, 10)
	if !ok || n.BitLen() > 256 {
		return nil, fmt.Errorf("uint256 amount required")
	}
	return n, nil
}
func mustUnits(s string) *big.Int {
	n, e := Units(s)
	if e != nil {
		panic(e)
	}
	return n
}
func (p Policy) Validate() error {
	if p.CosmosChainID != CosmosID || p.EVMChainID != EVMID || p.EVMChainIDHex != "0xdfe09" {
		return fmt.Errorf("fixed Devnet chain required")
	}
	fixed := map[string]string{"genesis": p.GenesisTotal, "mintA": p.MintACap, "mintB": p.MintBCap, "wrapper": p.WrapperDepositCap, "bond": p.ValidatorBond, "fee": p.MaxFeePerGas}
	expected := map[string]string{"genesis": "100000000000000000000", "mintA": "1000000000000000000000", "mintB": "1000000000", "wrapper": "10000000000000000000", "bond": "1000000000000000000", "fee": "2000000000"}
	for k, s := range fixed {
		if _, e := Units(s); e != nil {
			return fmt.Errorf("%s: %w", k, e)
		}
		if s != expected[k] {
			return fmt.Errorf("%s cap differs from proposed fixed policy", k)
		}
	}
	if p.BondSource != "deployer" {
		return fmt.Errorf("bond must come from existing deployer allocation, not extra issuance")
	}
	if len(p.Allocations) != 3 {
		return fmt.Errorf("three allocations required")
	}
	wanted := map[string]string{"deployer": "30000000000000000000", "test": "20000000000000000000", "reserve": "50000000000000000000"}
	seen := map[string]bool{}
	sum := new(big.Int)
	for _, a := range p.Allocations {
		if seen[a.Role] {
			return fmt.Errorf("duplicate allocation")
		}
		seen[a.Role] = true
		n, e := Units(a.Amount)
		if e != nil {
			return e
		}
		if wanted[a.Role] != a.Amount {
			return fmt.Errorf("allocation mismatch")
		}
		sum.Add(sum, n)
	}
	if sum.Cmp(mustUnits(p.GenesisTotal)) != 0 {
		return fmt.Errorf("Genesis total mismatch")
	}
	if len(p.Accounts) != 3 {
		return fmt.Errorf("three fresh account plans required")
	}
	seen = map[string]bool{}
	for _, a := range p.Accounts {
		if seen[a.Role] || wanted[a.Role] == "" || a.Creation != "new-per-run" || a.Address != nil || a.KeyPath != nil {
			return fmt.Errorf("existing/duplicate account or key use forbidden")
		}
		seen[a.Role] = true
	}
	if p.MaxGasPerTx == 0 || p.MaxGasPerTx > 5000000 || p.MaxTransactions == 0 || p.MaxTransactions > 64 {
		return fmt.Errorf("gas/transaction count exceeds fixed bound")
	}
	if p.TotalSeconds != 240 || p.StepSeconds != 20 || p.CleanupReserveSeconds != 50 || p.CloseSeconds != 5 || p.ChildTermGraceMS != 1000 || p.EvidenceSeconds != 2 {
		return fmt.Errorf("fixed finite runtime limits required")
	}
	if p.NewRunParent != "/tmp" || len(p.ExistingHomes) == 0 {
		return fmt.Errorf("new /tmp run and protected-home inventory required")
	}
	if p.AllowNode || p.AllowDeploy || p.AllowMint || p.AllowTransactions {
		return fmt.Errorf("offline policy must remain disabled; later live authorization is separate")
	}
	for _, path := range append(append([]string{}, p.ExistingHomes...), p.ExistingKeyPaths...) {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("invalid protected path")
		}
	}
	return nil
}

type PathInfo struct {
	Exists  bool
	Symlink bool
}
type Inspector interface {
	Inspect(string) (PathInfo, error)
}
type Plan struct {
	RunID     string
	Root      string
	Home      string
	KeyPaths  map[string]string
	Gross     map[string]string
	PostBond  map[string]string
	Bonded    string
	validated bool
	seal      string
}

func (p Plan) hash() string {
	b, _ := json.Marshal(p)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func (p Plan) intact() bool { return p.validated && p.seal != "" && p.seal == p.hash() }

var runRE = regexp.MustCompile(`^[a-z0-9]{8,32}$`)

func overlap(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}
func MakePlan(p Policy, id string, fs Inspector) (Plan, error) {
	if e := p.Validate(); e != nil {
		return Plan{}, e
	}
	if !runRE.MatchString(id) {
		return Plan{}, fmt.Errorf("safe run id required")
	}
	r := filepath.Join(p.NewRunParent, "lqc-stage7-"+id)
	h := filepath.Join(r, "home")
	keys := map[string]string{"deployer": filepath.Join(r, "keys/deployer.key"), "test": filepath.Join(r, "keys/test.key"), "reserve": filepath.Join(r, "keys/reserve.key"), "consensus": filepath.Join(h, "config/priv_validator_key.json"), "node": filepath.Join(h, "config/node_key.json"), "signingState": filepath.Join(h, "data/priv_validator_state.json")}
	for _, old := range append(append([]string{}, p.ExistingHomes...), p.ExistingKeyPaths...) {
		if overlap(r, old) {
			return Plan{}, fmt.Errorf("new run overlaps protected home/key")
		}
	}
	paths := []string{r, h}
	for _, x := range keys {
		paths = append(paths, x)
	}
	for _, target := range paths {
		for cur := target; ; cur = filepath.Dir(cur) {
			st, e := fs.Inspect(cur)
			if e != nil {
				return Plan{}, e
			}
			if st.Symlink {
				return Plan{}, fmt.Errorf("symlink path forbidden")
			}
			if st.Exists && (cur == r || cur == target) {
				return Plan{}, fmt.Errorf("existing home/key/run forbidden")
			}
			if st.Exists && cur != "/" {
				for _, m := range []string{"config/genesis.json", "config/priv_validator_key.json", "data/priv_validator_state.json"} {
					marker, e := fs.Inspect(filepath.Join(cur, m))
					if e != nil {
						return Plan{}, e
					}
					if marker.Exists {
						return Plan{}, fmt.Errorf("existing node-home ancestor forbidden")
					}
				}
			}
			if cur == "/" {
				break
			}
		}
	}
	gross := map[string]string{}
	post := map[string]string{}
	for _, a := range p.Allocations {
		gross[a.Role] = a.Amount
		post[a.Role] = a.Amount
	}
	post["deployer"] = new(big.Int).Sub(mustUnits(gross["deployer"]), mustUnits(p.ValidatorBond)).String()
	plan := Plan{RunID: id, Root: r, Home: h, KeyPaths: keys, Gross: gross, PostBond: post, Bonded: p.ValidatorBond, validated: true}
	plan.seal = plan.hash()
	return plan, nil
}

// Strict JSON rejects duplicate (including case-variant) keys and trailing input.
func DecodeStrict(raw []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	var walk func() error
	walk = func() error {
		t, e := d.Token()
		if e != nil {
			return e
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return e
				}
				s, ok := k.(string)
				if !ok {
					return fmt.Errorf("JSON key")
				}
				s = strings.ToLower(s)
				if seen[s] {
					return fmt.Errorf("duplicate JSON key")
				}
				seen[s] = true
				if e = walk(); e != nil {
					return e
				}
			}
			_, e = d.Token()
			return e
		case '[':
			for d.More() {
				if e = walk(); e != nil {
					return e
				}
			}
			_, e = d.Token()
			return e
		}
		return fmt.Errorf("JSON delimiter")
	}
	if e := walk(); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	return d.Decode(v)
}

type Intent struct {
	ID                 string
	Kind               string
	FromRole           string
	Amount             string
	GasLimit           uint64
	GasEstimate        uint64
	MaxFeePerGas       string
	ChainID            uint64
	UseExistingAccount bool
}
type Budget struct {
	mu                  sync.Mutex
	p                   Policy
	used                map[string]bool
	a, b, wrapper, fees *big.Int
	txs                 uint64
	blocked             bool
}

func NewBudget(p Policy) (*Budget, error) {
	if e := p.Validate(); e != nil {
		return nil, e
	}
	return &Budget{p: p, used: map[string]bool{}, a: new(big.Int), b: new(big.Int), wrapper: new(big.Int), fees: new(big.Int)}, nil
}
func (b *Budget) Reserve(i Intent) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.blocked {
		return ErrBlocked
	}
	fail := func(s string) error { b.blocked = true; return fmt.Errorf("BLOCKED: %s", s) }
	if i.ID == "" || b.used[i.ID] {
		return fail("duplicate/empty transaction id")
	}
	if i.ChainID != EVMID || i.UseExistingAccount || i.FromRole != "deployer" {
		return fail("chain or fresh account policy")
	}
	if i.GasLimit == 0 || i.GasLimit > b.p.MaxGasPerTx || i.GasEstimate == 0 || i.GasEstimate > i.GasLimit {
		return fail("gas estimate/limit exceeds bound or is missing")
	}
	price, e := Units(i.MaxFeePerGas)
	if e != nil || price.Sign() == 0 || price.Cmp(mustUnits(b.p.MaxFeePerGas)) > 0 {
		return fail("fee cap")
	}
	amount, e := Units(i.Amount)
	if e != nil {
		return fail("invalid base-unit amount")
	}
	if b.txs >= b.p.MaxTransactions {
		return fail("transaction count")
	}
	nextA, nextB, nextW := new(big.Int).Set(b.a), new(big.Int).Set(b.b), new(big.Int).Set(b.wrapper)
	switch i.Kind {
	case "mintA":
		nextA.Add(nextA, amount)
	case "mintB":
		nextB.Add(nextB, amount)
	case "deposit":
		nextW.Add(nextW, amount)
	case "deploy", "createPair", "approve", "swap", "remove", "withdraw":
		if amount.Sign() != 0 {
			return fail("native value not allowed for this intent")
		}
	default:
		return fail("unsupported intent")
	}
	if nextA.Cmp(mustUnits(b.p.MintACap)) > 0 || nextB.Cmp(mustUnits(b.p.MintBCap)) > 0 || nextW.Cmp(mustUnits(b.p.WrapperDepositCap)) > 0 {
		return fail("cumulative mint/deposit cap")
	}
	fee := new(big.Int).Mul(new(big.Int).SetUint64(i.GasLimit), price)
	nextFees := new(big.Int).Add(b.fees, fee)
	maxSpend := new(big.Int).Sub(mustUnits("30000000000000000000"), mustUnits(b.p.ValidatorBond))
	if new(big.Int).Add(nextFees, nextW).Cmp(maxSpend) > 0 {
		return fail("deployer funded budget insufficient; no automatic raise")
	}
	b.used[i.ID] = true
	b.txs++
	b.a, b.b, b.wrapper, b.fees = nextA, nextB, nextW, nextFees
	return nil
}
func (b *Budget) Totals() map[string]string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return map[string]string{"mintA": b.a.String(), "mintB": b.b.String(), "wrapper": b.wrapper.String(), "reservedGasFees": b.fees.String()}
}
