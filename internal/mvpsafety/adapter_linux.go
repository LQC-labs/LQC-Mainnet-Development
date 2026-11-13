//go:build linux

package mvpsafety

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	corenode "github.com/LQC-labs/LQC-Mainnet-Development/node"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"golang.org/x/sys/unix"
)

type Network struct {
	ChainID                                                          uint64
	ChainIDHex, CosmosChainID, Bech32Prefix, BaseDenom, DisplayDenom string
	Decimals                                                         int
	RPCURLs, AllowedOrigins                                          []string
}
type Source struct {
	CoreCommit, FlowCommit, OverlayArchiveSHA256, CandidateState string
	ProductionApproved                                           bool
}
type Asset struct {
	Kind               string
	Address            *string
	Decimals           int
	Denom, ContractRef string
	Canonical          bool
}
type Profile struct {
	SchemaVersion                          int
	Profile                                string
	DeploymentEnabled, TransactionsEnabled bool
	Network                                Network
	Source                                 Source
	Assets                                 map[string]Asset
	WrappedNative                          struct {
		Artifact                    string
		Canonical                   bool
		OnChainSymbol, DisplayAlias string
	}
	Dependencies struct{ PancakeLookup, BSCAddressReuse, ExternalRPC bool }
	Limits       struct {
		GasCap                                   uint64
		SimulationTimeoutMS, NodeLifetimeSeconds int
	}
}
type Contract struct {
	Artifact, ABIVersion                            string
	ChainID                                         uint64
	Address, TransactionHash, RuntimeBytecodeSHA256 *string
	Status, CreationKind                            string
}
type Manifest struct {
	SchemaVersion       int
	InterfaceFamily     string
	ChainID             uint64
	Status              string
	TransactionsEnabled bool
	Source              Source
	Contracts           map[string]Contract
}
type ImmutableRef struct{ Start, Length int }
type Artifact struct {
	ContractName, SourceName, Compiler string
	ABI                                json.RawMessage
	Bytecode, DeployedBytecode         string
	ImmutableReferences                map[string][]ImmutableRef
	ImmutableNames                     map[string]string
}
type ArtifactProof struct{ ArtifactSHA256, ABISHA256, CreationSHA256, RuntimeTemplateSHA256 string }
type BuildManifest struct {
	Compiler, CompilerSHA256, FlowCommit string
	ProductionApproved                   bool
	Settings                             json.RawMessage
	Sources                              map[string]string
	InputSHA256                          string
	Artifacts                            map[string]ArtifactProof
}
type Config struct {
	Profile   Profile
	Manifest  Manifest
	Policy    Policy
	Artifacts map[string]Artifact
	root      string
}

var IDs = []string{"mvp.tokenA", "mvp.tokenB", "mvp.wrappedNative", "mvp.factory", "mvp.pair", "mvp.pairNative", "mvp.router"}
var bsc = map[string]bool{"0xae13d989dac2f0debff460ac112a837c89baa7cd": true, "0x84a30a66cfcbb15453c83204b7e6ec436a0718fc": true, "0xa3e1fbe94055e7a8971b3994c7025b3c16273a24": true, "0xd99d1c33f9fc3444f8101754abc46c52416550d1": true, "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c": true, "0x10ed43c718714eb63d5aa57b78b54704e256024e": true, "0xca143ce32fe78f1f7019d7d551a6402fc5350c73": true, "0x6725f303b657a9451d8ba641348b6761a6cc7a17": true}

func LocalAddress(s string) (common.Address, error) {
	if len(s) != 42 || !strings.HasPrefix(s, "0x") || !common.IsHexAddress(s) || common.HexToAddress(s) == (common.Address{}) || bsc[strings.ToLower(s)] {
		return common.Address{}, fmt.Errorf("invalid/zero/BSC address")
	}
	return common.HexToAddress(s), nil
}
func LocalRPC(raw string) (string, error) {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" || u.Port() == "" || u.Hostname() != "127.0.0.1" && u.Hostname() != "::1" {
		return "", fmt.Errorf("literal localhost RPC only")
	}
	port, e := strconv.Atoi(u.Port())
	if e != nil || port <= 0 || port > 65535 {
		return "", fmt.Errorf("valid fixed RPC port required")
	}
	return u.Host, nil
}
func file(root, path string, v any) error {
	p := filepath.Join(root, path)
	st, e := os.Lstat(p)
	if e != nil {
		return e
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() || st.Size() > 2<<20 {
		return fmt.Errorf("unsafe config file")
	}
	raw, e := os.ReadFile(p)
	if e != nil {
		return e
	}
	return DecodeStrict(raw, v)
}
func LoadConfig(root string) (Config, error) {
	var c Config
	if !filepath.IsAbs(root) {
		return c, fmt.Errorf("absolute source root required")
	}
	c.root = root
	for path, v := range map[string]any{"config/flow/mvp/lqc-devnet.json": &c.Profile, "config/flow/mvp/deployments.lqc-devnet.json": &c.Manifest, "config/flow/mvp/execution-policy.json": &c.Policy} {
		if e := file(root, path, v); e != nil {
			return c, e
		}
	}
	var b BuildManifest
	if e := file(root, "tools/flow-mvp/build-manifest.json", &b); e != nil {
		return c, e
	}
	if b.FlowCommit != FlowCommit || b.Compiler != "0.8.30+commit.73712a01" || b.ProductionApproved {
		return c, fmt.Errorf("artifact provenance mismatch")
	}
	c.Artifacts = map[string]Artifact{}
	var settings struct {
		Optimizer struct {
			Enabled bool
			Runs    int
		}
		ViaIR      bool
		EVMVersion string
	}
	if e := DecodeStrict(b.Settings, &settings); e != nil || !settings.Optimizer.Enabled || settings.Optimizer.Runs != 200 || !settings.ViaIR || settings.EVMVersion != "shanghai" {
		return c, fmt.Errorf("compiler settings mismatch")
	}
	for name, proof := range b.Artifacts {
		var a Artifact
		if filepath.Base(name) != name {
			return c, fmt.Errorf("artifact path escape")
		}
		p := filepath.Join(root, "tools/flow-mvp/artifacts", name+".json")
		raw, e := os.ReadFile(p)
		if e != nil {
			return c, e
		}
		h := sha256.Sum256(raw)
		if hex.EncodeToString(h[:]) != proof.ArtifactSHA256 {
			return c, fmt.Errorf("artifact file hash mismatch")
		}
		if e = DecodeStrict(raw, &a); e != nil {
			return c, e
		}
		creation, e := hex.DecodeString(strings.TrimPrefix(a.Bytecode, "0x"))
		if e != nil {
			return c, e
		}
		runtime, e := hex.DecodeString(strings.TrimPrefix(a.DeployedBytecode, "0x"))
		if e != nil {
			return c, e
		}
		ch, rh := sha256.Sum256(creation), sha256.Sum256(runtime)
		if a.ContractName != name || a.Compiler != b.Compiler || hex.EncodeToString(ch[:]) != proof.CreationSHA256 || hex.EncodeToString(rh[:]) != proof.RuntimeTemplateSHA256 {
			return c, fmt.Errorf("artifact code mismatch")
		}
		c.Artifacts[name] = a
	}
	return c, c.Validate()
}
func (c Config) Validate() error {
	p, m := c.Profile, c.Manifest
	if e := c.Policy.Validate(); e != nil {
		return e
	}
	if p.SchemaVersion != 1 || p.Profile != "lqc-devnet-mvp" || m.SchemaVersion != 1 {
		return fmt.Errorf("schema version")
	}
	if p.Network.ChainID != EVMID || p.Network.ChainIDHex != "0xdfe09" || p.Network.CosmosChainID != CosmosID || p.Network.BaseDenom != "atest" || p.Network.DisplayDenom != "test" || p.Network.Decimals != 18 || p.Network.Bech32Prefix != "lqctest" {
		return fmt.Errorf("profile chain/units")
	}
	if len(p.Network.RPCURLs) != 1 {
		return fmt.Errorf("one RPC")
	}
	if _, e := LocalRPC(p.Network.RPCURLs[0]); e != nil {
		return e
	}
	if len(p.Network.AllowedOrigins) != 1 || p.Network.AllowedOrigins[0] != "http://localhost:3000" {
		return fmt.Errorf("exact Origin")
	}
	if p.DeploymentEnabled || p.TransactionsEnabled || p.Dependencies.ExternalRPC || p.Dependencies.PancakeLookup || p.Dependencies.BSCAddressReuse || p.WrappedNative.Canonical {
		return fmt.Errorf("inactive local-only profile required")
	}
	if p.Limits.GasCap < c.Policy.MaxGasPerTx || p.Limits.NodeLifetimeSeconds != 240 {
		return fmt.Errorf("policy cannot silently raise profile bounds")
	}
	if p.Source.CoreCommit != CoreCommit || p.Source.FlowCommit != FlowCommit || p.Source.CandidateState != "draft-unmerged" || p.Source.ProductionApproved || m.Source != p.Source {
		return fmt.Errorf("candidate source not operationally approved")
	}
	if m.InterfaceFamily != "mvp" || m.ChainID != EVMID || m.TransactionsEnabled || m.Status != "unconfigured" || len(m.Contracts) != len(IDs) {
		return fmt.Errorf("MVP/Router2 namespace or activation mismatch")
	}
	for _, id := range IDs {
		v, ok := m.Contracts[id]
		if !ok || v.ChainID != EVMID || v.Address != nil || v.TransactionHash != nil || v.RuntimeBytecodeSHA256 != nil || v.Status != "unconfigured" || !strings.HasPrefix(v.ABIVersion, "mvp.") {
			return fmt.Errorf("MVP contract initial state")
		}
		pair := strings.HasPrefix(id, "mvp.pair")
		if pair != (v.CreationKind == "factory-internal-create") {
			return fmt.Errorf("Pair creation kind")
		}
	}
	if len(p.Assets) != 4 || c.Profile.Assets["tokenA"].Decimals != 18 || c.Profile.Assets["tokenB"].Decimals != 6 || p.Assets["wrappedNative"].Canonical {
		return fmt.Errorf("token decimals/asset roles")
	}
	for _, a := range p.Assets {
		if a.Address != nil {
			return fmt.Errorf("configured existing asset forbidden")
		}
	}
	if len(c.Artifacts) != 5 {
		return fmt.Errorf("five compiled artifacts required")
	}
	return nil
}

type DeploymentStep struct {
	ID, Artifact, Kind string
	ConstructorTypes   []string
	References         []string
}

func (c Config) DeploymentPlan() ([]DeploymentStep, error) {
	if e := c.Validate(); e != nil {
		return nil, e
	}
	steps := []DeploymentStep{}
	for _, id := range IDs {
		v := c.Manifest.Contracts[id]
		a, ok := c.Artifacts[v.Artifact]
		if !ok {
			return nil, fmt.Errorf("missing artifact")
		}
		parsed, e := abi.JSON(bytes.NewReader(a.ABI))
		if e != nil {
			return nil, e
		}
		types := []string{}
		for _, arg := range parsed.Constructor.Inputs {
			types = append(types, arg.Type.String())
		}
		var refs []string
		switch id {
		case "mvp.tokenA", "mvp.tokenB", "mvp.factory":
			refs = []string{"new.deployer"}
		case "mvp.pair":
			refs = []string{"mvp.factory", "mvp.tokenA", "mvp.tokenB"}
		case "mvp.pairNative":
			refs = []string{"mvp.factory", "mvp.tokenA", "mvp.wrappedNative"}
		case "mvp.router":
			refs = []string{"mvp.factory", "mvp.wrappedNative"}
		}
		steps = append(steps, DeploymentStep{id, v.Artifact, v.CreationKind, types, refs})
	}
	return steps, nil
}

// The production factory compiles against Core's real Open/Start/Close API,
// but refuses the incompatible legacy Genesis budget before opening any DB.
type NodeRuntime interface {
	Start(context.Context) error
	StartEVMRPCWithOptions(context.Context, string, corenode.RPCBrowserOptions) (string, error)
	Close() error
}
type NodeFactory interface {
	SupportsFunding(Policy) error
	Open(string) (NodeRuntime, error)
}
type CoreNodeFactory struct{}

func (CoreNodeFactory) SupportsFunding(p Policy) error {
	if p.GenesisTotal != "3000000000000000000" || len(p.Allocations) != 1 {
		return ErrLegacyGenesis
	}
	return nil
}
func (CoreNodeFactory) Open(path string) (NodeRuntime, error) { return corenode.Open(path) }

type CleanupProbe interface {
	ListenerClosed(context.Context, string) error
	DBsClosed(context.Context, string) error
	HomeUnlocked(context.Context, string) error
}
type LocalProbe struct{}

func (LocalProbe) ListenerClosed(ctx context.Context, addr string) error {
	h, _, e := net.SplitHostPort(addr)
	if e != nil || h != "127.0.0.1" && h != "::1" {
		return fmt.Errorf("probe requires localhost")
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	c, e := (&net.Dialer{Timeout: 50 * time.Millisecond}).DialContext(ctx, "tcp", addr)
	if e == nil {
		c.Close()
		return fmt.Errorf("listener still open")
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if !errors.Is(e, syscall.ECONNREFUSED) {
		return fmt.Errorf("listener closure unproven: %w", e)
	}
	return nil
}
func lockAvailable(path string, directory bool) error {
	flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW
	if directory {
		flags |= unix.O_DIRECTORY
	}
	fd, e := unix.Open(path, flags, 0)
	if e != nil {
		return e
	}
	defer unix.Close(fd)
	if e = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); e != nil {
		return fmt.Errorf("lock retained: %w", e)
	}
	return unix.Flock(fd, unix.LOCK_UN)
}
func (LocalProbe) DBsClosed(ctx context.Context, home string) error {
	entries, e := os.ReadDir(filepath.Join(home, "data"))
	if e != nil {
		return e
	}
	checked := 0
	for _, x := range entries {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if x.IsDir() && strings.HasSuffix(x.Name(), ".db") {
			if e = lockAvailable(filepath.Join(home, "data", x.Name(), "LOCK"), false); e != nil {
				return e
			}
			checked++
		}
	}
	if checked == 0 {
		return fmt.Errorf("no DB cleanup proof")
	}
	return nil
}
func (LocalProbe) HomeUnlocked(_ context.Context, home string) error {
	return lockAvailable(home, true)
}

type Authorization struct {
	ApprovedLocalNode bool
	RunID             string
	Production        bool
}
type GoAdapter struct {
	Config  Config
	Factory NodeFactory
	Probe   CleanupProbe
}
type NodeResource struct {
	mu           sync.Mutex
	node         NodeRuntime
	probe        CleanupProbe
	home, rpc    string
	attemptedRPC bool
}

func (n *NodeResource) Name() string                { return "Core-node-DB-RPC-lock" }
func (n *NodeResource) Close(context.Context) error { return n.node.Close() }
func (n *NodeResource) VerifyClosed(ctx context.Context) error {
	n.mu.Lock()
	attempted := n.attemptedRPC
	n.mu.Unlock()
	if attempted {
		if e := n.probe.ListenerClosed(ctx, n.rpc); e != nil {
			return e
		}
	}
	if e := n.probe.DBsClosed(ctx, n.home); e != nil {
		return e
	}
	return n.probe.HomeUnlocked(ctx, n.home)
}
func (a GoAdapter) OpenAndStart(ctx context.Context, c *Coordinator, plan Plan, auth Authorization) error {
	if e := a.Config.Validate(); e != nil {
		return e
	}
	if !plan.intact() || !auth.ApprovedLocalNode || auth.Production || auth.RunID != plan.RunID {
		return fmt.Errorf("explicit isolated-local authorization and sealed fresh plan required")
	}
	if a.Factory == nil || a.Probe == nil {
		return fmt.Errorf("factory/cleanup proof required")
	}
	if e := a.Factory.SupportsFunding(a.Config.Policy); e != nil {
		return e
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	n, e := a.Factory.Open(plan.Home)
	if e != nil {
		return e
	}
	addr, _ := LocalRPC(a.Config.Profile.Network.RPCURLs[0])
	r := &NodeResource{node: n, probe: a.Probe, home: plan.Home, rpc: addr}
	if e = c.Register(r); e != nil {
		closeCtx, stop := context.WithTimeout(context.Background(), time.Duration(a.Config.Policy.CloseSeconds)*time.Second)
		defer stop()
		_, _ = bounded(closeCtx, func(context.Context) error { return n.Close() })
		return e
	}
	if e = n.Start(ctx); e != nil {
		return e
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	r.mu.Lock()
	r.attemptedRPC = true
	r.mu.Unlock()
	got, e := n.StartEVMRPCWithOptions(ctx, addr, corenode.RPCBrowserOptions{AllowedOrigins: a.Config.Profile.Network.AllowedOrigins})
	if e != nil {
		return e
	}
	if got != addr {
		return fmt.Errorf("RPC endpoint differs from allowed listener")
	}
	return nil
}
