//go:build linux

// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0
package node

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"cosmossdk.io/log/v2"
	"cosmossdk.io/math"
	"github.com/LQC-labs/LQC-Mainnet-Development/app"
	chainconfig "github.com/LQC-labs/LQC-Mainnet-Development/chain/config"
	"github.com/LQC-labs/LQC-Mainnet-Development/genesis"
	cmtdb "github.com/cometbft/cometbft-db"
	cmted "github.com/cometbft/cometbft/crypto/ed25519"
	cmtjson "github.com/cometbft/cometbft/libs/json"
	"github.com/cometbft/cometbft/p2p"
	"github.com/cometbft/cometbft/privval"
	storeproto "github.com/cometbft/cometbft/proto/tendermint/store"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	ctypes "github.com/cometbft/cometbft/rpc/core/types"
	cmtstate "github.com/cometbft/cometbft/state"
	cmtstore "github.com/cometbft/cometbft/store"
	cmttypes "github.com/cometbft/cometbft/types"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/client/tx"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	genutiltypes "github.com/cosmos/cosmos-sdk/x/genutil/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"github.com/cosmos/evm/crypto/ethsecp256k1"
	evmtypes "github.com/cosmos/evm/x/vm/types"
	"golang.org/x/sys/unix"
)

func TestClusterPolicyAndNonSigner(t *testing.T) {
	cfg := startFixtureProfile()
	o := RuntimeOptions{Network: chainconfig.NetworkMainnet, Profile: cfg, GenesisPath: "/not-read", ExpectedGenesisSHA256: strings.Repeat("0", 64), LocalTestOnly: true, EnableP2P: true, Role: RoleValidator, CometRPCListen: "127.0.0.1:27657", P2PListen: "127.0.0.1:27656", MaxInboundPeers: 3, MaxOutboundPeers: 3}
	if err := o.validate(); err != nil {
		t.Fatal(err)
	}
	for name, peer := range map[string]string{"public": strings.Repeat("a", 40) + "@192.0.2.1:26656", "dns": strings.Repeat("a", 40) + "@localhost:26656", "no-id": "127.0.0.1:26656", "zero-port": strings.Repeat("a", 40) + "@127.0.0.1:0"} {
		t.Run(name, func(t *testing.T) {
			bad := o
			bad.PersistentPeers = peer
			if bad.validate() == nil {
				t.Fatal("unsafe peer accepted")
			}
		})
	}
	limited := o
	limited.MaxOutboundPeers = 1
	limited.PersistentPeers = strings.Repeat("a", 40) + "@127.0.0.1:27656," + strings.Repeat("b", 40) + "@127.0.0.1:27666"
	if err := limited.validate(); err == nil || !strings.Contains(err.Error(), "configured peers exceed outbound limit") {
		t.Fatal("persistent peer bound not enforced", err)
	}
	bad := o
	bad.Role = "unknown"
	if bad.validate() == nil {
		t.Fatal("unknown role accepted")
	}
	pub := cmted.PubKey(bytes.Repeat([]byte{3}, 32))
	observer := observerValidator{public: pub}
	vote := &cmtproto.Vote{Height: 1}
	proposal := &cmtproto.Proposal{Height: 1}
	if observer.SignVote("test", vote) == nil || observer.SignProposal("test", proposal) == nil || len(vote.Signature) != 0 || len(proposal.Signature) != 0 {
		t.Fatal("Full Node signed or changed a message")
	}
	root := t.TempDir()
	key := cmted.GenPrivKey()
	pv := privval.NewFilePV(key, filepath.Join(root, "key.json"), filepath.Join(root, "state.json"))
	pv.Save()
	first := &cmtproto.Vote{Type: cmtproto.PrecommitType, Height: 1, Round: 0, Timestamp: time.Now().UTC(), BlockID: cmtproto.BlockID{Hash: bytes.Repeat([]byte{1}, 32), PartSetHeader: cmtproto.PartSetHeader{Total: 1, Hash: bytes.Repeat([]byte{2}, 32)}}}
	if err := pv.SignVote("double-sign-fixture-1", first); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(root, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	conflict := *first
	conflict.BlockID.Hash = bytes.Repeat([]byte{4}, 32)
	conflict.Signature = nil
	if pv.SignVote("double-sign-fixture-1", &conflict) == nil {
		t.Fatal("conflicting same-HRS vote signed")
	}
	after, err := os.ReadFile(filepath.Join(root, "state.json"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("failed double-sign attempt changed HRS", err)
	}
	t.Log("Full Node signing refusal and native FilePV conflicting same-HRS rejection PASS")
}

type clusterFixture struct {
	Config, Genesis, SHA256 string
	Profile                 chainconfig.RuntimeConfig
	Homes, IDs              []string
	RPC, P2P                []int
}

func TestClusterFixtureChild(t *testing.T) {
	root := os.Getenv("LQC_CLUSTER_FIXTURE_ROOT")
	if root == "" {
		t.Skip("cluster fixture child only")
	}
	cfg := startFixtureProfile()
	a, err := app.NewWithConfig(log.NewNopLogger(), dbm.NewMemDB(), t.TempDir(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	f := clusterFixture{Config: filepath.Join(root, "runtime.json"), Profile: cfg}
	for i := 0; i < 4; i++ {
		home := filepath.Join(root, fmt.Sprintf("node-%d", i))
		f.Homes = append(f.Homes, home)
		f.RPC = append(f.RPC, 27657+i*10)
		f.P2P = append(f.P2P, 27656+i*10)
		if i < 3 {
			if err := CreateHome(home); err != nil {
				t.Fatal(err)
			}
		} else {
			for _, p := range []string{home, filepath.Join(home, "config"), filepath.Join(home, "data")} {
				if err := os.Mkdir(p, 0700); err != nil {
					t.Fatal(err)
				}
			}
			nk := p2p.NodeKey{PrivKey: cmted.GenPrivKey()}
			b, err := cmtjson.Marshal(nk)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(home, "config/node_key.json"), b, 0600); err != nil {
				t.Fatal(err)
			}
		}
		b, err := os.ReadFile(filepath.Join(home, "config/node_key.json"))
		if err != nil {
			t.Fatal(err)
		}
		var nk p2p.NodeKey
		if cmtjson.Unmarshal(b, &nk) != nil {
			t.Fatal("invalid fixture P2P key")
		}
		f.IDs = append(f.IDs, string(nk.ID()))
	}
	state := a.SDK.BasicModuleManager.DefaultGenesis(a.SDK.AppCodec())
	for name, b := range state {
		if len(b) == 0 {
			delete(state, name)
		} else {
			state[name] = bytes.ReplaceAll(b, []byte(`"stake"`), []byte(`"astart"`))
		}
	}
	cdc := a.SDK.AppCodec()
	var bank banktypes.GenesisState
	var auth authtypes.GenesisState
	cdc.MustUnmarshalJSON(state["bank"], &bank)
	cdc.MustUnmarshalJSON(state["auth"], &auth)
	bank.DenomMetadata = []banktypes.Metadata{{Base: "astart", Display: "startfixture", Name: "Offline cluster fixture", Symbol: "FIX", DenomUnits: []*banktypes.DenomUnit{{Denom: "astart", Exponent: 0}, {Denom: "startfixture", Exponent: 18}}}}
	evm := evmtypes.DefaultGenesisState()
	evm.Params.EvmDenom = "astart"
	evm.Params.ExtendedDenomOptions = &evmtypes.ExtendedDenomOptions{ExtendedDenom: "astart"}
	state["evm"] = cdc.MustMarshalJSON(evm)
	accounts := authtypes.GenesisAccounts{}
	gentxs := []json.RawMessage{}
	consensus := &genutiltypes.ConsensusGenesis{Params: cmttypes.DefaultConsensusParams()}
	for i := 0; i < 3; i++ {
		fd, err := openDevnetHome(f.Homes[i])
		if err != nil {
			t.Fatal(err)
		}
		public, err := loadDevnetKeys(fd)
		unix.Close(fd)
		if err != nil {
			t.Fatal(err)
		}
		account, err := ethsecp256k1.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		address := sdk.AccAddress(account.PubKey().Address())
		accounts = append(accounts, authtypes.NewBaseAccount(address, account.PubKey(), 0, 0))
		bond := sdk.NewCoin("astart", sdk.DefaultPowerReduction)
		funds := sdk.NewCoins(sdk.NewCoin("astart", bond.Amount.MulRaw(3)))
		bank.Balances = append(bank.Balances, banktypes.Balance{Address: address.String(), Coins: funds})
		bank.Supply = bank.Supply.Add(funds...)
		msg, err := stakingtypes.NewMsgCreateValidator(sdk.ValAddress(address).String(), public, bond, stakingtypes.NewDescription(fmt.Sprintf("validator-%d", i), "", "", "", ""), stakingtypes.NewCommissionRates(math.LegacyZeroDec(), math.LegacyOneDec(), math.LegacyOneDec()), math.OneInt())
		if err != nil {
			t.Fatal(err)
		}
		builder := a.SDK.GetTxConfig().NewTxBuilder()
		if err := builder.SetMsgs(msg); err != nil {
			t.Fatal(err)
		}
		builder.SetGasLimit(3_000_000)
		if err := builder.SetSignatures(signing.SignatureV2{PubKey: account.PubKey(), Data: &signing.SingleSignatureData{SignMode: signing.SignMode_SIGN_MODE_DIRECT}}); err != nil {
			t.Fatal(err)
		}
		sig, err := tx.SignWithPrivKey(context.Background(), signing.SignMode_SIGN_MODE_DIRECT, authsigning.SignerData{Address: address.String(), ChainID: cfg.Chain.CosmosChainID, PubKey: account.PubKey()}, builder, account, a.SDK.GetTxConfig(), 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := builder.SetSignatures(sig); err != nil {
			t.Fatal(err)
		}
		b, err := a.SDK.GetTxConfig().TxJSONEncoder()(builder.GetTx())
		if err != nil {
			t.Fatal(err)
		}
		gentxs = append(gentxs, b)
		pk := cmted.PubKey(public.Bytes())
		consensus.Validators = append(consensus.Validators, cmttypes.GenesisValidator{Address: pk.Address(), PubKey: pk, Power: 1, Name: fmt.Sprintf("validator-%d", i)})
	}
	auth.Accounts, err = authtypes.PackAccounts(accounts)
	if err != nil {
		t.Fatal(err)
	}
	state["auth"] = cdc.MustMarshalJSON(&auth)
	state["bank"] = cdc.MustMarshalJSON(&bank)
	state["genutil"] = cdc.MustMarshalJSON(&genutiltypes.GenesisState{GenTxs: gentxs})
	b, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	doc := genesis.MainnetDocument{AppGenesis: genutiltypes.AppGenesis{AppName: app.Name, AppVersion: app.Version, ChainID: cfg.Chain.CosmosChainID, GenesisTime: time.Unix(1_700_000_000, 0).UTC(), InitialHeight: 1, AppState: b, Consensus: consensus}, SchemaVersion: genesis.MainnetGenesisSchemaVersion, Profile: cfg}
	b, err = json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b)
	f.SHA256 = hex.EncodeToString(h[:])
	f.Genesis = filepath.Join(root, "genesis.json")
	if err := os.WriteFile(f.Genesis, b, 0600); err != nil {
		t.Fatal(err)
	}
	for _, home := range f.Homes {
		if err := os.WriteFile(filepath.Join(home, "config/genesis.json"), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	b, _ = json.Marshal(cfg)
	if err := os.WriteFile(f.Config, b, 0600); err != nil {
		t.Fatal(err)
	}
	b, _ = json.Marshal(f)
	if err := os.WriteFile(filepath.Join(root, "cluster.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
}

func clusterArgs(f clusterFixture, i int, isolated bool) []string {
	role := "validator"
	if i == 3 {
		role = "fullnode"
	}
	peers := []string{}
	seeds := ""
	limit := 3
	if !isolated {
		for j := range f.Homes {
			if j == i {
				continue
			}
			peer := fmt.Sprintf("%s@127.0.0.1:%d", f.IDs[j], f.P2P[j])
			if i == 3 && j == 0 {
				seeds = peer
			} else {
				peers = append(peers, peer)
			}
		}
	} else {
		limit = 0
	}
	return []string{"start", "--network", "mainnet", "--config", f.Config, "--genesis", f.Genesis, "--expected-genesis-sha256", f.SHA256, "--home", f.Homes[i], "--local-test-only", "--enable-p2p", "--role", role, "--p2p-listen", fmt.Sprintf("127.0.0.1:%d", f.P2P[i]), "--comet-rpc-listen", fmt.Sprintf("127.0.0.1:%d", f.RPC[i]), "--seeds", seeds, "--persistent-peers", strings.Join(peers, ","), "--max-inbound-peers", fmt.Sprint(limit), "--max-outbound-peers", fmt.Sprint(limit)}
}

func clusterRPC(port int, path string, dst interface{}) error {
	client := &http.Client{Timeout: time.Second}
	defer client.CloseIdleConnections()
	res, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/%s", port, path))
	if err != nil {
		return err
	}
	defer res.Body.Close()
	var env struct {
		Result json.RawMessage
		Error  interface{}
	}
	if err := json.NewDecoder(res.Body).Decode(&env); err != nil {
		return err
	}
	if env.Error != nil || len(env.Result) == 0 {
		return fmt.Errorf("RPC error: %v", env.Error)
	}
	return cmtjson.Unmarshal(env.Result, dst)
}

type clusterProcess struct {
	cmd     *exec.Cmd
	done    chan error
	file    *os.File
	cancel  context.CancelFunc
	stopped bool
}

func launchClusterNode(t *testing.T, ctx context.Context, binary string, f clusterFixture, i int, isolated bool, logPath string) *clusterProcess {
	t.Helper()
	childCtx, cancel := context.WithCancel(ctx)
	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	cmd := exec.CommandContext(childCtx, binary, clusterArgs(f, i, isolated)...)
	cmd.Stdout = file
	cmd.Stderr = file
	if err := cmd.Start(); err != nil {
		cancel()
		file.Close()
		t.Fatal(err)
	}
	p := &clusterProcess{cmd: cmd, done: make(chan error, 1), file: file, cancel: cancel}
	go func() { p.done <- cmd.Wait() }()
	t.Cleanup(func() {
		if !p.stopped {
			p.cancel()
			<-p.done
			p.file.Close()
			p.stopped = true
		}
	})
	return p
}
func stopClusterNode(t *testing.T, p *clusterProcess) {
	t.Helper()
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-p.done:
		p.stopped = true
		p.cancel()
		p.file.Close()
		if err != nil {
			t.Fatal("cluster shutdown failed", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("cluster shutdown deadline")
	}
}

type clusterSample struct {
	Height    int64  `json:"height"`
	BlockHash string `json:"block_hash"`
	AppHash   string `json:"app_hash"`
	SDKHeight int64  `json:"sdk_height"`
	Peers     int    `json:"peers"`
}

func observeCluster(f clusterFixture, height int64) ([]clusterSample, error) {
	rows := []clusterSample{}
	for i := range f.Homes {
		var info ctypes.ResultABCIInfo
		if err := clusterRPC(f.RPC[i], "abci_info", &info); err != nil {
			return nil, err
		}
		if info.Response.LastBlockHeight < height+1 {
			return nil, fmt.Errorf("node %d SDK not committed through %d", i, height+1)
		}
		var block, next ctypes.ResultBlock
		var result ctypes.ResultBlockResults
		var peers ctypes.ResultNetInfo
		if err := clusterRPC(f.RPC[i], fmt.Sprintf("block?height=%d", height), &block); err != nil {
			return nil, err
		}
		if err := clusterRPC(f.RPC[i], fmt.Sprintf("block?height=%d", height+1), &next); err != nil {
			return nil, err
		}
		if err := clusterRPC(f.RPC[i], fmt.Sprintf("block_results?height=%d", height), &result); err != nil {
			return nil, err
		}
		if err := clusterRPC(f.RPC[i], "net_info", &peers); err != nil {
			return nil, err
		}
		if block.Block == nil || next.Block == nil || len(result.AppHash) == 0 || !bytes.Equal(result.AppHash, next.Block.AppHash) {
			return nil, fmt.Errorf("block/AppHash height binding mismatch")
		}
		rows = append(rows, clusterSample{Height: height, BlockHash: hex.EncodeToString(block.BlockID.Hash), AppHash: hex.EncodeToString(result.AppHash), SDKHeight: info.Response.LastBlockHeight, Peers: peers.NPeers})
	}
	for _, row := range rows {
		if row.BlockHash != rows[0].BlockHash || row.AppHash != rows[0].AppHash {
			return nil, fmt.Errorf("nodes disagree at height %d", height)
		}
	}
	return rows, nil
}

func TestClusterConsensusIntegration(t *testing.T) {
	if os.Getenv("LQC_RUN_CLUSTER") != "1" {
		t.Skip("explicit isolated cluster opt-in required")
	}
	binary := os.Getenv("LQC_STEP4_CLI_BINARY")
	if binary == "" {
		t.Fatal("CLI binary required")
	}
	root, err := os.MkdirTemp("/tmp", "lqc-cluster.")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("PRESERVED_CLUSTER_EVIDENCE=" + root)
	ctx, cancel := context.WithTimeout(t.Context(), 210*time.Second)
	defer cancel()
	prepare := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestClusterFixtureChild$", "-test.count=1", "-test.v")
	prepare.Env = append(os.Environ(), "LQC_CLUSTER_FIXTURE_ROOT="+root)
	out, err := prepare.CombinedOutput()
	_ = os.WriteFile(filepath.Join(root, "prepare.log"), out, 0600)
	if err != nil {
		t.Fatalf("cluster fixture: %v\n%s", err, out)
	}
	var f clusterFixture
	b, err := os.ReadFile(filepath.Join(root, "cluster.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	keyHashes := map[string][32]byte{}
	ids := map[string]bool{}
	for i, home := range f.Homes {
		if ids[f.IDs[i]] {
			t.Fatal("shared P2P ID")
		}
		ids[f.IDs[i]] = true
		for _, rel := range []string{"config/genesis.json", "config/node_key.json", "config/priv_validator_key.json"} {
			path := filepath.Join(home, rel)
			b, err := os.ReadFile(path)
			if i == 3 && rel == "config/priv_validator_key.json" {
				if !os.IsNotExist(err) {
					t.Fatal("Full Node has consensus key")
				}
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			keyHashes[path] = sha256.Sum256(b)
		}
	}
	processes := make([]*clusterProcess, 4)
	for i := range processes {
		processes[i] = launchClusterNode(t, ctx, binary, f, i, false, filepath.Join(root, fmt.Sprintf("node-%d-first.log", i)))
	}
	waitAgreement := func(name string, height int64) []clusterSample {
		t.Helper()
		deadline := time.Now().Add(65 * time.Second)
		var last error
		for time.Now().Before(deadline) && ctx.Err() == nil {
			rows, err := observeCluster(f, height)
			if err == nil {
				ready := true
				for _, row := range rows {
					if row.Peers < 2 {
						ready = false
					}
				}
				if ready {
					b, _ := json.MarshalIndent(rows, "", "  ")
					if err := os.WriteFile(filepath.Join(root, name+".json"), b, 0600); err != nil {
						t.Fatal(err)
					}
					t.Logf("%s: height=%d AppHash=%s block=%s peers=%v", name, height, rows[0].AppHash, rows[0].BlockHash, rows)
					return rows
				}
			}
			last = err
			select {
			case <-ctx.Done():
			case <-time.After(150 * time.Millisecond):
			}
		}
		for i, p := range processes {
			if p != nil && !p.stopped {
				select {
				case e := <-p.done:
					p.done <- e
					t.Logf("node %d exited: %v", i, e)
				default:
				}
			}
		}
		t.Fatal("cluster agreement deadline", last)
		return nil
	}
	first := waitAgreement("initial-agreement", 4)
	// Cryptographically verify the common commit against all three independent
	// public keys and their declared voting power, not just matching RPC text.
	var doc genesis.MainnetDocument
	b, _ = os.ReadFile(f.Genesis)
	if json.Unmarshal(b, &doc) != nil {
		t.Fatal("bad fixture Genesis")
	}
	vals := []*cmttypes.Validator{}
	for _, v := range doc.Consensus.Validators {
		vals = append(vals, cmttypes.NewValidator(v.PubKey, v.Power))
	}
	set := cmttypes.NewValidatorSet(vals)
	var commit ctypes.ResultCommit
	if err := clusterRPC(f.RPC[0], "commit?height=4", &commit); err != nil {
		t.Fatal(err)
	}
	if err := set.VerifyCommit(f.Profile.Chain.CosmosChainID, commit.Commit.BlockID, 4, commit.Commit); err != nil {
		t.Fatal("invalid common commit", err)
	}
	stopClusterNode(t, processes[0])
	oldState, err := os.ReadFile(filepath.Join(f.Homes[0], "data/priv_validator_state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var signedBefore privval.FilePVLastSignState
	if cmtjson.Unmarshal(oldState, &signedBefore) != nil {
		t.Fatal("invalid signing state")
	}
	processes[0] = launchClusterNode(t, ctx, binary, f, 0, false, filepath.Join(root, "validator-0-restart.log"))
	after := waitAgreement("validator-restart-agreement", first[0].SDKHeight+3)
	// Keep the Full Node alive with both peer limits set to zero. Validators
	// remain connected and commit additional blocks while the isolated observer
	// has no peers and cannot advance, then restore its original peer topology.
	stopClusterNode(t, processes[3])
	processes[3] = launchClusterNode(t, ctx, binary, f, 3, true, filepath.Join(root, "fullnode-partition.log"))
	deadline := time.Now().Add(20 * time.Second)
	var isolatedHeight int64
	isolated := false
	for time.Now().Before(deadline) {
		var peers ctypes.ResultNetInfo
		var info ctypes.ResultABCIInfo
		if clusterRPC(f.RPC[3], "net_info", &peers) == nil && clusterRPC(f.RPC[3], "abci_info", &info) == nil && peers.NPeers == 0 {
			isolatedHeight = info.Response.LastBlockHeight
			isolated = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !isolated {
		t.Fatal("Full Node did not disconnect")
	}
	deadline = time.Now().Add(30 * time.Second)
	advanced := false
	for time.Now().Before(deadline) {
		var info ctypes.ResultABCIInfo
		if clusterRPC(f.RPC[0], "abci_info", &info) == nil && info.Response.LastBlockHeight >= isolatedHeight+3 {
			advanced = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !advanced {
		t.Fatal("validators did not progress during Full Node partition")
	}
	var isolatedInfo ctypes.ResultABCIInfo
	if err := clusterRPC(f.RPC[3], "abci_info", &isolatedInfo); err != nil || isolatedInfo.Response.LastBlockHeight != isolatedHeight {
		t.Fatal("disconnected Full Node advanced", err)
	}
	t.Logf("partition PASS: Full Node height=%d peers=0; 3 validators advanced >=3 blocks", isolatedHeight)
	stopClusterNode(t, processes[3])
	processes[3] = launchClusterNode(t, ctx, binary, f, 3, false, filepath.Join(root, "fullnode-reconnect.log"))
	final := waitAgreement("reconnected-agreement", isolatedHeight+4)
	for i := range processes {
		stopClusterNode(t, processes[i])
	}
	for path, h := range keyHashes {
		b, err := os.ReadFile(path)
		if err != nil || sha256.Sum256(b) != h {
			t.Fatal("Genesis/key changed", path, err)
		}
	}
	for _, rel := range []string{"config/priv_validator_key.json", "data/priv_validator_state.json"} {
		if _, err := os.Lstat(filepath.Join(f.Homes[3], rel)); !os.IsNotExist(err) {
			t.Fatal("Full Node generated signing material")
		}
	}
	var signedAfter privval.FilePVLastSignState
	b, _ = os.ReadFile(filepath.Join(f.Homes[0], "data/priv_validator_state.json"))
	if cmtjson.Unmarshal(b, &signedAfter) != nil || signedAfter.Height <= signedBefore.Height {
		t.Fatal("validator signing state failed to advance")
	}
	// Restore a previously valid but older test signing state. The persisted
	// commits prove the rollback, so preflight must reject without any DB write.
	if err := os.WriteFile(filepath.Join(f.Homes[0], "data/priv_validator_state.json"), oldState, 0600); err != nil {
		t.Fatal(err)
	}
	before := startSnapshot(t, f.Homes[0])
	reject := exec.CommandContext(ctx, binary, append(clusterArgs(f, 0, false), "--preflight-only")...)
	out, err = reject.CombinedOutput()
	_ = os.WriteFile(filepath.Join(root, "rollback-rejection.log"), out, 0600)
	if err == nil || !strings.Contains(string(out), "signing state rollback") {
		t.Fatalf("rollback not rejected: %v\n%s", err, out)
	}
	if !reflect.DeepEqual(before, startSnapshot(t, f.Homes[0])) {
		t.Fatal("rollback rejection changed DB or signing files")
	}
	result := map[string]interface{}{"validators": 3, "full_nodes": 1, "initial": first, "after_validator_restart": after, "after_reconnect": final, "partition_fullnode_height": isolatedHeight, "signing_before": signedBefore.Height, "signing_after": signedAfter.Height, "commit_signature_verification": true, "rollback_rejected_without_writes": true, "fullnode_signing_files_absent": true}
	b, _ = json.MarshalIndent(result, "", "  ")
	if err := os.WriteFile(filepath.Join(root, "result.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("CLUSTER PASS: 3 validators + 1 non-signing Full Node; agreed H=%d AppHash=%s; validator restart, live partition/reconnect, native double-sign guard and persisted-signature rollback checks PASS", final[0].Height, final[0].AppHash)
}

func TestClusterRejectsInterruptedFirstCommit(t *testing.T) {
	home := t.TempDir()
	data := filepath.Join(home, "data")
	if err := os.Mkdir(data, 0700); err != nil {
		t.Fatal(err)
	}
	n := &Node{home: home, cluster: true, role: RoleFullNode}
	if err := n.checkClusterSigning(cmtstate.State{}); err != nil {
		t.Fatal("fresh empty home rejected", err)
	}
	db, err := cmtdb.NewGoLevelDB("blockstore", data)
	if err != nil {
		t.Fatal(err)
	}
	cmtstore.SaveBlockStoreState(&storeproto.BlockStoreState{Base: 1, Height: 1}, db)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	before := startSnapshot(t, home)
	if err := n.checkClusterSigning(cmtstate.State{}); err == nil || !strings.Contains(err.Error(), "blockstore/consensus heights differ") {
		t.Fatal("interrupted height-zero commit accepted", err)
	}
	if !reflect.DeepEqual(before, startSnapshot(t, home)) {
		t.Fatal("rejected interrupted state changed files")
	}
}
