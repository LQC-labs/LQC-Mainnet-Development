//go:build linux

// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0
package node

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"cosmossdk.io/log/v2"
	"github.com/LQC-labs/LQC-Mainnet-Development/app"
	cmtdb "github.com/cometbft/cometbft-db"
	"github.com/cometbft/cometbft/crypto/ed25519"
	cmtjson "github.com/cometbft/cometbft/libs/json"
	"github.com/cometbft/cometbft/privval"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	cmttypes "github.com/cometbft/cometbft/types"
	dbm "github.com/cosmos/cosmos-db"
	"golang.org/x/sys/unix"
)

func TestNodeFixture(t *testing.T) {
	home := os.Getenv("LQC_NODE_FIXTURE_HOME")
	if home == "" {
		t.Skip("fixture subprocess only")
	}
	a, err := app.New(log.NewNopLogger(), dbm.NewMemDB(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if err = InitDevnetHome(a, home); err != nil {
		t.Fatal(err)
	}
}

func preparedNodeHome(t *testing.T) string {
	t.Helper()
	home := filepath.Join(t.TempDir(), "node")
	command := exec.Command(os.Args[0], "-test.run=^TestNodeFixture$", "-test.v")
	command.Env = append(os.Environ(), "LQC_NODE_FIXTURE_HOME="+home)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("fixture: %v\n%s", err, output)
	}
	return home
}

func TestNodeOpenWithoutStarting(t *testing.T) {
	if runDevnetChild(t, "node-open") {
		return
	}
	home := preparedNodeHome(t)
	before := snapshotDevnet(t, home)
	n, err := Open(home)
	if err != nil {
		t.Fatal(err)
	}
	if n.node != nil || n.attempted || n.application.SDK.LastBlockHeight() != 0 {
		t.Fatal("Open started a node")
	}
	if _, err = Open(home); err == nil {
		t.Fatal("duplicate home accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err = n.Start(ctx); err == nil {
		t.Fatal("canceled context accepted")
	}
	if err = n.Close(); err != nil {
		t.Fatal(err)
	}
	if err = n.Close(); err != nil {
		t.Fatal(err)
	}
	if err = n.Start(context.Background()); err == nil {
		t.Fatal("closed node accepted")
	}
	after := snapshotDevnet(t, home)
	for name, content := range before {
		if string(content) != string(after[name]) {
			t.Fatalf("preparation changed %s", name)
		}
	}
	fd, err := openDevnetHome(home)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal("home lock leaked")
	}
	unix.Flock(fd, unix.LOCK_UN)
	// Reconnection uses a separate process; upstream global configuration is
	// never reset to fake a restart. No Start is called in either process.
	command := exec.Command(os.Args[0], "-test.run=^TestNodeReopenOnly$", "-test.v")
	command.Env = append(os.Environ(), "LQC_NODE_REOPEN_HOME="+home)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("reopen: %v\n%s", err, output)
	}
}

func TestNodeReopenOnly(t *testing.T) {
	home := os.Getenv("LQC_NODE_REOPEN_HOME")
	if home == "" {
		t.Skip("reopen subprocess only")
	}
	n, err := Open(home)
	if err != nil {
		t.Fatal(err)
	}
	if n.node != nil || n.application.SDK.LastBlockHeight() != 0 {
		t.Fatal("unexpected node execution")
	}
	if err = n.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestNodePreflightErrors(t *testing.T) {
	for _, mode := range []string{"chain", "gentx", "consensus", "missing-key", "missing-state", "bad-state", "identity", "stored-genesis", "unidentified-db", "db-symlink"} {
		t.Run(mode, func(t *testing.T) {
			if runDevnetChild(t, "node-error-"+mode) {
				return
			}
			home := preparedNodeHome(t)
			expected := ""
			switch mode {
			case "chain", "gentx":
				path := filepath.Join(home, "config/genesis.json")
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var document map[string]interface{}
				if err = json.Unmarshal(raw, &document); err != nil {
					t.Fatal(err)
				}
				if mode == "chain" {
					document["chain_id"] = "wrong-devnet-1"
					expected = "chain identity"
				} else {
					document["app_state"].(map[string]interface{})["genutil"].(map[string]interface{})["gen_txs"] = []interface{}{}
					expected = "invalid test genesis"
				}
				raw, err = json.Marshal(document)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "consensus":
				other := filepath.Join(t.TempDir(), "other")
				if err := CreateHome(other); err != nil {
					t.Fatal(err)
				}
				raw, err := os.ReadFile(filepath.Join(other, "config/priv_validator_key.json"))
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(filepath.Join(home, "config/priv_validator_key.json"), raw, 0600); err != nil {
					t.Fatal(err)
				}
				expected = "does not match"
			case "missing-key", "missing-state":
				name := "config/node_key.json"
				if mode == "missing-state" {
					name = "data/priv_validator_state.json"
				}
				if err := os.Rename(filepath.Join(home, name), filepath.Join(home, name+".saved")); err != nil {
					t.Fatal(err)
				}
				expected = "open "
			case "bad-state":
				if err := os.WriteFile(filepath.Join(home, "data/priv_validator_state.json"), []byte(`{"height":"1","round":0,"step":3}`), 0600); err != nil {
					t.Fatal(err)
				}
				expected = "signing state signature"
			case "identity":
				if err := os.WriteFile(filepath.Join(home, "data/node.identity.json"), []byte(`{"chain_id":"wrong"}`), 0600); err != nil {
					t.Fatal(err)
				}
				expected = "identity mismatch"
			case "unidentified-db":
				if err := os.Mkdir(filepath.Join(home, "data/application.db"), 0700); err != nil {
					t.Fatal(err)
				}
				expected = "without trusted"
			case "db-symlink":
				if err := os.Symlink(t.TempDir(), filepath.Join(home, "data/evidence.db")); err != nil {
					t.Fatal(err)
				}
				expected = "symlink in node DB"
			case "stored-genesis":
				fd, err := openDevnetHome(home)
				if err != nil {
					t.Fatal(err)
				}
				pv, nk, err := loadRuntimeKeys(fd, home)
				unix.Close(fd)
				if err != nil {
					t.Fatal(err)
				}
				raw, err := os.ReadFile(filepath.Join(home, "config/genesis.json"))
				if err != nil {
					t.Fatal(err)
				}
				sum := sha256.Sum256(raw)
				identity := nodeIdentity{ChainID: "lqc-devnet-test-1", GenesisSHA256: hex.EncodeToString(sum[:]), ConsensusPublicKey: hex.EncodeToString(pv.Key.PubKey.Bytes()), NodeID: string(nk.ID())}
				raw, err = json.Marshal(identity)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(filepath.Join(home, "data/node.identity.json"), raw, 0600); err != nil {
					t.Fatal(err)
				}
				database, err := cmtdb.NewDB("state", cmtdb.GoLevelDBBackend, filepath.Join(home, "data"))
				if err != nil {
					t.Fatal(err)
				}
				raw, err = cmtjson.Marshal(&cmttypes.GenesisDoc{ChainID: "wrong-devnet-1"})
				if err != nil {
					t.Fatal(err)
				}
				if err = database.SetSync([]byte("genesisDoc"), raw); err != nil {
					t.Fatal(err)
				}
				database.Close()
				expected = "Comet Genesis mismatch"
			}
			n, err := Open(home)
			if err == nil {
				n.Close()
				t.Fatal("invalid preflight accepted")
			}
			if !strings.Contains(err.Error(), expected) {
				t.Fatalf("wrong error for %s: %v", mode, err)
			}
			if mode == "gentx" || mode == "consensus" {
				database, openErr := dbm.NewDB("application", dbm.GoLevelDBBackend, filepath.Join(home, "data"))
				if openErr != nil {
					t.Fatal("failed preflight leaked application DB")
				}
				database.Close()
			}
			fd, err := openDevnetHome(home)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(fd)
			if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
				t.Fatal("failed preflight leaked lock")
			}
			unix.Flock(fd, unix.LOCK_UN)
		})
	}
}

func TestLocalConfigAndSigningState(t *testing.T) {
	cfg := localConfig("/tmp/isolated-home")
	if err := cfg.ValidateBasic(); err != nil {
		t.Fatal(err)
	}
	if cfg.P2P.ListenAddress != "tcp://127.0.0.1:26656" || cfg.RPC.ListenAddress != "tcp://127.0.0.1:26657" || cfg.P2P.PexReactor || cfg.P2P.Seeds != "" || cfg.P2P.PersistentPeers != "" || cfg.P2P.MaxNumOutboundPeers != 0 || cfg.StateSync.Enable || cfg.Instrumentation.Prometheus || cfg.RPC.GRPCListenAddress != "" || cfg.RPC.Unsafe {
		t.Fatal("unsafe local config")
	}
	private := ed25519.GenPrivKey()
	key := privval.FilePVKey{PrivKey: private, PubKey: private.PubKey(), Address: private.PubKey().Address()}
	if err := checkSigningState(key, privval.FilePVLastSignState{}); err != nil {
		t.Fatal(err)
	}
	vote := &cmtproto.Vote{Type: cmtproto.PrecommitType, Height: 12, Round: 0}
	signBytes := cmttypes.VoteSignBytes("lqc-devnet-test-1", vote)
	signature, err := private.Sign(signBytes)
	if err != nil {
		t.Fatal(err)
	}
	state := privval.FilePVLastSignState{Height: 12, Round: 0, Step: 3, SignBytes: signBytes, Signature: signature}
	if err = checkSigningState(key, state); err != nil {
		t.Fatal(err)
	}
	state.Height = 11
	if err = checkSigningState(key, state); err == nil {
		t.Fatal("HRS mismatch accepted")
	}
	state.Height = 12
	state.SignBytes = cmttypes.VoteSignBytes("wrong-devnet-1", vote)
	state.Signature, err = private.Sign(state.SignBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err = checkSigningState(key, state); err == nil {
		t.Fatal("wrong signing chain accepted")
	}
}
