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
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"cosmossdk.io/log/v2"
	"cosmossdk.io/math"
	"github.com/LQC-labs/LQC-Mainnet-Development/app"
	chainconfig "github.com/LQC-labs/LQC-Mainnet-Development/chain/config"
	"github.com/LQC-labs/LQC-Mainnet-Development/genesis"
	cmtjson "github.com/cometbft/cometbft/libs/json"
	"github.com/cometbft/cometbft/privval"
	cmttypes "github.com/cometbft/cometbft/types"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/client/tx"
	sdked25519 "github.com/cosmos/cosmos-sdk/crypto/keys/ed25519"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	genutiltypes "github.com/cosmos/cosmos-sdk/x/genutil/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"github.com/cosmos/evm/crypto/ethsecp256k1"
	evmtypes "github.com/cosmos/evm/x/vm/types"
	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/sys/unix"
)

func startFixtureProfile() chainconfig.RuntimeConfig {
	// Synthetic test profile; never adopted as LQC Mainnet parameters.
	return chainconfig.RuntimeConfig{Chain: chainconfig.ChainConfig{NetworkKind: chainconfig.NetworkMainnet, CosmosChainID: "runtime-start-fixture-3", EVMChainID: 423456783, Bech32Prefix: "starttest", NativeDenom: "astart"}, MinimumGasPrice: "0.01astart"}
}

func TestRuntimePolicyAndRPC(t *testing.T) {
	cfg := startFixtureProfile()
	id := new(big.Int).SetUint64(cfg.Chain.EVMChainID)
	if err := validateEVMRPCProfile(cfg, cfg.Chain.CosmosChainID, cfg.Chain.EVMChainID, id); err != nil {
		t.Fatal(err)
	}
	if validateEVMRPCProfile(cfg, "wrong", cfg.Chain.EVMChainID, id) == nil || validateEVMRPCProfile(cfg, cfg.Chain.CosmosChainID, cfg.Chain.EVMChainID, nil) == nil {
		t.Fatal("RPC identity mismatch accepted")
	}
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	to := common.HexToAddress("0x1000000000000000000000000000000000000001")
	for name, chain := range map[string]*big.Int{"configured": id, "devnet": big.NewInt(917001), "overflow": new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 64), id)} {
		tx, err := ethtypes.SignNewTx(key, ethtypes.LatestSignerForChainID(chain), &ethtypes.DynamicFeeTx{ChainID: chain, To: &to, Gas: 21000, GasFeeCap: big.NewInt(1), GasTipCap: big.NewInt(1)})
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := tx.MarshalBinary()
		err = validateRawEVMTransactionForChain(raw, id)
		if (name == "configured") != (err == nil) {
			t.Fatal("wrong configured replay protection", name, err)
		}
	}
	if validateRawEVMTransactionForChain(nil, nil) == nil {
		t.Fatal("missing EVM chain accepted")
	}
	options := RuntimeOptions{Network: chainconfig.NetworkMainnet, Profile: cfg, GenesisPath: "/not-read", ExpectedGenesisSHA256: strings.Repeat("0", 64), LocalTestOnly: true}
	if err := options.validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*RuntimeOptions){"public-mode": func(o *RuntimeOptions) { o.LocalTestOnly = false }, "network": func(o *RuntimeOptions) { o.Network = "" }, "hash": func(o *RuntimeOptions) { o.ExpectedGenesisSHA256 = "" }, "public-rpc": func(o *RuntimeOptions) { o.CometRPCListen = "0.0.0.0:26657" }, "public-p2p": func(o *RuntimeOptions) { o.P2PListen = "192.0.2.1:26656" }, "public-evm": func(o *RuntimeOptions) { o.EVMRPCListen = "0.0.0.0:8545" }} {
		t.Run(name, func(t *testing.T) {
			o := options
			mutate(&o)
			if o.validate() == nil {
				t.Fatal("unsafe runtime accepted")
			}
		})
	}
}

type startFixture struct {
	Home, Config, Genesis, SHA256 string
	Profile                       chainconfig.RuntimeConfig
}

func TestRuntimeFixtureChild(t *testing.T) {
	root := os.Getenv("LQC_START_FIXTURE_ROOT")
	if root == "" {
		t.Skip("fixture child only")
	}
	cfg := startFixtureProfile()
	if os.Getenv("LQC_START_FIXTURE_NETWORK") == "devnet" {
		cfg = chainconfig.RuntimeFromDevnet(chainconfig.TestOnlyDevnetConfig())
	}
	a, err := app.NewWithConfig(log.NewNopLogger(), dbm.NewMemDB(), t.TempDir(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	home := filepath.Join(root, "home")
	if cfg.Chain.NetworkKind == chainconfig.NetworkDevnet {
		if err := InitDevnetHome(a, home); err != nil {
			t.Fatal(err)
		}
	} else {
		if err := CreateHome(home); err != nil {
			t.Fatal(err)
		}
		fd, err := openDevnetHome(home)
		if err != nil {
			t.Fatal(err)
		}
		public, err := loadDevnetKeys(fd)
		unix.Close(fd)
		if err != nil {
			t.Fatal(err)
		}
		state := a.SDK.BasicModuleManager.DefaultGenesis(a.SDK.AppCodec())
		for name, raw := range state {
			if len(raw) == 0 {
				delete(state, name)
			} else {
				state[name] = bytes.ReplaceAll(raw, []byte(`"stake"`), []byte(`"astart"`))
			}
		}
		var bank banktypes.GenesisState
		var auth authtypes.GenesisState
		cdc := a.SDK.AppCodec()
		cdc.MustUnmarshalJSON(state["bank"], &bank)
		cdc.MustUnmarshalJSON(state["auth"], &auth)
		bank.DenomMetadata = []banktypes.Metadata{{Base: "astart", Display: "startfixture", Name: "Offline start fixture", Symbol: "FIX", DenomUnits: []*banktypes.DenomUnit{{Denom: "astart", Exponent: 0}, {Denom: "startfixture", Exponent: 18}}}}
		evm := evmtypes.DefaultGenesisState()
		evm.Params.EvmDenom = "astart"
		evm.Params.ExtendedDenomOptions = &evmtypes.ExtendedDenomOptions{ExtendedDenom: "astart"}
		state["evm"] = cdc.MustMarshalJSON(evm)
		accounts := authtypes.GenesisAccounts{}
		gentxs := []json.RawMessage{}
		count := 1
		if os.Getenv("LQC_START_FIXTURE_MULTI") == "1" {
			count = 2
		}
		for i := 0; i < count; i++ {
			consensus := public
			if i == 1 {
				consensus = &sdked25519.PubKey{Key: bytes.Repeat([]byte{0x34}, 32)}
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
			msg, err := stakingtypes.NewMsgCreateValidator(sdk.ValAddress(address).String(), consensus, bond, stakingtypes.NewDescription("offline-start", "", "", "", ""), stakingtypes.NewCommissionRates(math.LegacyZeroDec(), math.LegacyOneDec(), math.LegacyOneDec()), math.OneInt())
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
			raw, err := a.SDK.GetTxConfig().TxJSONEncoder()(builder.GetTx())
			if err != nil {
				t.Fatal(err)
			}
			gentxs = append(gentxs, raw)
		}
		auth.Accounts, err = authtypes.PackAccounts(accounts)
		if err != nil {
			t.Fatal(err)
		}
		state["auth"] = cdc.MustMarshalJSON(&auth)
		state["bank"] = cdc.MustMarshalJSON(&bank)
		state["genutil"] = cdc.MustMarshalJSON(&genutiltypes.GenesisState{GenTxs: gentxs})
		raw, err := json.Marshal(state)
		if err != nil {
			t.Fatal(err)
		}
		doc := genesis.MainnetDocument{AppGenesis: genutiltypes.AppGenesis{AppName: app.Name, AppVersion: app.Version, ChainID: cfg.Chain.CosmosChainID, GenesisTime: time.Unix(1_700_000_000, 0).UTC(), InitialHeight: 1, AppState: raw, Consensus: &genutiltypes.ConsensusGenesis{Params: cmttypes.DefaultConsensusParams()}}, Profile: cfg, SchemaVersion: genesis.MainnetGenesisSchemaVersion}
		output, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(home, "config/genesis.json"), output, 0600); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(filepath.Join(home, "config/genesis.json"))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	config := filepath.Join(root, "runtime.json")
	b, _ := json.Marshal(cfg)
	if err := os.WriteFile(config, b, 0600); err != nil {
		t.Fatal(err)
	}
	fixture := startFixture{Home: home, Config: config, Genesis: filepath.Join(home, "config/genesis.json"), SHA256: hex.EncodeToString(digest[:]), Profile: cfg}
	b, _ = json.Marshal(fixture)
	if err := os.WriteFile(filepath.Join(root, "fixture.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
}

func prepareStartFixture(t *testing.T, network string, multi bool) (string, startFixture) {
	t.Helper()
	root, err := os.MkdirTemp("/tmp", "lqc-runtime-start.")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestRuntimeFixtureChild$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), "LQC_START_FIXTURE_ROOT="+root, "LQC_START_FIXTURE_NETWORK="+network)
	if multi {
		cmd.Env = append(cmd.Env, "LQC_START_FIXTURE_MULTI=1")
	}
	out, err := cmd.CombinedOutput()
	_ = os.WriteFile(filepath.Join(root, "prepare.log"), out, 0600)
	if err != nil {
		t.Fatalf("prepare failed: %v\n%s", err, out)
	}
	var fixture startFixture
	b, err := os.ReadFile(filepath.Join(root, "fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	t.Log("PRESERVED_RUNTIME_START_EVIDENCE=" + root)
	return root, fixture
}

func startArgs(f startFixture) []string {
	return []string{"start", "--network", string(f.Profile.Chain.NetworkKind), "--config", f.Config, "--genesis", f.Genesis, "--expected-genesis-sha256", f.SHA256, "--home", f.Home, "--local-test-only", "--evm-rpc-listen", "127.0.0.1:8545"}
}

func startSnapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	result := map[string]string{}
	err := filepath.WalkDir(root, func(p string, e os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := e.Info()
		if err != nil {
			return err
		}
		if e.IsDir() {
			return nil
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		result[p] = fmt.Sprintf("%x:%o:%d", sha256.Sum256(raw), info.Mode().Perm(), info.ModTime().UnixNano())
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestRuntimeRejections(t *testing.T) {
	if os.Getenv("LQC_RUN_RUNTIME_START") != "1" {
		t.Skip("explicit isolated CLI test opt-in required")
	}
	binary := os.Getenv("LQC_STEP3_CLI_BINARY")
	if binary == "" {
		t.Fatal("CLI binary required")
	}
	for _, mode := range []string{"wrong-hash", "wrong-profile", "public-evm", "missing-key", "invalid-signature", "multi-validator"} {
		t.Run(mode, func(t *testing.T) {
			root, f := prepareStartFixture(t, "mainnet", mode == "multi-validator")
			args := startArgs(f)
			switch mode {
			case "wrong-hash":
				args[8] = strings.Repeat("0", 64)
			case "wrong-profile":
				cfg := f.Profile
				cfg.Chain.EVMChainID++
				b, _ := json.Marshal(cfg)
				if err := os.WriteFile(f.Config, b, 0600); err != nil {
					t.Fatal(err)
				}
			case "public-evm":
				args[len(args)-1] = "0.0.0.0:8545"
			case "missing-key":
				if err := os.Rename(filepath.Join(f.Home, "config/node_key.json"), filepath.Join(root, "node_key.saved")); err != nil {
					t.Fatal(err)
				}
			case "invalid-signature":
				var doc map[string]interface{}
				b, _ := os.ReadFile(f.Genesis)
				_ = json.Unmarshal(b, &doc)
				doc["app_state"].(map[string]interface{})["genutil"].(map[string]interface{})["gen_txs"].([]interface{})[0].(map[string]interface{})["signatures"] = []string{"AAAA"}
				b, _ = json.Marshal(doc)
				if err := os.WriteFile(f.Genesis, b, 0600); err != nil {
					t.Fatal(err)
				}
				h := sha256.Sum256(b)
				args[8] = hex.EncodeToString(h[:])
			}
			before := startSnapshot(t, f.Home)
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binary, args...)
			out, err := cmd.CombinedOutput()
			_ = os.WriteFile(filepath.Join(root, "reject.log"), out, 0600)
			if err == nil || ctx.Err() != nil {
				t.Fatalf("rejection failed: %v\n%s", err, out)
			}
			want := map[string]string{"wrong-hash": "Genesis SHA-256 mismatch", "wrong-profile": "Genesis schema/profile mismatch", "public-evm": "RPC must bind numeric IPv4 loopback", "missing-key": "open node_key.json", "invalid-signature": "signature", "multi-validator": "single-validator local runtime only"}[mode]
			if !strings.Contains(string(out), want) {
				t.Fatalf("wrong rejection for %s: %s", mode, out)
			}
			if !reflect.DeepEqual(before, startSnapshot(t, f.Home)) {
				t.Fatal("rejected request changed prepared home")
			}
			t.Logf("%s rejected before persistent writes: %s", mode, out)
		})
	}
}

func TestRuntimeLocalCLIIntegration(t *testing.T) {
	if os.Getenv("LQC_RUN_RUNTIME_START") != "1" {
		t.Skip("explicit isolated CLI test opt-in required")
	}
	binary := os.Getenv("LQC_STEP3_CLI_BINARY")
	if binary == "" {
		t.Fatal("CLI binary required")
	}
	for _, network := range []string{"devnet", "mainnet"} {
		t.Run(network, func(t *testing.T) {
			root, f := prepareStartFixture(t, network, false)
			keyHashes := map[string][32]byte{}
			for _, rel := range []string{"config/genesis.json", "config/node_key.json", "config/priv_validator_key.json"} {
				b, err := os.ReadFile(filepath.Join(f.Home, rel))
				if err != nil {
					t.Fatal(err)
				}
				keyHashes[rel] = sha256.Sum256(b)
			}
			var previousSigning int64
			for run, target := range []uint64{3, 6} {
				ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
				logPath := filepath.Join(root, fmt.Sprintf("run-%d.log", run))
				file, err := os.OpenFile(logPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
				if err != nil {
					cancel()
					t.Fatal(err)
				}
				cmd := exec.CommandContext(ctx, binary, startArgs(f)...)
				cmd.Stdout = file
				cmd.Stderr = file
				if err := cmd.Start(); err != nil {
					cancel()
					file.Close()
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() { done <- cmd.Wait() }()
				client := &http.Client{Timeout: time.Second}
				reached := false
				for ctx.Err() == nil {
					response, err := client.Post("http://127.0.0.1:8545/", "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}`))
					if err == nil {
						var rpc struct {
							Result string
							Error  interface{}
						}
						_ = json.NewDecoder(response.Body).Decode(&rpc)
						response.Body.Close()
						if rpc.Result != "" && rpc.Result != fmt.Sprintf("0x%x", f.Profile.Chain.EVMChainID) {
							t.Fatal("RPC wrong chain ID", rpc.Result)
						}
						response, err = client.Post("http://127.0.0.1:8545/", "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"eth_blockNumber","params":[]}`))
						if err == nil {
							var block struct{ Result string }
							_ = json.NewDecoder(response.Body).Decode(&block)
							response.Body.Close()
							height, _ := strconv.ParseUint(strings.TrimPrefix(block.Result, "0x"), 16, 64)
							if height >= target && rpc.Result == fmt.Sprintf("0x%x", f.Profile.Chain.EVMChainID) {
								reached = true
								break
							}
						}
					}
					select {
					case err := <-done:
						cancel()
						file.Close()
						b, _ := os.ReadFile(logPath)
						t.Fatalf("CLI exited before readiness: %v\n%s", err, b)
					case <-time.After(100 * time.Millisecond):
					}
				}
				client.CloseIdleConnections()
				if !reached {
					cancel()
					<-done
					file.Close()
					b, _ := os.ReadFile(logPath)
					t.Fatalf("CLI height deadline\n%s", b)
				}
				if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
					cancel()
					t.Fatal(err)
				}
				err = <-done
				cancel()
				file.Close()
				if err != nil {
					b, _ := os.ReadFile(logPath)
					t.Fatalf("SIGTERM cleanup failed: %v\n%s", err, b)
				}
				if conn, err := net.DialTimeout("tcp", "127.0.0.1:8545", time.Second); err == nil {
					conn.Close()
					t.Fatal("RPC survived shutdown")
				}
				stateRaw, err := os.ReadFile(filepath.Join(f.Home, "data/priv_validator_state.json"))
				if err != nil {
					t.Fatal(err)
				}
				var signed privval.FilePVLastSignState
				if cmtjson.Unmarshal(stateRaw, &signed) != nil || signed.Height < int64(target) || signed.Height < previousSigning || len(signed.Signature) == 0 {
					t.Fatal("signing state not preserved", signed.Height)
				}
				previousSigning = signed.Height
				for rel, h := range keyHashes {
					b, err := os.ReadFile(filepath.Join(f.Home, rel))
					if err != nil || sha256.Sum256(b) != h {
						t.Fatal("key/Genesis changed", rel, err)
					}
				}
				fd, err := openDevnetHome(f.Home)
				if err != nil {
					t.Fatal(err)
				}
				if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
					unix.Close(fd)
					t.Fatal("home lock leaked")
				}
				unix.Flock(fd, unix.LOCK_UN)
				unix.Close(fd)
				t.Logf("%s CLI run=%d target=%d signing=%d; injected chain/RPC, SIGTERM, keys and flock PASS", network, run, target, signed.Height)
			}
			identityRaw, err := os.ReadFile(filepath.Join(f.Home, "data/node.identity.json"))
			if err != nil {
				t.Fatal(err)
			}
			var identity nodeIdentity
			if json.Unmarshal(identityRaw, &identity) != nil || identity.ChainID != f.Profile.Chain.CosmosChainID || identity.GenesisSHA256 != f.SHA256 {
				t.Fatal("persistent Genesis identity missing")
			}
			if network == "mainnet" && identity.ProfileSHA256 != runtimeProfileSHA256(f.Profile) {
				t.Fatal("runtime profile identity missing")
			}
			// A changed Genesis with a freshly supplied matching hash must still
			// fail against the existing DB identity before any DB is opened.
			var doc map[string]interface{}
			b, _ := os.ReadFile(f.Genesis)
			_ = json.Unmarshal(b, &doc)
			doc["genesis_time"] = "2020-01-01T00:00:00Z"
			b, _ = json.Marshal(doc)
			if err := os.WriteFile(f.Genesis, b, 0600); err != nil {
				t.Fatal(err)
			}
			h := sha256.Sum256(b)
			changed := f
			changed.SHA256 = hex.EncodeToString(h[:])
			before := startSnapshot(t, f.Home)
			cmd := exec.CommandContext(t.Context(), binary, startArgs(changed)...)
			out, err := cmd.CombinedOutput()
			_ = os.WriteFile(filepath.Join(root, "db-genesis-rejection.log"), out, 0600)
			if err == nil || !strings.Contains(string(out), "identity mismatch") {
				t.Fatalf("different Genesis reused DB: %v\n%s", err, out)
			}
			if !reflect.DeepEqual(before, startSnapshot(t, f.Home)) {
				t.Fatal("rejected DB reuse changed persistent files")
			}
		})
	}
}
