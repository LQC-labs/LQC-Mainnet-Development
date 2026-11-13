//go:build linux

// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

package genesis_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"cosmossdk.io/log/v2"
	"cosmossdk.io/math"
	"github.com/LQC-labs/LQC-Mainnet-Development/app"
	chainconfig "github.com/LQC-labs/LQC-Mainnet-Development/chain/config"
	"github.com/LQC-labs/LQC-Mainnet-Development/genesis"
	cmted25519 "github.com/cometbft/cometbft/crypto/ed25519"
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
	"golang.org/x/sys/unix"
)

func mainnetFixtureProfile() chainconfig.RuntimeConfig {
	// Synthetic offline values only. Never adopted as LQC network parameters.
	return chainconfig.RuntimeConfig{Chain: chainconfig.ChainConfig{NetworkKind: chainconfig.NetworkMainnet, CosmosChainID: "mainnet-fixture-2", EVMChainID: 423456782, Bech32Prefix: "mntest", NativeDenom: "afixture"}, MinimumGasPrice: "0.01afixture"}
}

func mainnetFixture(t *testing.T, a *app.App, decimals uint32, signingChain string) genesis.MainnetDocument {
	t.Helper()
	cdc := a.SDK.AppCodec()
	cfg := a.Profile
	state := a.SDK.BasicModuleManager.DefaultGenesis(cdc)
	for name, raw := range state {
		if len(raw) == 0 {
			delete(state, name)
			continue
		}
		state[name] = bytes.ReplaceAll(raw, []byte(`"stake"`), []byte(`"`+cfg.Chain.NativeDenom+`"`))
	}
	var bank banktypes.GenesisState
	var auth authtypes.GenesisState
	cdc.MustUnmarshalJSON(state[banktypes.ModuleName], &bank)
	cdc.MustUnmarshalJSON(state[authtypes.ModuleName], &auth)
	bank.DenomMetadata = []banktypes.Metadata{{Base: cfg.Chain.NativeDenom, Display: "fixture", Name: "Offline synthetic fixture", Symbol: "FIX", DenomUnits: []*banktypes.DenomUnit{{Denom: cfg.Chain.NativeDenom, Exponent: 0}, {Denom: "fixture", Exponent: decimals}}}}
	evm := evmtypes.DefaultGenesisState()
	evm.Params.EvmDenom = cfg.Chain.NativeDenom
	extended := cfg.Chain.NativeDenom
	if decimals != 18 {
		extended = "aextendedfixture"
	}
	evm.Params.ExtendedDenomOptions = &evmtypes.ExtendedDenomOptions{ExtendedDenom: extended}
	state[evmtypes.ModuleName] = cdc.MustMarshalJSON(evm)
	params := cmttypes.DefaultConsensusParams()
	params.Block.MaxGas = 30_000_000
	params.Validator.PubKeyTypes = []string{"ed25519"}
	consensus := &genutiltypes.ConsensusGenesis{Params: params}
	accounts := authtypes.GenesisAccounts{}
	gentxs := []json.RawMessage{}
	publicVectors := []string{"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"}
	for i, vector := range publicVectors {
		// Disposable account signers stay in memory. Consensus uses public test
		// vectors only; no validator/P2P key or signing state is generated.
		account, err := ethsecp256k1.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		pub, _ := hex.DecodeString(vector)
		consensusKey := &sdked25519.PubKey{Key: pub}
		address := sdk.AccAddress(account.PubKey().Address())
		accounts = append(accounts, authtypes.NewBaseAccount(address, account.PubKey(), 0, 0))
		bond := sdk.NewCoin(cfg.Chain.NativeDenom, sdk.DefaultPowerReduction.MulRaw(int64(i+1)))
		funds := sdk.NewCoins(sdk.NewCoin(cfg.Chain.NativeDenom, bond.Amount.MulRaw(3)))
		bank.Balances = append(bank.Balances, banktypes.Balance{Address: address.String(), Coins: funds})
		bank.Supply = bank.Supply.Add(funds...)
		msg, err := stakingtypes.NewMsgCreateValidator(sdk.ValAddress(address).String(), consensusKey, bond, stakingtypes.NewDescription(fmt.Sprintf("offline-%d", i), "", "", "", ""), stakingtypes.NewCommissionRates(math.LegacyZeroDec(), math.LegacyOneDec(), math.LegacyOneDec()), math.OneInt())
		if err != nil {
			t.Fatal(err)
		}
		builder := a.SDK.GetTxConfig().NewTxBuilder()
		if err := builder.SetMsgs(msg); err != nil {
			t.Fatal(err)
		}
		builder.SetGasLimit(3_000_000)
		if err := builder.SetSignatures(signing.SignatureV2{PubKey: account.PubKey(), Data: &signing.SingleSignatureData{SignMode: signing.SignMode_SIGN_MODE_DIRECT}, Sequence: 0}); err != nil {
			t.Fatal(err)
		}
		sig, err := tx.SignWithPrivKey(context.Background(), signing.SignMode_SIGN_MODE_DIRECT, authsigning.SignerData{Address: address.String(), ChainID: signingChain, AccountNumber: 0, Sequence: 0, PubKey: account.PubKey()}, builder, account, a.SDK.GetTxConfig(), 0)
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
		cometKey := cmted25519.PubKey(pub)
		consensus.Validators = append(consensus.Validators, cmttypes.GenesisValidator{Address: cometKey.Address(), PubKey: cometKey, Power: int64(i + 1), Name: fmt.Sprintf("offline-%d", i)})
	}
	var err error
	auth.Accounts, err = authtypes.PackAccounts(accounts)
	if err != nil {
		t.Fatal(err)
	}
	state[authtypes.ModuleName] = cdc.MustMarshalJSON(&auth)
	state[banktypes.ModuleName] = cdc.MustMarshalJSON(&bank)
	state[genutiltypes.ModuleName] = cdc.MustMarshalJSON(&genutiltypes.GenesisState{GenTxs: gentxs})
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	return genesis.MainnetDocument{AppGenesis: genutiltypes.AppGenesis{AppName: app.Name, AppVersion: app.Version, ChainID: cfg.Chain.CosmosChainID, GenesisTime: time.Unix(1_700_000_000, 0).UTC(), InitialHeight: 1, AppState: raw, Consensus: consensus}, Profile: cfg, SchemaVersion: genesis.MainnetGenesisSchemaVersion}
}

func mainnetBytes(t *testing.T, doc genesis.MainnetDocument) ([]byte, string) {
	t.Helper()
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b)
	return b, hex.EncodeToString(h[:])
}

func TestMainnetGenesisValidation(t *testing.T) {
	mode := os.Getenv("LQC_STEP2_MAINNET_CASE")
	if mode == "" {
		for _, name := range []string{"18", "6"} {
			t.Run(name, func(t *testing.T) {
				cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestMainnetGenesisValidation$", "-test.count=1", "-test.v", "-test.timeout=150s")
				cmd.Env = append(os.Environ(), "LQC_STEP2_MAINNET_CASE="+name)
				out, err := cmd.CombinedOutput()
				t.Log(string(out))
				if err != nil {
					t.Fatal(err)
				}
			})
		}
		return
	}
	decimals := uint32(18)
	if mode == "6" {
		decimals = 6
	}
	cfg := mainnetFixtureProfile()
	home := t.TempDir()
	a, err := app.NewWithConfig(log.NewNopLogger(), dbm.NewMemDB(), home, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := a.Close(); err != nil {
			t.Error(err)
		}
	}()
	before := a.SDK.LastCommitID()
	homeBefore := mainnetHomeSnapshot(t, home)
	t.Logf("scratch home after app construction: %v", homeBefore)
	doc := mainnetFixture(t, a, decimals, cfg.Chain.CosmosChainID)
	raw, digest := mainnetBytes(t, doc)
	loaded, err := genesis.LoadMainnet(bytes.NewReader(raw), cfg, digest)
	if err != nil {
		t.Fatal(err)
	}
	report, err := genesis.ValidateMainnet(a, loaded)
	if err != nil {
		t.Fatal(err)
	}
	if report.Decimals != decimals || len(report.Validators) != 2 || report.Validators[0].VotingPower != 1 || report.Validators[1].VotingPower != 2 || report.LaunchApproved || report.GenesisSHA256 != digest {
		t.Fatalf("unexpected report: %+v", report)
	}
	copyOfBytes := loaded.Bytes()
	copyOfBytes[0] = 'x'
	if !bytes.Equal(loaded.Bytes(), raw) {
		t.Fatal("mutable input snapshot")
	}
	path := filepath.Join(t.TempDir(), "genesis.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if g, err := genesis.LoadMainnetFile(path, cfg, digest); err != nil || g.SHA256() != digest {
		t.Fatal("file loading failed", err)
	}
	configRaw, _ := json.Marshal(cfg)
	if decoded, err := genesis.DecodeMainnetConfig(configRaw); err != nil || decoded != cfg {
		t.Fatal("config decoding", err)
	}
	if _, err := genesis.LoadMainnet(bytes.NewReader(raw), cfg, strings.Repeat("0", 64)); err == nil {
		t.Fatal("wrong digest accepted")
	}
	if _, err := genesis.LoadMainnet(bytes.NewReader(raw), cfg, ""); err == nil {
		t.Fatal("missing digest accepted")
	}
	other := cfg
	other.Chain.EVMChainID++
	if _, err := genesis.LoadMainnet(bytes.NewReader(raw), other, digest); err == nil {
		t.Fatal("different runtime profile accepted")
	}
	if _, err := genesis.LoadMainnet(bytes.NewReader(raw), chainconfig.RuntimeFromDevnet(chainconfig.TestOnlyDevnetConfig()), digest); err == nil {
		t.Fatal("Devnet accepted by Mainnet loader")
	}
	if _, err := genesis.DecodeMainnetConfig([]byte(`{}`)); err == nil {
		t.Fatal("empty config accepted")
	}
	if _, err := genesis.DecodeMainnetConfig(append(configRaw, []byte(` {}`)...)); err == nil {
		t.Fatal("trailing config accepted")
	}
	if _, err := genesis.LoadMainnet(strings.NewReader(strings.Repeat("x", genesis.MaxMainnetGenesisBytes+1)), cfg, digest); err == nil {
		t.Fatal("oversize input accepted")
	}
	for name, mutate := range map[string]func(*genesis.MainnetDocument, map[string]json.RawMessage){
		"height":            func(d *genesis.MainnetDocument, _ map[string]json.RawMessage) { d.InitialHeight = 0 },
		"time":              func(d *genesis.MainnetDocument, _ map[string]json.RawMessage) { d.GenesisTime = time.Time{} },
		"app-hash":          func(d *genesis.MainnetDocument, _ map[string]json.RawMessage) { d.AppHash = []byte{1} },
		"schema":            func(d *genesis.MainnetDocument, _ map[string]json.RawMessage) { d.SchemaVersion = 0 },
		"version":           func(d *genesis.MainnetDocument, _ map[string]json.RawMessage) { d.AppVersion = "other" },
		"chain":             func(d *genesis.MainnetDocument, _ map[string]json.RawMessage) { d.ChainID = "other-fixture-2" },
		"consensus-default": func(d *genesis.MainnetDocument, _ map[string]json.RawMessage) { d.Consensus.Params = nil },
		"consensus-power":   func(d *genesis.MainnetDocument, _ map[string]json.RawMessage) { d.Consensus.Validators[0].Power++ },
		"consensus-address": func(d *genesis.MainnetDocument, _ map[string]json.RawMessage) {
			d.Consensus.Validators[0].Address = nil
		},
		"consensus-key-type": func(d *genesis.MainnetDocument, _ map[string]json.RawMessage) {
			d.Consensus.Params.Validator.PubKeyTypes = []string{"secp256k1"}
		},
		"missing-module": func(_ *genesis.MainnetDocument, s map[string]json.RawMessage) { delete(s, "bank") },
		"extra-module": func(_ *genesis.MainnetDocument, s map[string]json.RawMessage) {
			s["unexpected"] = json.RawMessage(`{}`)
		},
		"null-module":    func(_ *genesis.MainnetDocument, s map[string]json.RawMessage) { s["bank"] = json.RawMessage(`null`) },
		"missing-params": func(_ *genesis.MainnetDocument, s map[string]json.RawMessage) { s["mint"] = json.RawMessage(`{}`) },
		"supply": func(_ *genesis.MainnetDocument, s map[string]json.RawMessage) {
			var b banktypes.GenesisState
			a.SDK.AppCodec().MustUnmarshalJSON(s["bank"], &b)
			b.Supply = sdk.NewCoins(sdk.NewInt64Coin(cfg.Chain.NativeDenom, 1))
			s["bank"] = a.SDK.AppCodec().MustMarshalJSON(&b)
		},
		"metadata": func(_ *genesis.MainnetDocument, s map[string]json.RawMessage) {
			var b banktypes.GenesisState
			a.SDK.AppCodec().MustUnmarshalJSON(s["bank"], &b)
			b.DenomMetadata = nil
			s["bank"] = a.SDK.AppCodec().MustMarshalJSON(&b)
		},
		"decimals": func(_ *genesis.MainnetDocument, s map[string]json.RawMessage) {
			var b banktypes.GenesisState
			a.SDK.AppCodec().MustUnmarshalJSON(s["bank"], &b)
			b.DenomMetadata[0].DenomUnits[1].Exponent = 19
			s["bank"] = a.SDK.AppCodec().MustMarshalJSON(&b)
		},
		"unowned-balance": func(_ *genesis.MainnetDocument, s map[string]json.RawMessage) {
			var b banktypes.GenesisState
			a.SDK.AppCodec().MustUnmarshalJSON(s["bank"], &b)
			b.Balances[0].Address = sdk.AccAddress(bytes.Repeat([]byte{9}, 20)).String()
			s["bank"] = a.SDK.AppCodec().MustMarshalJSON(&b)
		},
		"duplicate-account": func(_ *genesis.MainnetDocument, s map[string]json.RawMessage) {
			var v authtypes.GenesisState
			a.SDK.AppCodec().MustUnmarshalJSON(s["auth"], &v)
			v.Accounts = append(v.Accounts, v.Accounts[0])
			s["auth"] = a.SDK.AppCodec().MustMarshalJSON(&v)
		},
		"evm-denom": func(_ *genesis.MainnetDocument, s map[string]json.RawMessage) {
			var v evmtypes.GenesisState
			a.SDK.AppCodec().MustUnmarshalJSON(s["evm"], &v)
			v.Params.EvmDenom = "other"
			s["evm"] = a.SDK.AppCodec().MustMarshalJSON(&v)
		},
		"extended-denom": func(_ *genesis.MainnetDocument, s map[string]json.RawMessage) {
			var v evmtypes.GenesisState
			a.SDK.AppCodec().MustUnmarshalJSON(s["evm"], &v)
			if decimals == 18 {
				v.Params.ExtendedDenomOptions.ExtendedDenom = "other"
			} else {
				v.Params.ExtendedDenomOptions = nil
			}
			s["evm"] = a.SDK.AppCodec().MustMarshalJSON(&v)
		},
		"staking-denom": func(_ *genesis.MainnetDocument, s map[string]json.RawMessage) {
			var v stakingtypes.GenesisState
			a.SDK.AppCodec().MustUnmarshalJSON(s["staking"], &v)
			v.Params.BondDenom = "other"
			s["staking"] = a.SDK.AppCodec().MustMarshalJSON(&v)
		},
		"exported-staking": func(_ *genesis.MainnetDocument, s map[string]json.RawMessage) {
			var v stakingtypes.GenesisState
			a.SDK.AppCodec().MustUnmarshalJSON(s["staking"], &v)
			v.Exported = true
			s["staking"] = a.SDK.AppCodec().MustMarshalJSON(&v)
		},
		"max-validators": func(_ *genesis.MainnetDocument, s map[string]json.RawMessage) {
			var v stakingtypes.GenesisState
			a.SDK.AppCodec().MustUnmarshalJSON(s["staking"], &v)
			v.Params.MaxValidators = 1
			s["staking"] = a.SDK.AppCodec().MustMarshalJSON(&v)
		},
		"no-gentxs": func(_ *genesis.MainnetDocument, s map[string]json.RawMessage) {
			s["genutil"] = a.SDK.AppCodec().MustMarshalJSON(&genutiltypes.GenesisState{})
		},
		"duplicate-gentx": func(_ *genesis.MainnetDocument, s map[string]json.RawMessage) {
			var v genutiltypes.GenesisState
			a.SDK.AppCodec().MustUnmarshalJSON(s["genutil"], &v)
			v.GenTxs = append(v.GenTxs, v.GenTxs[0])
			s["genutil"] = a.SDK.AppCodec().MustMarshalJSON(&v)
		},
		"signature": func(_ *genesis.MainnetDocument, s map[string]json.RawMessage) {
			var v genutiltypes.GenesisState
			a.SDK.AppCodec().MustUnmarshalJSON(s["genutil"], &v)
			var tx map[string]interface{}
			_ = json.Unmarshal(v.GenTxs[0], &tx)
			tx["signatures"] = []string{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}
			v.GenTxs[0], _ = json.Marshal(tx)
			s["genutil"] = a.SDK.AppCodec().MustMarshalJSON(&v)
		},
	} {
		t.Run(name, func(t *testing.T) {
			var candidate genesis.MainnetDocument
			if err := json.Unmarshal(raw, &candidate); err != nil {
				t.Fatal(err)
			}
			var state map[string]json.RawMessage
			_ = json.Unmarshal(candidate.AppState, &state)
			mutate(&candidate, state)
			candidate.AppState, _ = json.Marshal(state)
			b, h := mainnetBytes(t, candidate)
			g, err := genesis.LoadMainnet(bytes.NewReader(b), cfg, h)
			if err == nil {
				_, err = genesis.ValidateMainnet(a, g)
			}
			if err == nil {
				t.Fatal("invalid Genesis accepted")
			}
			t.Log("expected rejection:", err)
		})
	}
	wrong := mainnetFixture(t, a, decimals, "wrong-signing-chain-2")
	b, h := mainnetBytes(t, wrong)
	g, err := genesis.LoadMainnet(bytes.NewReader(b), cfg, h)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := genesis.ValidateMainnet(a, g); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatal("wrong signing chain not rejected", err)
	}
	for name, b := range map[string][]byte{
		"duplicate-key": append(bytes.Clone(raw[:len(raw)-1]), []byte(`,"chain_id":"mainnet-fixture-2"}`)...),
		"unknown-field": append(bytes.Clone(raw[:len(raw)-1]), []byte(`,"unknown":true}`)...),
		"trailing-json": append(bytes.Clone(raw), []byte(` {}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			hash := sha256.Sum256(b)
			if _, err := genesis.LoadMainnet(bytes.NewReader(b), cfg, hex.EncodeToString(hash[:])); err == nil {
				t.Fatal("ambiguous JSON accepted")
			}
		})
	}
	var envelope map[string]json.RawMessage
	_ = json.Unmarshal(raw, &envelope)
	var consensus map[string]json.RawMessage
	_ = json.Unmarshal(envelope["consensus"], &consensus)
	consensus["unknown"] = json.RawMessage(`true`)
	envelope["consensus"], _ = json.Marshal(consensus)
	b, _ = json.Marshal(envelope)
	sum := sha256.Sum256(b)
	if _, err := genesis.LoadMainnet(bytes.NewReader(b), cfg, hex.EncodeToString(sum[:])); err == nil {
		t.Fatal("unknown consensus field accepted")
	}
	link := filepath.Join(t.TempDir(), "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := genesis.LoadMainnetFile(link, cfg, digest); err == nil {
		t.Fatal("symlink input followed")
	}
	parentLink := filepath.Join(t.TempDir(), "parent")
	if err := os.Symlink(filepath.Dir(path), parentLink); err != nil {
		t.Fatal(err)
	}
	if _, err := genesis.LoadMainnetFile(filepath.Join(parentLink, "genesis.json"), cfg, digest); err == nil {
		t.Fatal("parent symlink followed")
	}
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := genesis.ReadMainnetInputFile(fifo, 100); err == nil {
		t.Fatal("FIFO accepted")
	}
	if binary := os.Getenv("LQC_STEP2_CLI_BINARY"); binary != "" {
		configPath := filepath.Join(t.TempDir(), "runtime.json")
		if err := os.WriteFile(configPath, configRaw, 0600); err != nil {
			t.Fatal(err)
		}
		args := []string{"genesis", "validate-runtime", "--network", "mainnet", "--config", configPath, "--genesis", path, "--expected-genesis-sha256", digest}
		cmd := exec.CommandContext(t.Context(), binary, args...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("CLI failed: %v\n%s", err, output)
		}
		var cli genesis.MainnetReport
		if json.Unmarshal(output, &cli) != nil || cli.GenesisSHA256 != digest || len(cli.Validators) != 2 || cli.LaunchApproved {
			t.Fatalf("invalid CLI result: %s", output)
		}
		t.Logf("offline CLI PASS: %s", output)
		args[len(args)-1] = strings.Repeat("0", 64)
		cmd = exec.CommandContext(t.Context(), binary, args...)
		if output, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(output), "SHA-256 mismatch") {
			t.Fatal("CLI digest mismatch not rejected", err)
		}
	}
	afterFile, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(raw, afterFile) {
		t.Fatal("input file changed", err)
	}
	after := a.SDK.LastCommitID()
	if a.SDK.LastBlockHeight() != 0 || before.Version != after.Version || !bytes.Equal(before.Hash, after.Hash) {
		t.Fatal("validation committed state")
	}
	if !reflect.DeepEqual(homeBefore, mainnetHomeSnapshot(t, home)) {
		t.Fatal("Genesis validation changed scratch home contents or permissions")
	}
	data, _ := json.Marshal(report)
	t.Logf("offline multi-validator validation PASS; height=0; no InitChain/commit/node/key files; report=%s", data)
}

// The pinned upgrade keeper creates an empty data directory during application
// construction. Snapshot that baseline; the validator must add/change NOTHING.
func mainnetHomeSnapshot(t *testing.T, home string) map[string]string {
	t.Helper()
	snapshot := map[string]string{}
	err := filepath.WalkDir(home, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(home, path)
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			return fmt.Errorf("unexpected file or link in scratch home: %s", relative)
		}
		snapshot[relative] = fmt.Sprintf("%o:%d", info.Mode().Perm(), info.ModTime().UnixNano())
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}
