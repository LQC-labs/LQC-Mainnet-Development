// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

package genesis

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cosmossdk.io/log/v2"
	"github.com/LQC-labs/LQC-Mainnet-Development/app"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	dbm "github.com/cosmos/cosmos-db"
	sdk "github.com/cosmos/cosmos-sdk/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	evmtypes "github.com/cosmos/evm/x/vm/types"
)

func TestGenesisDraft(t *testing.T) {
	if runGenesisTestInSubprocess(t) {
		return
	}
	a, err := app.New(log.NewNopLogger(), dbm.NewMemDB(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := a.Close(); err != nil {
			t.Error(err)
		}
	})
	good, err := New(a)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(a, good); err != nil {
		t.Fatal(err)
	}
	mutate := func(fn func(map[string]interface{})) []byte {
		var doc map[string]interface{}
		if err := json.Unmarshal(good, &doc); err != nil {
			t.Fatal(err)
		}
		fn(doc)
		b, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	cases := map[string][]byte{
		"malformed":         []byte("{"),
		"null":              []byte("null"),
		"trailing":          append(append([]byte{}, good...), []byte("{}")...),
		"chain":             mutate(func(d map[string]interface{}) { d["chain_id"] = "wrong" }),
		"missing consensus": mutate(func(d map[string]interface{}) { d["consensus"] = nil }),
		"evm chain": mutate(func(d map[string]interface{}) {
			d["lqc_profile"].(map[string]interface{})["Chain"].(map[string]interface{})["EVMChainID"] = 1
		}),
		"prefix": mutate(func(d map[string]interface{}) {
			d["lqc_profile"].(map[string]interface{})["Chain"].(map[string]interface{})["Bech32Prefix"] = "cosmos"
		}),
		"minimum gas": mutate(func(d map[string]interface{}) {
			d["lqc_profile"].(map[string]interface{})["MinimumGasPrice"] = "1atest"
		}),
		"profile denom": mutate(func(d map[string]interface{}) {
			d["lqc_profile"].(map[string]interface{})["Chain"].(map[string]interface{})["NativeDenom"] = "other"
		}),
		"missing module": mutate(func(d map[string]interface{}) { delete(d["app_state"].(map[string]interface{}), "evm") }),
		"unknown module": mutate(func(d map[string]interface{}) {
			d["app_state"].(map[string]interface{})["unexpected"] = map[string]interface{}{}
		}),
		"null module": mutate(func(d map[string]interface{}) { d["app_state"].(map[string]interface{})["evm"] = nil }),
		"evm denom": mutate(func(d map[string]interface{}) {
			d["app_state"].(map[string]interface{})["evm"].(map[string]interface{})["params"].(map[string]interface{})["evm_denom"] = "stake"
		}),
		"mint denom": mutate(func(d map[string]interface{}) {
			d["app_state"].(map[string]interface{})["mint"].(map[string]interface{})["params"].(map[string]interface{})["mint_denom"] = "stake"
		}),
		"invalid staking params": mutate(func(d map[string]interface{}) {
			d["app_state"].(map[string]interface{})["staking"].(map[string]interface{})["params"].(map[string]interface{})["max_validators"] = 0
		}),
		"unknown field":   mutate(func(d map[string]interface{}) { d["production"] = true }),
		"missing profile": mutate(func(d map[string]interface{}) { delete(d, "lqc_profile") }),
		"funded account": mutate(func(d map[string]interface{}) {
			d["app_state"].(map[string]interface{})["bank"].(map[string]interface{})["balances"] = []interface{}{map[string]interface{}{"address": "lqctest-invalid", "coins": []interface{}{map[string]interface{}{"denom": "atest", "amount": "1"}}}}
		}),
		"wrong decimal metadata": mutate(func(d map[string]interface{}) {
			d["app_state"].(map[string]interface{})["bank"].(map[string]interface{})["denom_metadata"] = []interface{}{map[string]interface{}{"base": "atest", "display": "test", "name": "test", "symbol": "TEST", "denom_units": []interface{}{map[string]interface{}{"denom": "atest", "exponent": 0}, map[string]interface{}{"denom": "test", "exponent": 18}}}}
		}),
		"missing metadata": mutate(func(d map[string]interface{}) {
			d["app_state"].(map[string]interface{})["bank"].(map[string]interface{})["denom_metadata"] = []interface{}{}
		}),
		"wrong precision": mutate(func(d map[string]interface{}) {
			d["app_state"].(map[string]interface{})["bank"].(map[string]interface{})["denom_metadata"].([]interface{})[0].(map[string]interface{})["denom_units"].([]interface{})[1].(map[string]interface{})["exponent"] = 6
		}),
		"wrong metadata base": mutate(func(d map[string]interface{}) {
			d["app_state"].(map[string]interface{})["bank"].(map[string]interface{})["denom_metadata"].([]interface{})[0].(map[string]interface{})["base"] = "other"
		}),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if err := Validate(a, data); err == nil {
				t.Fatal("invalid genesis accepted")
			}
		})
	}
	home := t.TempDir()
	path, err := Init(a, home)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(a, before); err != nil {
		t.Fatal(err)
	}
	if _, err := Init(a, home); err == nil {
		t.Fatal("existing genesis overwritten")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("existing genesis changed")
	}
	for _, rel := range []string{"config/priv_validator_key.json", "config/node_key.json", "config/config.toml", "config/app.toml"} {
		if _, err := os.Stat(filepath.Join(home, rel)); !os.IsNotExist(err) {
			t.Fatalf("unexpected node artifact %s", rel)
		}
	}
	// A malformed pre-existing file must also remain byte-identical.
	invalidHome := t.TempDir()
	if err := os.Mkdir(filepath.Join(invalidHome, "config"), 0700); err != nil {
		t.Fatal(err)
	}
	invalidPath := filepath.Join(invalidHome, "config", "genesis.json")
	if err := os.WriteFile(invalidPath, []byte("do not overwrite"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Init(a, invalidHome); err == nil {
		t.Fatal("invalid existing file overwritten")
	}
	unchanged, _ := os.ReadFile(invalidPath)
	if string(unchanged) != "do not overwrite" {
		t.Fatal("invalid file changed")
	}
	t.Run("isolated EVM metadata compatibility probe", func(t *testing.T) {
		// This cache is never written back: no InitChain, Commit, validator or
		// blocks. Candidate metadata is a fixture, not an adopted token profile.
		ctx := sdk.NewContext(a.SDK.CommitMultiStore().CacheMultiStore(), cmtproto.Header{}, false, log.NewNopLogger())
		params := evmtypes.DefaultParams()
		params.EvmDenom = "atest"
		params.ExtendedDenomOptions = &evmtypes.ExtendedDenomOptions{ExtendedDenom: "atest"}
		if err := a.SDK.EVMKeeper.SetParams(ctx, params); err != nil {
			t.Fatal(err)
		}
		if _, err := a.SDK.EVMKeeper.LoadEvmCoinInfo(ctx); err == nil || !strings.Contains(err.Error(), "denom metadata atest could not be found") {
			t.Fatalf("expected missing metadata blocker, got %v", err)
		}
		candidate := banktypes.Metadata{
			Description: "ISOLATED TEST FIXTURE ONLY", Base: "atest", Display: "test", Name: "Test fixture", Symbol: "TEST",
			DenomUnits: []*banktypes.DenomUnit{{Denom: "atest", Exponent: 0}, {Denom: "test", Exponent: 18}},
		}
		if err := candidate.Validate(); err != nil {
			t.Fatal(err)
		}
		a.SDK.BankKeeper.SetDenomMetaData(ctx, candidate)
		if err := a.SDK.EVMKeeper.InitEvmCoinInfo(ctx); err != nil {
			t.Fatal(err)
		}
		info := a.SDK.EVMKeeper.GetEvmCoinInfo(ctx)
		if info.Denom != "atest" || info.ExtendedDenom != "atest" || info.Decimals != 18 || info.DisplayDenom != "test" {
			t.Fatalf("unexpected coin info: %+v", info)
		}
		if evmtypes.EighteenDecimals.ConversionFactor().String() != "1" {
			t.Fatal("18-decimal conversion must be 1:1")
		}
		// Ensure no candidate metadata was inserted into the generated document.
		if err := Validate(a, good); err != nil {
			t.Fatal(err)
		}
	})
}
