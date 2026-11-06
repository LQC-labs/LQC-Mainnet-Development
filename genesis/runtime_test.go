// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

package genesis

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"cosmossdk.io/log/v2"
	"github.com/LQC-labs/LQC-Mainnet-Development/app"
	abci "github.com/cometbft/cometbft/abci/types"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	dbm "github.com/cosmos/cosmos-db"
	sdk "github.com/cosmos/cosmos-sdk/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	evmtypes "github.com/cosmos/evm/x/vm/types"
)

// Each case needs a separate process: the official EVM InitGenesis configures
// process-global coin information. Do not reset/bypass that production guard.
func TestWholeAppGenesis(t *testing.T) {
	mode := os.Getenv("LQC_GENESIS_RUNTIME_CASE")
	if mode == "" {
		for _, fixture := range []string{"missing", "18", "6", "invalid"} {
			t.Run(fixture, func(t *testing.T) {
				cmd := exec.Command(os.Args[0], "-test.run=^TestWholeAppGenesis$", "-test.v")
				cmd.Env = append(os.Environ(), "LQC_GENESIS_RUNTIME_CASE="+fixture)
				output, err := cmd.CombinedOutput()
				t.Log(string(output))
				if err != nil {
					t.Fatalf("isolated app probe failed: %v", err)
				}
			})
		}
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
	raw, err := New(a)
	if err != nil {
		t.Fatal(err)
	}
	var doc Document
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var state map[string]json.RawMessage
	if err := json.Unmarshal(doc.AppState, &state); err != nil {
		t.Fatal(err)
	}
	if mode == "missing" {
		var bank banktypes.GenesisState
		a.SDK.AppCodec().MustUnmarshalJSON(state[banktypes.ModuleName], &bank)
		bank.DenomMetadata = nil
		state[banktypes.ModuleName] = a.SDK.AppCodec().MustMarshalJSON(&bank)
	}
	if mode != "missing" {
		exponent := uint32(18)
		if mode == "6" {
			exponent = 6
		}
		metadata := banktypes.Metadata{
			Description: "ISOLATED GENESIS CANDIDATE, NOT ADOPTED", Base: "atest", Display: "test", Name: "Test fixture", Symbol: "TEST",
			DenomUnits: []*banktypes.DenomUnit{{Denom: "atest", Exponent: 0}, {Denom: "test", Exponent: exponent}},
		}
		if mode == "invalid" {
			metadata.DenomUnits[0].Exponent = 1
		}
		var bank banktypes.GenesisState
		a.SDK.AppCodec().MustUnmarshalJSON(state[banktypes.ModuleName], &bank)
		bank.DenomMetadata = []banktypes.Metadata{metadata}
		state[banktypes.ModuleName] = a.SDK.AppCodec().MustMarshalJSON(&bank)
		if mode == "6" {
			var evm evmtypes.GenesisState
			a.SDK.AppCodec().MustUnmarshalJSON(state[evmtypes.ModuleName], &evm)
			evm.Params.ExtendedDenomOptions = &evmtypes.ExtendedDenomOptions{ExtendedDenom: "aexttest"}
			state[evmtypes.ModuleName] = a.SDK.AppCodec().MustMarshalJSON(&evm)
		}
	}
	err = a.SDK.BasicModuleManager.ValidateGenesis(a.SDK.AppCodec(), a.SDK.GetTxConfig(), state)
	if mode == "invalid" {
		if err == nil || !strings.Contains(err.Error(), "exponent") {
			t.Fatalf("invalid base exponent accepted: %v", err)
		}
		t.Logf("invalid metadata rejected BEFORE module initialization: %v", err)
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	stateBytes, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	ctx := sdk.NewContext(a.SDK.CommitMultiStore().CacheMultiStore(), cmtproto.Header{ChainID: doc.ChainID, Time: doc.GenesisTime}, false, log.NewLogger(&logs, log.OutputJSONOption())).WithConsensusParams(doc.Consensus.Params.ToProto())
	var response *abci.ResponseInitChain
	var panicValue interface{}
	func() {
		defer func() { panicValue = recover() }()
		response, err = a.SDK.InitChainer(ctx, &abci.RequestInitChain{ChainId: doc.ChainID, Time: doc.GenesisTime, InitialHeight: doc.InitialHeight, AppStateBytes: stateBytes})
	}()
	t.Logf("module initialization log:\n%s", logs.String())
	if mode == "missing" {
		if panicValue == nil || !strings.Contains(fmt.Sprint(panicValue), "denom metadata atest could not be found") {
			t.Fatalf("wrong missing-metadata failure: panic=%v error=%v", panicValue, err)
		}
		t.Logf("expected metadata failure at EVM InitGenesis: %v", panicValue)
		return
	}
	if panicValue != nil {
		t.Fatalf("unexpected initialization panic: %v", panicValue)
	}
	// This is a failure of complete app initialization, not a successful node.
	// Reaching the official final guard proves the module loop was completed.
	if err == nil || !strings.HasPrefix(err.Error(), "validator set is empty after InitGenesis") {
		t.Fatalf("expected unchanged no-validator guard; got %v", err)
	}
	if response == nil || len(response.Validators) != 0 {
		t.Fatal("unexpected validator updates")
	}
	var observed []string
	for _, line := range strings.Split(logs.String(), "\n") {
		var event map[string]interface{}
		if json.Unmarshal([]byte(line), &event) == nil && event["message"] == "running initialization for module" {
			observed = append(observed, fmt.Sprint(event["module"]))
		}
	}
	var expected []string
	for _, name := range a.SDK.ModuleManager.OrderInitGenesis {
		if state[name] != nil {
			expected = append(expected, name)
		}
	}
	if strings.Join(observed, ",") != strings.Join(expected, ",") {
		t.Fatalf("initialization order mismatch: got %v want %v", observed, expected)
	}
	info := a.SDK.EVMKeeper.GetEvmCoinInfo(ctx)
	wantDecimals := uint32(18)
	wantExtended := "atest"
	if mode == "6" {
		wantDecimals, wantExtended = 6, "aexttest"
	}
	if info.Decimals != wantDecimals || info.Denom != "atest" || info.ExtendedDenom != wantExtended {
		t.Fatalf("unexpected initialized coin info: %+v", info)
	}
	if !a.SDK.BankKeeper.GetSupply(ctx, "atest").IsZero() {
		t.Fatal("candidate must not mint initial test assets")
	}
	address := sdk.AccAddress(bytes.Repeat([]byte{0x11}, 20))
	encoded := address.String()
	decoded, decodeErr := sdk.AccAddressFromBech32(encoded)
	if decodeErr != nil || !strings.HasPrefix(encoded, "lqctest1") || !bytes.Equal(decoded, address) || hex.EncodeToString(decoded) != strings.Repeat("11", 20) {
		t.Fatalf("Bech32/EVM address byte mapping failed: %v", decodeErr)
	}
	if doc.ChainID != "lqc-devnet-test-1" || evmtypes.GetEthChainConfig().ChainID.Uint64() != 917001 {
		t.Fatal("chain identity changed during Genesis")
	}
	if evmtypes.Decimals(info.Decimals).ConversionFactor().String() != map[string]string{"18": "1", "6": "1000000000000"}[mode] {
		t.Fatal("unexpected native/EVM precision conversion")
	}
	if a.SDK.LastBlockHeight() != 0 {
		t.Fatal("must not produce blocks")
	}
	t.Logf("candidate %s: %d module initializers visited in official order; coin info %+v; APP INIT FAIL (expected): %v; cache NOT committed", mode, len(observed), info, err)
}
