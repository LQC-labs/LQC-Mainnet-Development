// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

package genesis

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	"cosmossdk.io/log/v2"
	"github.com/LQC-labs/LQC-Mainnet-Development/app"
	abci "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/crypto/ed25519"
	cmttypes "github.com/cometbft/cometbft/types"
	dbm "github.com/cosmos/cosmos-db"
	simtestutil "github.com/cosmos/cosmos-sdk/testutil/sims"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	evmtypes "github.com/cosmos/evm/x/vm/types"
)

// Public information only. Never creates a signer, a node, a block or a commit.
// Independent processes respect the EVM's one-time global initialization guards.
func TestGenesisWithInitialValidator(t *testing.T) {
	mode := os.Getenv("LQC_INITIAL_VALIDATOR_CASE")
	if mode == "" {
		for _, candidate := range []string{"18", "6", "below-power", "mismatched-update"} {
			t.Run(candidate, func(t *testing.T) {
				cmd := exec.Command(os.Args[0], "-test.run=^TestGenesisWithInitialValidator$", "-test.v")
				cmd.Env = append(os.Environ(), "LQC_INITIAL_VALIDATOR_CASE="+candidate)
				output, err := cmd.CombinedOutput()
				t.Log(string(output))
				if err != nil {
					t.Fatalf("initial validator probe: %v", err)
				}
			})
		}
		return
	}
	home := t.TempDir()
	a, err := app.New(log.NewNopLogger(), dbm.NewMemDB(), home)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := a.Close(); err != nil {
			t.Error(err)
		}
	})
	initialCommit := a.SDK.LastCommitID()
	generatedPath := os.Getenv("LQC_GENERATED_GENESIS_FILE")
	if generatedPath == "" || mode != "18" {
		generatedPath, err = Init(a, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
	}
	original, err := os.ReadFile(generatedPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(a, original); err != nil {
		t.Fatal(err)
	}
	var doc Document
	if err := json.Unmarshal(original, &doc); err != nil {
		t.Fatal(err)
	}
	var state map[string]json.RawMessage
	if err := json.Unmarshal(doc.AppState, &state); err != nil {
		t.Fatal(err)
	}
	var generatedBank banktypes.GenesisState
	a.SDK.AppCodec().MustUnmarshalJSON(state[banktypes.ModuleName], &generatedBank)
	// Fixed public test vector. No corresponding private key is loaded/generated.
	publicBytes, err := hex.DecodeString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	if err != nil {
		t.Fatal(err)
	}
	pub := ed25519.PubKey(publicBytes)
	valSet := cmttypes.NewValidatorSet([]*cmttypes.Validator{cmttypes.NewValidator(pub, 1)})
	account := authtypes.NewBaseAccountWithAddress(sdk.AccAddress(bytes.Repeat([]byte{0x22}, 20)))
	// The official SDK helper is also used by the pinned evmd test helpers.
	state, err = simtestutil.GenesisStateWithValSet(a.SDK.AppCodec(), state, valSet, []authtypes.GenesisAccount{account})
	if err != nil {
		t.Fatal(err)
	}
	var staking stakingtypes.GenesisState
	a.SDK.AppCodec().MustUnmarshalJSON(state[stakingtypes.ModuleName], &staking)
	staking.Params.BondDenom = "atest"
	bond := sdk.DefaultPowerReduction
	if mode == "below-power" {
		bond = bond.SubRaw(1)
		staking.Validators[0].Tokens = bond
	}
	state[stakingtypes.ModuleName] = a.SDK.AppCodec().MustMarshalJSON(&staking)
	var bank banktypes.GenesisState
	a.SDK.AppCodec().MustUnmarshalJSON(state[banktypes.ModuleName], &bank)
	bank.Supply = sdk.NewCoins(sdk.NewCoin("atest", bond))
	bank.Balances = []banktypes.Balance{{Address: authtypes.NewModuleAddress(stakingtypes.BondedPoolName).String(), Coins: sdk.NewCoins(sdk.NewCoin("atest", bond))}}
	exponent := uint32(18)
	if mode == "6" {
		exponent = 6
	}
	bank.DenomMetadata = generatedBank.DenomMetadata
	if mode == "6" {
		bank.DenomMetadata = []banktypes.Metadata{{Base: "atest", Display: "test", Name: "Isolated test fixture", Symbol: "TEST", DenomUnits: []*banktypes.DenomUnit{{Denom: "atest", Exponent: 0}, {Denom: "test", Exponent: exponent}}}}
	}
	state[banktypes.ModuleName] = a.SDK.AppCodec().MustMarshalJSON(&bank)
	if mode == "6" {
		var evm evmtypes.GenesisState
		a.SDK.AppCodec().MustUnmarshalJSON(state[evmtypes.ModuleName], &evm)
		evm.Params.ExtendedDenomOptions = &evmtypes.ExtendedDenomOptions{ExtendedDenom: "aexttest"}
		state[evmtypes.ModuleName] = a.SDK.AppCodec().MustMarshalJSON(&evm)
	}
	if err := a.SDK.BasicModuleManager.ValidateGenesis(a.SDK.AppCodec(), a.SDK.GetTxConfig(), state); err != nil {
		t.Fatal(err)
	}
	appState, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	params := doc.Consensus.Params.ToProto()
	updates := cmttypes.TM2PB.ValidatorUpdates(valSet)
	if mode == "mismatched-update" {
		updates[0].Power = 2
	}
	response, initErr := a.SDK.InitChain(&abci.RequestInitChain{ChainId: doc.ChainID, Time: doc.GenesisTime, InitialHeight: doc.InitialHeight, ConsensusParams: &params, Validators: updates, AppStateBytes: appState})
	if mode == "below-power" {
		if initErr == nil || !strings.Contains(initErr.Error(), "validator set is empty after InitGenesis") {
			t.Fatalf("expected official empty validator guard, got %v", initErr)
		}
		t.Logf("below-power candidate correctly rejected: %v", initErr)
		return
	}
	if mode == "mismatched-update" {
		if initErr == nil || !strings.Contains(initErr.Error(), "!= req.Validators") {
			t.Fatalf("expected official validator equality guard, got %v", initErr)
		}
		t.Logf("mismatched request update correctly rejected: %v", initErr)
		return
	}
	if initErr != nil {
		t.Fatal(initErr)
	}
	if response == nil || len(response.Validators) != 1 || response.Validators[0].Power != 1 || !bytes.Equal(response.Validators[0].PubKey.GetEd25519(), publicBytes) {
		t.Fatalf("incorrect initialized validator response: %+v", response)
	}
	ctx := a.SDK.NewContext(false)
	info := a.SDK.EVMKeeper.GetEvmCoinInfo(ctx)
	if info.Decimals != exponent || info.Denom != "atest" {
		t.Fatalf("wrong initialized coin info: %+v", info)
	}
	if !a.SDK.BankKeeper.GetSupply(ctx, "atest").Amount.Equal(bond) {
		t.Fatal("test-only bonded supply mismatch")
	}
	finalCommit := a.SDK.LastCommitID()
	if a.SDK.LastBlockHeight() != 0 || finalCommit.Version != initialCommit.Version || !bytes.Equal(finalCommit.Hash, initialCommit.Hash) {
		t.Fatalf("commit state changed: before=%+v after=%+v height=%d", initialCommit, finalCommit, a.SDK.LastBlockHeight())
	}
	// The generated CLI draft remains unaltered; candidate allocation is memory-only.
	if err := Validate(a, original); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(generatedPath)
	if err != nil || !bytes.Equal(original, after) {
		t.Fatal("generated input Genesis changed")
	}
	for _, path := range []string{"config/priv_validator_key.json", "config/node_key.json", "config/genesis.json"} {
		if _, err := os.Stat(home + "/" + path); !os.IsNotExist(err) {
			t.Fatalf("unexpected persisted artifact %s", path)
		}
	}
	t.Logf("BaseApp.InitChain SUCCESS: decimals=%d, validator updates=1, power=1, bonded base units=%s, staking power reduction=%s, display units per power=%s, height=0, no commit/signing/network", exponent, bond.String(), a.SDK.StakingKeeper.PowerReduction(ctx).String(), sdk.NewDecCoinFromCoin(sdk.NewCoin("atest", bond)).Amount.QuoInt64(int64Pow10(exponent)).String())
}

func int64Pow10(exponent uint32) int64 {
	var n int64 = 1
	for range exponent {
		n *= 10
	}
	return n
}
