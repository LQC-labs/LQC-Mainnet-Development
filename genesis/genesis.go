// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

// Package genesis creates and validates an unfunded, validator-free Devnet draft.
// It never calls InitChain or creates signing keys.
package genesis

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/LQC-labs/LQC-Mainnet-Development/app"
	chainconfig "github.com/LQC-labs/LQC-Mainnet-Development/chain/config"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	genutiltypes "github.com/cosmos/cosmos-sdk/x/genutil/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	erc20types "github.com/cosmos/evm/x/erc20/types"
	evmtypes "github.com/cosmos/evm/x/vm/types"
)

// Document embeds the official SDK AppGenesis unchanged. The additional profile
// records settings that are NOT native fields in the upstream EVM genesis schema.
// A node launcher must consume and enforce this profile in a later stage.
type Document struct {
	genutiltypes.AppGenesis
	Profile chainconfig.DevnetConfig `json:"lqc_profile"`
}

// New uses registered module defaults, deliberately excluding evmd's example
// token pairs, funded accounts and preinstalls. Native test units use 18 decimals.
func New(a *app.App) ([]byte, error) {
	state := a.SDK.BasicModuleManager.DefaultGenesis(a.SDK.AppCodec())
	// The SDK defaults use stake in staking, mint and governance. Replace only
	// exact default denomination strings in newly generated module defaults.
	for name, raw := range state {
		// Some SDK modules (e.g. consensus) have no module-level genesis.
		if len(raw) == 0 {
			delete(state, name)
			continue
		}
		var value interface{}
		if err := json.Unmarshal(raw, &value); err != nil {
			return nil, fmt.Errorf("default genesis module %s: %w", name, err)
		}
		updated, err := json.Marshal(replaceDenom(value, sdk.DefaultBondDenom, a.Profile.Chain.NativeDenom))
		if err != nil {
			return nil, err
		}
		state[name] = updated
	}
	evm := evmtypes.DefaultGenesisState()
	evm.Params.EvmDenom = a.Profile.Chain.NativeDenom
	evm.Params.ExtendedDenomOptions = &evmtypes.ExtendedDenomOptions{ExtendedDenom: a.Profile.Chain.NativeDenom}
	state[evmtypes.ModuleName] = a.SDK.AppCodec().MustMarshalJSON(evm)
	var bank banktypes.GenesisState
	if err := a.SDK.AppCodec().UnmarshalJSON(state[banktypes.ModuleName], &bank); err != nil {
		return nil, err
	}
	bank.DenomMetadata = []banktypes.Metadata{nativeMetadata()}
	state[banktypes.ModuleName] = a.SDK.AppCodec().MustMarshalJSON(&bank)
	raw, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	g := genutiltypes.NewAppGenesisWithVersion(a.Profile.Chain.CosmosChainID, raw)
	g.AppName, g.AppVersion = app.Name, app.Version
	g.GenesisTime = time.Now().UTC()
	if err := g.ValidateAndComplete(); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(Document{AppGenesis: *g, Profile: a.Profile}, "", "  ")
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')
	return data, Validate(a, data)
}

func replaceDenom(v interface{}, old, denom string) interface{} {
	switch x := v.(type) {
	case string:
		if x == old {
			return denom
		}
	case []interface{}:
		for i := range x {
			x[i] = replaceDenom(x[i], old, denom)
		}
	case map[string]interface{}:
		for k := range x {
			x[k] = replaceDenom(x[k], old, denom)
		}
	}
	return v
}

// Validate is read-only: completion operates on a decoded copy, never the file.
// This stage accepts only unfunded drafts; allocation/validator tooling is absent.
func Validate(a *app.App, data []byte) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("invalid genesis: %v", p)
		}
	}()
	var doc Document
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return err
	}
	if err := dec.Decode(new(interface{})); err != io.EOF {
		return fmt.Errorf("unexpected trailing genesis data")
	}
	if err := doc.Profile.Validate(); err != nil {
		return err
	}
	if doc.ChainID != doc.Profile.Chain.CosmosChainID || doc.AppName != app.Name || doc.AppVersion != app.Version {
		return fmt.Errorf("genesis application identity or chain ID mismatch")
	}
	if doc.Consensus == nil || len(doc.Consensus.Validators) != 0 || len(doc.AppHash) != 0 || doc.InitialHeight != 1 || doc.GenesisTime.IsZero() {
		return fmt.Errorf("expected an unstarted, validator-free genesis draft")
	}
	if err := doc.ValidateAndComplete(); err != nil {
		return err
	}
	if sdk.GetConfig().GetBech32AccountAddrPrefix() != doc.Profile.Chain.Bech32Prefix || evmtypes.GetEthChainConfig() == nil || evmtypes.GetEthChainConfig().ChainID.Uint64() != doc.Profile.Chain.EVMChainID {
		return fmt.Errorf("runtime profile mismatch")
	}
	var state map[string]json.RawMessage
	if err := json.Unmarshal(doc.AppState, &state); err != nil {
		return err
	}
	expected := a.SDK.BasicModuleManager.DefaultGenesis(a.SDK.AppCodec())
	for name, raw := range expected {
		if len(raw) == 0 {
			delete(expected, name)
		}
	}
	if len(state) != len(expected) {
		return fmt.Errorf("unexpected or missing genesis modules")
	}
	for name := range expected {
		if len(state[name]) == 0 || bytes.Equal(bytes.TrimSpace(state[name]), []byte("null")) {
			return fmt.Errorf("missing module %s", name)
		}
	}
	if err := a.SDK.BasicModuleManager.ValidateGenesis(a.SDK.AppCodec(), a.SDK.GetTxConfig(), state); err != nil {
		return fmt.Errorf("module genesis: %w", err)
	}
	var evm evmtypes.GenesisState
	if err := a.SDK.AppCodec().UnmarshalJSON(state[evmtypes.ModuleName], &evm); err != nil {
		return err
	}
	denom := doc.Profile.Chain.NativeDenom
	if evm.Params.EvmDenom != denom || evm.Params.ExtendedDenomOptions == nil || evm.Params.ExtendedDenomOptions.ExtendedDenom != denom || len(evm.Accounts) != 0 || len(evm.Preinstalls) != 0 {
		return fmt.Errorf("invalid EVM denomination or nonempty EVM allocations")
	}
	var bank banktypes.GenesisState
	if err := a.SDK.AppCodec().UnmarshalJSON(state[banktypes.ModuleName], &bank); err != nil {
		return err
	}
	if len(bank.Balances) != 0 || len(bank.Supply) != 0 {
		return fmt.Errorf("funding is outside this unfunded draft")
	}
	if len(bank.DenomMetadata) != 1 {
		return fmt.Errorf("exactly one native test token metadata entry is required")
	}
	metadata := bank.DenomMetadata[0]
	expectedMetadata := nativeMetadata()
	if err := metadata.Validate(); err != nil {
		return err
	}
	if metadata.Base != denom || metadata.Display != expectedMetadata.Display || metadata.Name != expectedMetadata.Name || metadata.Symbol != expectedMetadata.Symbol || len(metadata.DenomUnits) != 2 {
		return fmt.Errorf("native token metadata does not match the fixed test profile")
	}
	for i, unit := range metadata.DenomUnits {
		if unit == nil || unit.Denom != expectedMetadata.DenomUnits[i].Denom || unit.Exponent != expectedMetadata.DenomUnits[i].Exponent || len(unit.Aliases) != 0 {
			return fmt.Errorf("native test token requires atest exponent 0 and test exponent 18")
		}
	}
	var auth authtypes.GenesisState
	if err := a.SDK.AppCodec().UnmarshalJSON(state[authtypes.ModuleName], &auth); err != nil {
		return err
	}
	if len(auth.Accounts) != 0 {
		return fmt.Errorf("initial accounts are not enabled")
	}
	var staking stakingtypes.GenesisState
	if err := a.SDK.AppCodec().UnmarshalJSON(state[stakingtypes.ModuleName], &staking); err != nil {
		return err
	}
	if staking.Params.BondDenom != denom || len(staking.Validators) != 0 || len(staking.Delegations) != 0 || len(staking.UnbondingDelegations) != 0 || len(staking.Redelegations) != 0 || len(staking.LastValidatorPowers) != 0 || !staking.LastTotalPower.IsZero() || staking.Exported {
		return fmt.Errorf("invalid staking draft")
	}
	var erc20 erc20types.GenesisState
	if err := a.SDK.AppCodec().UnmarshalJSON(state[erc20types.ModuleName], &erc20); err != nil {
		return err
	}
	if len(erc20.TokenPairs) != 0 || len(erc20.Allowances) != 0 || len(erc20.NativePrecompiles) != 0 || len(erc20.DynamicPrecompiles) != 0 {
		return fmt.Errorf("example tokens and allowances are not enabled")
	}
	// Check all SDK coin/denom fields, including mint and both governance deposits.
	var generic interface{}
	if err := json.Unmarshal(doc.AppState, &generic); err != nil {
		return err
	}
	// Metadata units have already been checked against the exact profile above.
	// Their display denomination "test" is not an SDK coin base denomination.
	if root, ok := generic.(map[string]interface{}); ok {
		if bankState, ok := root[banktypes.ModuleName].(map[string]interface{}); ok {
			delete(bankState, "denom_metadata")
		}
	}
	if err := checkDenoms(generic, denom); err != nil {
		return err
	}
	var gentxs genutiltypes.GenesisState
	if err := a.SDK.AppCodec().UnmarshalJSON(state[genutiltypes.ModuleName], &gentxs); err != nil {
		return err
	}
	if len(gentxs.GenTxs) != 0 {
		return fmt.Errorf("validator transactions are outside this stage")
	}
	return nil
}

func nativeMetadata() banktypes.Metadata {
	return banktypes.Metadata{
		Description: "LQC isolated test Devnet native token", Base: "atest", Display: "test", Name: "LQC Devnet Test", Symbol: "TEST",
		DenomUnits: []*banktypes.DenomUnit{{Denom: "atest", Exponent: 0}, {Denom: "test", Exponent: 18}},
	}
}

func checkDenoms(v interface{}, denom string) error {
	switch x := v.(type) {
	case map[string]interface{}:
		for k, child := range x {
			if k == "denom" || k == "mint_denom" || k == "bond_denom" || k == "evm_denom" || k == "extended_denom" {
				if child != denom {
					return fmt.Errorf("%s must be %s", k, denom)
				}
			}
			if err := checkDenoms(child, denom); err != nil {
				return err
			}
		}
	case []interface{}:
		for _, child := range x {
			if err := checkDenoms(child, denom); err != nil {
				return err
			}
		}
	}
	return nil
}

// Init exclusively creates genesis.json; existing files (including symlinks)
// are never followed or overwritten. No config, keyring or validator key is made.
func Init(a *app.App, home string) (string, error) {
	data, err := New(a)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, "config")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "genesis.json")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if writeErr != nil {
		return "", writeErr
	}
	return path, closeErr
}
