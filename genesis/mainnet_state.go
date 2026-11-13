// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

package genesis

import (
	"encoding/json"
	"fmt"

	"github.com/LQC-labs/LQC-Mainnet-Development/app"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	genutiltypes "github.com/cosmos/cosmos-sdk/x/genutil/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	erc20types "github.com/cosmos/evm/x/erc20/types"
	evmtypes "github.com/cosmos/evm/x/vm/types"
)

func validateMainnetState(a *app.App, doc *MainnetDocument, state map[string]json.RawMessage, digest string) (*MainnetReport, error) {
	cdc := a.SDK.AppCodec()
	var auth authtypes.GenesisState
	var bank banktypes.GenesisState
	var staking stakingtypes.GenesisState
	var gen genutiltypes.GenesisState
	var evm evmtypes.GenesisState
	var erc20 erc20types.GenesisState
	for _, entry := range []struct {
		name   string
		decode func([]byte) error
	}{
		{authtypes.ModuleName, func(b []byte) error { return cdc.UnmarshalJSON(b, &auth) }},
		{banktypes.ModuleName, func(b []byte) error { return cdc.UnmarshalJSON(b, &bank) }},
		{stakingtypes.ModuleName, func(b []byte) error { return cdc.UnmarshalJSON(b, &staking) }},
		{genutiltypes.ModuleName, func(b []byte) error { return cdc.UnmarshalJSON(b, &gen) }},
		{evmtypes.ModuleName, func(b []byte) error { return cdc.UnmarshalJSON(b, &evm) }},
		{erc20types.ModuleName, func(b []byte) error { return cdc.UnmarshalJSON(b, &erc20) }},
	} {
		if err := entry.decode(state[entry.name]); err != nil {
			return nil, err
		}
	}
	denom := doc.Profile.Chain.NativeDenom
	if len(bank.DenomMetadata) != 1 || bank.DenomMetadata[0].Base != denom {
		return nil, fmt.Errorf("exactly one matching native token metadata required")
	}
	meta := bank.DenomMetadata[0]
	var decimals uint32
	for _, unit := range meta.DenomUnits {
		if unit != nil && unit.Denom == meta.Display {
			decimals = unit.Exponent
		}
	}
	if err := evmtypes.Decimals(decimals).Validate(); err != nil {
		return nil, err
	}
	if evm.Params.EvmDenom != denom || len(evm.Accounts) != 0 || len(evm.Preinstalls) != 0 {
		return nil, fmt.Errorf("native EVM denomination required; EVM allocations/preinstalls unsupported")
	}
	if decimals == 18 {
		if evm.Params.ExtendedDenomOptions != nil && evm.Params.ExtendedDenomOptions.ExtendedDenom != denom {
			return nil, fmt.Errorf("18-decimal EVM extended denomination mismatch")
		}
	} else if evm.Params.ExtendedDenomOptions == nil || evm.Params.ExtendedDenomOptions.ExtendedDenom == denom || sdk.ValidateDenom(evm.Params.ExtendedDenomOptions.ExtendedDenom) != nil {
		return nil, fmt.Errorf("explicit distinct extended EVM denomination required")
	}
	if len(erc20.TokenPairs) != 0 || len(erc20.Allowances) != 0 || len(erc20.NativePrecompiles) != 0 || len(erc20.DynamicPrecompiles) != 0 {
		return nil, fmt.Errorf("preconfigured ERC20 assets/precompiles unsupported")
	}
	// Only new-chain signed gentxs are supported here. Exported/prebonded state
	// needs a separately reviewed validation path, not relaxed checks.
	if staking.Params.BondDenom != denom || staking.Exported || len(staking.Validators) != 0 || len(staking.Delegations) != 0 || len(staking.UnbondingDelegations) != 0 || len(staking.Redelegations) != 0 || len(staking.LastValidatorPowers) != 0 || (!staking.LastTotalPower.IsNil() && !staking.LastTotalPower.IsZero()) {
		return nil, fmt.Errorf("new-chain empty staking state required")
	}
	accounts, err := authtypes.UnpackAccounts(auth.Accounts)
	if err != nil {
		return nil, err
	}
	byAddress := map[string]*authtypes.BaseAccount{}
	for _, account := range accounts {
		base, ok := account.(*authtypes.BaseAccount)
		if !ok || base.GetAccountNumber() != 0 || base.GetSequence() != 0 {
			return nil, fmt.Errorf("initial zero-sequence base accounts required; module/vesting accounts unsupported")
		}
		address := base.GetAddress().String()
		if byAddress[address] != nil {
			return nil, fmt.Errorf("duplicate initial account")
		}
		byAddress[address] = base
	}
	balances := map[string]sdk.Coins{}
	total := sdk.Coins{}
	for _, balance := range bank.Balances {
		address, err := sdk.AccAddressFromBech32(balance.Address)
		if err != nil || address.String() != balance.Address || byAddress[balance.Address] == nil || balances[balance.Address] != nil || !balance.Coins.IsValid() || len(balance.Coins) != 1 || balance.Coins[0].Denom != denom || !balance.Coins.IsAllPositive() {
			return nil, fmt.Errorf("invalid, duplicate or unowned native balance")
		}
		balances[balance.Address] = balance.Coins
		total = total.Add(balance.Coins...)
	}
	if len(bank.Supply) != 1 || !bank.Supply.IsValid() || !bank.Supply.IsAllPositive() || bank.Supply[0].Denom != denom || !bank.Supply.Equal(total) {
		return nil, fmt.Errorf("explicit native total supply must equal all balances")
	}
	// Check module coin fields while allowing the explicit extended EVM denom.
	var generic map[string]interface{}
	if err := json.Unmarshal(doc.AppState, &generic); err != nil {
		return nil, err
	}
	if b, ok := generic[banktypes.ModuleName].(map[string]interface{}); ok {
		delete(b, "denom_metadata")
	}
	if e, ok := generic[evmtypes.ModuleName].(map[string]interface{}); ok {
		if p, ok := e["params"].(map[string]interface{}); ok {
			delete(p, "extended_denom_options")
		}
	}
	if err := checkDenoms(generic, denom); err != nil {
		return nil, err
	}
	validators, err := validateMainnetGentxs(a, doc, auth, staking, gen, byAddress, balances)
	if err != nil {
		return nil, err
	}
	return &MainnetReport{GenesisSHA256: digest, ChainID: doc.ChainID, EVMChainID: doc.Profile.Chain.EVMChainID, NativeDenom: denom, DisplayDenom: meta.Display, Decimals: decimals, TotalSupply: bank.Supply.String(), Validators: validators, LaunchApproved: false}, nil
}
