// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

package genesis

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	chainconfig "github.com/LQC-labs/LQC-Mainnet-Development/chain/config"
)

// ValidateMainnetDraft performs an offline, fail-closed structural preflight.
// It is NOT Cosmos SDK module validation, a genesis generator or launch approval.
// The production genesis must pass full module and multi-validator integration
// gates separately. This draft deliberately allows no initial allocations.
func ValidateMainnetDraft(profile chainconfig.RuntimeConfig, raw []byte) error {
	if profile.Chain.NetworkKind != chainconfig.NetworkMainnet {
		return fmt.Errorf("mainnet profile required")
	}
	if err := profile.Validate(); err != nil {
		return err
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return fmt.Errorf("invalid genesis JSON: %w", err)
	}
	var doc struct {
		ChainID    string          `json:"chain_id"`
		AppState   json.RawMessage `json:"app_state"`
		Validators []json.RawMessage `json:"validators"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&doc); err != nil {
		return fmt.Errorf("decode genesis draft: %w", err)
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("trailing genesis draft data")
	}
	if doc.ChainID != profile.Chain.CosmosChainID {
		return fmt.Errorf("genesis Cosmos chain ID mismatch")
	}
	if doc.Validators == nil || len(doc.Validators) != 0 {
		return fmt.Errorf("validators require separately approved integration")
	}
	var state map[string]json.RawMessage
	if len(doc.AppState) == 0 || bytes.Equal(bytes.TrimSpace(doc.AppState), []byte("null")) {
		return fmt.Errorf("missing app_state")
	}
	if err := json.Unmarshal(doc.AppState, &state); err != nil || len(state) == 0 {
		return fmt.Errorf("invalid app_state")
	}
	for _, module := range []string{"auth", "bank", "staking", "genutil"} {
		v, ok := state[module]
		if !ok || len(v) == 0 || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return fmt.Errorf("missing %s module", module)
		}
	}
	// All allocation and validator paths must be empty at this preflight gate.
	var bank struct {
		Balances []json.RawMessage `json:"balances"`
		Supply []json.RawMessage `json:"supply"`
	}
	if err := json.Unmarshal(state["bank"], &bank); err != nil || bank.Balances == nil || bank.Supply == nil || len(bank.Balances) != 0 || len(bank.Supply) != 0 {
		return fmt.Errorf("funded bank genesis forbidden in draft")
	}
	var auth struct { Accounts []json.RawMessage `json:"accounts"` }
	if err := json.Unmarshal(state["auth"], &auth); err != nil || auth.Accounts == nil || len(auth.Accounts) != 0 {
		return fmt.Errorf("accounts forbidden in draft")
	}
	var staking struct { Validators []json.RawMessage `json:"validators"` }
	if err := json.Unmarshal(state["staking"], &staking); err != nil || staking.Validators == nil || len(staking.Validators) != 0 {
		return fmt.Errorf("staking validators forbidden in draft")
	}
	var genutil struct { GenTxs []json.RawMessage `json:"gen_txs"` }
	if err := json.Unmarshal(state["genutil"], &genutil); err != nil || genutil.GenTxs == nil || len(genutil.GenTxs) != 0 {
		return fmt.Errorf("genesis transactions forbidden in draft")
	}
	// Check explicit denomination declarations when supplied. These checks do
	// not replace SDK module genesis validation.
	if err := validateDraftDenom(state["staking"], []string{"params", "bond_denom"}, profile.Chain.NativeDenom); err != nil {
		return fmt.Errorf("staking denomination: %w", err)
	}
	if rawEVM, ok := state["evm"]; ok {
		if err := validateDraftDenom(rawEVM, []string{"params", "evm_denom"}, profile.Chain.NativeDenom); err != nil {
			return fmt.Errorf("EVM denomination: %w", err)
		}
	}
	return nil
}

func validateDraftDenom(raw json.RawMessage, path []string, expected string) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return fmt.Errorf("invalid module object")
	}
	for _, field := range path[:len(path)-1] {
		child, exists := object[field]
		if !exists { return nil }
		if err := json.Unmarshal(child, &object); err != nil || object == nil {
			return fmt.Errorf("invalid %s object", field)
		}
	}
	field := path[len(path)-1]
	if value, exists := object[field]; exists {
		var denom string
		if err := json.Unmarshal(value, &denom); err != nil || denom != expected {
			return fmt.Errorf("%s must match native denomination", field)
		}
	}
	return nil
}
