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

// MainnetProfile is an offline, explicit-parameter validation envelope.
// It does not generate, sign, fund or activate a network.
type MainnetProfile struct {
	Chain           chainconfig.RuntimeConfig `json:"chain"`
	GenesisHash     string                    `json:"genesis_hash"`
	ValidatorCount  int                       `json:"validator_count"`
	Approved        bool                      `json:"approved"`
}

// ValidateMainnetProfile validates a pre-activation proposal only.
// No default mainnet identities or validator keys are created.
func ValidateMainnetProfile(raw []byte) error {
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return fmt.Errorf("invalid mainnet profile JSON: %w", err)
	}
	var p MainnetProfile
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return fmt.Errorf("decode mainnet profile: %w", err)
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("unexpected trailing mainnet profile data")
	}
	if p.Chain.Chain.NetworkKind != chainconfig.NetworkMainnet {
		return fmt.Errorf("explicit mainnet network kind required")
	}
	if err := p.Chain.Validate(); err != nil {
		return fmt.Errorf("mainnet runtime config: %w", err)
	}
	if p.GenesisHash != "" || p.ValidatorCount != 0 || p.Approved {
		return fmt.Errorf("activation fields are not accepted during offline proposal validation")
	}
	return nil
}
