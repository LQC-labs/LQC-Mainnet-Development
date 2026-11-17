// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"strings"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// RuntimeConfig is an explicit application profile, not a Genesis or launch
// approval. Its JSON shape preserves existing Devnet application identities.
// No production identifiers, denomination or gas price defaults are supplied.
type RuntimeConfig struct {
	Chain           ChainConfig
	MinimumGasPrice string
}

func RuntimeFromDevnet(d DevnetConfig) RuntimeConfig {
	return RuntimeConfig{Chain: d.Chain, MinimumGasPrice: d.MinimumGasPrice}
}

// AsTestDevnet deliberately retains the existing strict test-only validator.
func (r RuntimeConfig) AsTestDevnet() (DevnetConfig, error) {
	d := DevnetConfig{Chain: r.Chain, MinimumGasPrice: r.MinimumGasPrice}
	return d, d.Validate()
}

func (r RuntimeConfig) Validate() error {
	if r.Chain.NetworkKind == NetworkDevnet {
		_, err := r.AsTestDevnet()
		return err
	}
	if err := r.Chain.Validate(); err != nil {
		return err
	}
	if err := ValidateNetworkPair(TestOnlyDevnetConfig().Chain, r.Chain); err != nil {
		return err
	}
	if r.MinimumGasPrice == "" || strings.TrimSpace(r.MinimumGasPrice) != r.MinimumGasPrice {
		return fmt.Errorf("explicit minimum gas price required")
	}
	price, err := sdk.ParseDecCoin(r.MinimumGasPrice)
	if err != nil || price.Denom != r.Chain.NativeDenom || price.IsNegative() {
		return fmt.Errorf("minimum gas price must be one nonnegative native-denomination decimal coin")
	}
	return nil
}
