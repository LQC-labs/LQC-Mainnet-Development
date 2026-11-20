// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

package genesis

import (
	"fmt"

	"github.com/LQC-labs/LQC-Mainnet-Development/app"
	chainconfig "github.com/LQC-labs/LQC-Mainnet-Development/chain/config"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	genutiltypes "github.com/cosmos/cosmos-sdk/x/genutil/types"
)

// MainnetDraft uses the approved development identity and leaves accounts,
// funding and validators empty. It cannot be loaded by the Devnet node.
type MainnetDraft struct {
	genutiltypes.AppGenesis
	Profile chainconfig.ChainConfig `json:"lqc_profile"`
	Draft   bool                    `json:"lqc_genesis_draft"`
}

func NewMainnetDraft(a *app.App) ([]byte, error) {
	chain := chainconfig.MainnetChainConfig()
	if a.Profile.Chain != chain {
		return nil, fmt.Errorf("approved Mainnet draft application required")
	}
	draft, err := newDraft(a, mainnetMetadata(chain.NativeDenom))
	if err != nil {
		return nil, err
	}
	data, err := marshalDraft(MainnetDraft{AppGenesis: *draft, Profile: chain, Draft: true})
	if err != nil {
		return nil, err
	}
	return data, ValidateMainnetDraft(a, data)
}

func ValidateMainnetDraft(a *app.App, data []byte) error {
	var doc MainnetDraft
	if err := decodeDraft(data, &doc); err != nil {
		return err
	}
	chain := chainconfig.MainnetChainConfig()
	if !doc.Draft || doc.Profile != chain {
		return fmt.Errorf("approved Mainnet identity and explicit draft marker required")
	}
	return validateDraft(a, &doc.AppGenesis, chain, mainnetMetadata(chain.NativeDenom))
}

func mainnetMetadata(denom string) banktypes.Metadata {
	display := chainconfig.MainnetDisplayDenom
	return banktypes.Metadata{
		Description: "LQC native token", Base: denom, Display: display, Name: "LQC", Symbol: display,
		DenomUnits: []*banktypes.DenomUnit{{Denom: denom, Exponent: 0}, {Denom: display, Exponent: chainconfig.MainnetDecimals}},
	}
}
