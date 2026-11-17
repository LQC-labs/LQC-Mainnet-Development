// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

package genesis

import (
	"strings"
	"testing"
)

func TestMainnetDraftRejectsDuplicateJSONKeys(t *testing.T) {
	profile := mainnetFixture().Chain
	good := `{"chain_id":"lqc-offline-fixture-1","validators":[],"app_state":{"auth":{"accounts":[]},"bank":{"balances":[],"supply":[]},"staking":{"validators":[]},"genutil":{"gen_txs":[]}}}`
	if err := ValidateMainnetDraft(profile, []byte(good)); err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]string{
		"root override": strings.Replace(good, `"validators":[]`, `"validators":[{"fake":1}],"validators":[]`, 1),
		"nested bank override": strings.Replace(good, `"balances":[]`, `"balances":[{"fake":1}],"balances":[]`, 1),
		"duplicate module": strings.Replace(good, `"auth":{"accounts":[]}`, `"auth":{"accounts":[1]},"auth":{"accounts":[]}`, 1),
		"trailing value": good + ` {}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateMainnetDraft(profile, []byte(raw)); err == nil {
				t.Fatal("ambiguous JSON was accepted")
			}
		})
	}
}
