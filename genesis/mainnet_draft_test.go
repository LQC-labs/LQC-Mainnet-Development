// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

package genesis

import (
	"encoding/json"
	"testing"
)

func TestMainnetDraftOfflinePreflight(t *testing.T) {
	profile := mainnetFixture().Chain
	base := map[string]any{
		"chain_id": profile.Chain.CosmosChainID,
		"validators": []any{},
		"app_state": map[string]any{
			"auth": map[string]any{"accounts": []any{}},
			"bank": map[string]any{"balances": []any{}, "supply": []any{}},
			"staking": map[string]any{"validators": []any{}},
			"genutil": map[string]any{"gen_txs": []any{}},
		},
	}
	check := func(t *testing.T, data map[string]any, wantValid bool) {
		t.Helper()
		raw, err := json.Marshal(data)
		if err != nil { t.Fatal(err) }
		err = ValidateMainnetDraft(profile, raw)
		if (err == nil) != wantValid { t.Fatalf("valid=%v error=%v", wantValid, err) }
	}
	check(t, base, true)
	for name, mutate := range map[string]func(map[string]any){
		"null validators": func(d map[string]any) { d["validators"] = nil },
		"missing validators": func(d map[string]any) { delete(d, "validators") },
		"null bank": func(d map[string]any) { d["app_state"].(map[string]any)["bank"] = nil },
		"missing balances": func(d map[string]any) { d["app_state"].(map[string]any)["bank"] = map[string]any{"supply": []any{}} },
		"null balances": func(d map[string]any) { d["app_state"].(map[string]any)["bank"] = map[string]any{"balances": nil, "supply": []any{}} },
		"missing accounts": func(d map[string]any) { d["app_state"].(map[string]any)["auth"] = map[string]any{} },
		"null accounts": func(d map[string]any) { d["app_state"].(map[string]any)["auth"] = map[string]any{"accounts": nil} },
		"missing staking validators": func(d map[string]any) { d["app_state"].(map[string]any)["staking"] = map[string]any{} },
		"missing gentxs": func(d map[string]any) { d["app_state"].(map[string]any)["genutil"] = map[string]any{} },
		"unknown root field": func(d map[string]any) { d["unapproved_activation"] = true },
		"wrong chain": func(d map[string]any) { d["chain_id"] = "wrong-1" },
		"validators": func(d map[string]any) { d["validators"] = []any{map[string]any{"address": "fake"}} },
		"missing state": func(d map[string]any) { delete(d, "app_state") },
		"funded bank": func(d map[string]any) { d["app_state"].(map[string]any)["bank"] = map[string]any{"balances": []any{1}} },
		"supply": func(d map[string]any) { d["app_state"].(map[string]any)["bank"] = map[string]any{"supply": []any{1}} },
		"accounts": func(d map[string]any) { d["app_state"].(map[string]any)["auth"] = map[string]any{"accounts": []any{1}} },
		"staking": func(d map[string]any) { d["app_state"].(map[string]any)["staking"] = map[string]any{"validators": []any{1}} },
		"gentxs": func(d map[string]any) { d["app_state"].(map[string]any)["genutil"] = map[string]any{"gen_txs": []any{1}} },
	} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(base)
			var copy map[string]any
			if err := json.Unmarshal(raw, &copy); err != nil { t.Fatal(err) }
			mutate(copy)
			check(t, copy, false)
		})
	}
	for _, raw := range [][]byte{nil, []byte("{}"), []byte("null"), []byte("[]"), []byte("{} {}")} {
		if ValidateMainnetDraft(profile, raw) == nil { t.Fatalf("invalid raw accepted: %s", raw) }
	}
}
