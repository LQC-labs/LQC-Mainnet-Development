// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

package genesis

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	"cosmossdk.io/log/v2"
	"github.com/LQC-labs/LQC-Mainnet-Development/app"
	dbm "github.com/cosmos/cosmos-db"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

func TestMainnetDraft(t *testing.T) {
	// The SDK seals its address prefixes and installs the EVM chain ID per process.
	if os.Getenv("LQC_MAINNET_DRAFT_TEST_CHILD") != "1" {
		child := exec.Command(os.Args[0], "-test.run=^TestMainnetDraft$", "-test.v")
		child.Env = append(os.Environ(), "LQC_MAINNET_DRAFT_TEST_CHILD=1")
		out, err := child.CombinedOutput()
		t.Log(string(out))
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	logger := log.NewNopLogger()
	a, err := app.NewMainnetDraft(logger, dbm.NewMemDB(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	before := a.SDK.LastCommitID()
	raw, err := NewMainnetDraft(a)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateMainnetDraft(a, raw); err != nil {
		t.Fatal(err)
	}
	address := sdk.AccAddress(bytes.Repeat([]byte{1}, 20))
	if !strings.HasPrefix(address.String(), "lqc1") ||
		!strings.HasPrefix(sdk.ValAddress(address).String(), "lqcvaloper1") ||
		!strings.HasPrefix(sdk.ConsAddress(address).String(), "lqcvalcons1") {
		t.Fatal("unexpected Mainnet address prefixes")
	}
	if err := Validate(a, raw); err == nil {
		t.Fatal("Devnet validator accepted a Mainnet draft")
	}
	db := dbm.NewMemDB()
	defer db.Close()
	if wrong, err := app.New(logger, db, t.TempDir()); err == nil {
		_ = wrong.Close()
		t.Fatal("process accepted a switch from Mainnet to Devnet")
	}
	for _, tt := range []struct {
		name, from, to string
	}{
		{"missing draft marker", `"lqc_genesis_draft": true`, `"lqc_genesis_draft": false`},
		{"Cosmos ID", `"chain_id": "lqc-1"`, `"chain_id": "lqc-devnet-test-1"`},
		{"EVM ID", `"EVMChainID": 768167`, `"EVMChainID": 917001`},
		{"Bech32 prefix", `"Bech32Prefix": "lqc"`, `"Bech32Prefix": "lqctest"`},
		{"staking denom", `"bond_denom": "alqc"`, `"bond_denom": "atest"`},
		{"EVM denom", `"evm_denom": "alqc"`, `"evm_denom": "atest"`},
		{"extended denom", `"extended_denom": "alqc"`, `"extended_denom": "atest"`},
		{"display denom case", `"display": "LQC"`, `"display": "lqc"`},
		{"bank display exponent", `"exponent": 18`, `"exponent": 6`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if !bytes.Contains(raw, []byte(tt.from)) {
				t.Fatalf("fixture field missing: %s", tt.from)
			}
			bad := bytes.Replace(raw, []byte(tt.from), []byte(tt.to), 1)
			if !json.Valid(bad) || ValidateMainnetDraft(a, bad) == nil {
				t.Fatal("expected valid JSON to be rejected by draft validation")
			}
		})
	}
	after := a.SDK.LastCommitID()
	if a.SDK.LastBlockHeight() != 0 || before.Version != after.Version || !bytes.Equal(before.Hash, after.Hash) {
		t.Fatal("offline draft tools changed committed state")
	}
}
