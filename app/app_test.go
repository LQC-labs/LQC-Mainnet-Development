// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"os"
	"testing"

	"cosmossdk.io/log/v2"
	dbm "github.com/cosmos/cosmos-db"
	sdk "github.com/cosmos/cosmos-sdk/types"
	evmtypes "github.com/cosmos/evm/x/vm/types"
)

func TestApplicationWiringWithoutGenesis(t *testing.T) {
	home := t.TempDir()
	db := dbm.NewMemDB()
	application, err := New(log.NewNopLogger(), db, home)
	if err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := application.Close(); err != nil {
			t.Error(err)
		}
	})
	if application.SDK.Name() != Name || application.SDK.ChainID() != "lqc-devnet-test-1" {
		t.Fatal("application identity does not match the fixed test profile")
	}
	if sdk.GetConfig().GetBech32AccountAddrPrefix() != "lqctest" {
		t.Fatal("wrong address prefix")
	}
	if application.Profile.Chain.EVMChainID != 917001 || application.Profile.Chain.NativeDenom != "atest" {
		t.Fatal("wrong EVM ID or denomination")
	}
	if evmtypes.GetEthChainConfig() == nil || evmtypes.GetEthChainConfig().ChainID.Uint64() != 917001 {
		t.Fatal("EVM keeper did not receive the fixed chain ID")
	}
	if application.SDK.EVMKeeper == nil || application.SDK.TransferKeeper == nil || application.SDK.StakingKeeper == nil {
		t.Fatal("required upstream keepers are not connected")
	}
	for _, name := range []string{"auth", "bank", "staking", "evm", "feemarket", "erc20"} {
		if _, ok := application.SDK.ModuleManager.Modules[name]; !ok {
			t.Errorf("missing module %s", name)
		}
	}
	if application.SDK.GetAnteHandler() == nil {
		t.Fatal("ante handler is missing")
	}
	if application.SDK.LastBlockHeight() != 0 {
		t.Fatal("application must not produce blocks during construction")
	}
	for _, file := range []string{"config/genesis.json", "config/priv_validator_key.json", "config/node_key.json"} {
		if _, err := os.Stat(home + "/" + file); !os.IsNotExist(err) {
			t.Fatalf("unexpected initialization artifact %s: %v", file, err)
		}
	}
}
