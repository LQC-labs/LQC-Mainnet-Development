// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

// Package app wires the pinned Cosmos EVM reference application for LQC.
// Genesis and node startup are intentionally outside Core 2/2-1.
package app

import (
	"fmt"
	"sync"

	"cosmossdk.io/log/v2"
	chainconfig "github.com/LQC-labs/LQC-Mainnet-Development/chain/config"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/baseapp"
	"github.com/cosmos/cosmos-sdk/client/flags"
	sdkserver "github.com/cosmos/cosmos-sdk/server"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/evm/crypto/hd"
	"github.com/cosmos/evm/evmd"
	evmflags "github.com/cosmos/evm/server/flags"
)

const (
	Name            = "lqc"
	Version         = "0.0.0-core2.1-dev"
	ReferenceCommit = "c3ae9067a7eadcdea55a5192226916deb44c71c4"
)

var configureOnce sync.Once

type options map[string]interface{}

func (o options) Get(key string) interface{} { return o[key] }

// App owns the SDK BaseApp, module manager and keepers built by the exact
// v0.7.3 reference constructor. It has no Genesis or start CLI in this stage.
type App struct {
	SDK     *evmd.EVMD
	Profile chainconfig.DevnetConfig
}

// New constructs and loads an empty application database, without InitChain,
// validator keys, listeners, transactions, or token metadata initialization.
// The caller supplies an isolated home and owns the database until success.
func New(logger log.Logger, db dbm.DB, home string) (result *App, err error) {
	profile := chainconfig.TestOnlyDevnetConfig()
	if err := profile.Validate(); err != nil {
		return nil, err
	}
	if logger == nil || db == nil || home == "" {
		return nil, fmt.Errorf("logger, database and isolated home are required")
	}
	defer func() {
		if failure := recover(); failure != nil {
			result = nil
			err = fmt.Errorf("LQC application initialization failed: %v", failure)
		}
	}()
	configureOnce.Do(func() {
		cfg := sdk.GetConfig()
		prefix := profile.Chain.Bech32Prefix
		cfg.SetBech32PrefixForAccount(prefix, prefix+sdk.PrefixPublic)
		cfg.SetBech32PrefixForValidator(prefix+sdk.PrefixValidator+sdk.PrefixOperator, prefix+sdk.PrefixValidator+sdk.PrefixOperator+sdk.PrefixPublic)
		cfg.SetBech32PrefixForConsensusNode(prefix+sdk.PrefixValidator+sdk.PrefixConsensus, prefix+sdk.PrefixValidator+sdk.PrefixConsensus+sdk.PrefixPublic)
		cfg.SetCoinType(hd.Bip44CoinType)
		cfg.Seal()
	})
	opts := options{
		flags.FlagHome:             home,
		evmflags.EVMChainID:        profile.Chain.EVMChainID,
		sdkserver.FlagMinGasPrices: profile.MinimumGasPrice,
	}
	// Keep all upstream keeper dependencies, object stores, ante/post handlers,
	// and module execution ordering. Do not use upstream example Genesis data.
	application := evmd.NewExampleApp(logger, db, false, opts,
		baseapp.SetChainID(profile.Chain.CosmosChainID),
		baseapp.SetMinGasPrices(profile.MinimumGasPrice),
		func(b *baseapp.BaseApp) { b.SetName(Name) },
	)
	application.SetVersion(Version)
	if err := application.LoadLatestVersion(); err != nil {
		return nil, fmt.Errorf("load LQC application stores: %w", err)
	}
	return &App{SDK: application, Profile: profile}, nil
}

func (a *App) Close() error { return a.SDK.Close() }
