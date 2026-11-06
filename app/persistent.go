//go:build linux

// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0
package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cosmossdk.io/log/v2"
	chainconfig "github.com/LQC-labs/LQC-Mainnet-Development/chain/config"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/baseapp"
	sdkserver "github.com/cosmos/cosmos-sdk/server"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/evm/evmd"
	evmmempool "github.com/cosmos/evm/mempool"
	evmserver "github.com/cosmos/evm/server"
	evmflags "github.com/cosmos/evm/server/flags"
)

// Bounded local TEST Devnet defaults, applied only to persistent apps.
// The pinned implementation uses InsertQueueSize for BOTH insert queues.
const PersistentInsertQueueCapacity = 128
const persistentCosmosPoolCapacity = 512

func persistentOptions() options {
	return options{
		evmflags.EVMMempoolPendingTxProposalTimeout: 10 * time.Second,
		evmflags.EVMMempoolInsertQueueSize:          PersistentInsertQueueCapacity,
		sdkserver.FlagMempoolMaxTxs:                 persistentCosmosPoolCapacity,
	}
}

// OpenPersistent loads an owner-controlled TEST home, never creates keys or
// Genesis, and returns an App owning its persistent DB. The node layer must hold
// the home lock and validate Genesis/Comet state before starting consensus.
// Use a fresh process per application (upstream EVM globals are one-shot).
func OpenPersistent(logger log.Logger, home string) (result *App, err error) {
	if logger == nil {
		return nil, fmt.Errorf("logger required")
	}
	data := filepath.Join(home, "data")
	if err = privatePersistentPath(home); err != nil {
		return nil, err
	}
	if err = privatePersistentPath(data); err != nil {
		return nil, err
	}
	identityPath := filepath.Join(data, "application.identity.json")
	expected, err := json.Marshal(chainconfig.TestOnlyDevnetConfig())
	if err != nil {
		return nil, err
	}
	previous, readErr := os.ReadFile(identityPath)
	if readErr == nil {
		if err = privatePersistentFile(identityPath); err != nil {
			return nil, err
		}
		var profile chainconfig.DevnetConfig
		if json.Unmarshal(previous, &profile) != nil || profile.Validate() != nil {
			return nil, fmt.Errorf("stored application chain identity mismatch")
		}
	} else if !os.IsNotExist(readErr) {
		return nil, fmt.Errorf("read application identity: %w", readErr)
	} else {
		if _, statErr := os.Lstat(filepath.Join(data, "application.db")); !os.IsNotExist(statErr) {
			return nil, fmt.Errorf("existing application DB has no trusted chain identity")
		}
		f, createErr := os.OpenFile(identityPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if createErr != nil {
			return nil, createErr
		}
		_, writeErr := f.Write(expected)
		syncErr := f.Sync()
		closeErr := f.Close()
		if writeErr != nil {
			return nil, writeErr
		}
		if syncErr != nil {
			return nil, syncErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
	}
	databasePath := filepath.Join(data, "application.db")
	if _, statErr := os.Lstat(databasePath); os.IsNotExist(statErr) {
		if err = os.Mkdir(databasePath, 0700); err != nil {
			return nil, err
		}
	}
	if err = privatePersistentPath(databasePath); err != nil {
		return nil, err
	}
	if err = filepath.WalkDir(databasePath, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink in application DB forbidden")
		}
		return nil
	}); err != nil {
		return nil, err
	}
	database, err := dbm.NewDB("application", dbm.GoLevelDBBackend, data)
	if err != nil {
		return nil, fmt.Errorf("open application DB: %w", err)
	}
	var application *App
	defer func() {
		if recover() != nil {
			result = nil
			err = fmt.Errorf("restore persistent application failed")
		}
		if err != nil {
			if application != nil {
				_ = application.Close()
			} else {
				_ = database.Close()
			}
		}
	}()
	application, err = newWithOptions(logger, database, home, persistentOptions(), configurePersistentMempool)
	if err != nil {
		return nil, err
	}
	// Match pinned EVMD's loadLatest path without changing the old New API or
	// invoking its os.Exit-on-load-error constructor branch.
	if application.SDK.LastBlockHeight() > 1 {
		module, ok := application.SDK.ModuleManager.Modules["evm"].(interface{ HydrateGlobals(context.Context) })
		if !ok {
			return nil, fmt.Errorf("pinned EVM hydration API unavailable")
		}
		module.HydrateGlobals(application.SDK.NewContextLegacy(true, cmtproto.Header{Height: application.SDK.LastBlockHeight(), ChainID: application.Profile.Chain.CosmosChainID}))
	}
	if err = restorePersistentMempool(application); err != nil {
		return nil, err
	}
	return application, nil
}

// restorePersistentMempool replays normal in-memory head notifications, not
// transactions or commits. The pinned blockchain adapter initially returns its
// zero placeholder until the first notification seeds previousHeaderHash. A
// second notification then reads the actual loaded DB head and schedules real
// EVM/Cosmos rechecks. Neither notification writes a height or marks work done.
func restorePersistentMempool(a *App) error {
	height := a.SDK.LastBlockHeight()
	if height == 0 {
		return nil
	}
	pool, ok := a.SDK.EVMMempool.(*evmmempool.Mempool)
	if !ok || pool == nil {
		return fmt.Errorf("pinned persistent EVM mempool required")
	}
	before := a.SDK.LastCommitID()
	pool.NotifyNewBlock()
	pool.NotifyNewBlock()
	if err := a.CheckPersistentMempoolReady(context.Background()); err != nil {
		return err
	}
	after := a.SDK.LastCommitID()
	if after.Version != before.Version || !bytes.Equal(after.Hash, before.Hash) {
		return fmt.Errorf("mempool bootstrap changed committed state")
	}
	return nil
}

// CheckPersistentMempoolReady waits for BOTH normal pool rechecks at the loaded
// committed height via the public iterator API. Its deadline is shorter than
// the persistent proposal timeout, so an iterator timeout cannot fake success.
// Call only before consensus starts, while the committed height is stable.
func (a *App) CheckPersistentMempoolReady(parent context.Context) error {
	if parent == nil {
		return fmt.Errorf("mempool readiness context required")
	}
	pool, ok := a.SDK.EVMMempool.(*evmmempool.Mempool)
	if !ok || pool == nil {
		return fmt.Errorf("pinned EVM mempool required")
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	head := pool.GetBlockchain().CurrentBlock()
	if head == nil || head.Number == nil || head.Number.Int64() != a.SDK.LastBlockHeight() {
		return fmt.Errorf("persistent mempool head does not match committed DB height")
	}
	query, err := committedMempoolContext(a.SDK, 0, false)
	if err != nil {
		return fmt.Errorf("read committed mempool context: %w", err)
	}
	// Iterator selection for the next proposal requests committed height H.
	pool.Select(query.WithBlockHeight(a.SDK.LastBlockHeight()+1).WithContext(ctx), nil)
	if err = ctx.Err(); err != nil {
		return fmt.Errorf("persistent mempool recheck not ready: %w", err)
	}
	return nil
}

// The pinned SDK deliberately loads CheckState with an empty header. Its
// latest-query API rejects that header until the first new commit. Internal
// mempool reads therefore use the SDK's explicit committed-version API, which
// also restores CommitInfo.Timestamp. No DB version or recheck counter is set.
func committedMempoolContext(a *evmd.EVMD, height int64, prove bool) (sdk.Context, error) {
	latest := a.LastBlockHeight()
	if height == 0 && latest > 0 {
		ctx, err := a.CreateQueryContext(latest, prove)
		if err != nil {
			return sdk.Context{}, err
		}
		header := ctx.BlockHeader()
		header.AppHash = a.LastCommitID().Hash
		return ctx.WithBlockHeader(header), nil
	}
	return a.CreateQueryContext(height, prove)
}

// Install the same pinned production mempool and ABCI handlers, changing only
// its committed-state query adapter. This hook runs BEFORE BaseApp is sealed.
// The constructor's original pool is closed before the replacement is created.
// The old New constructor never invokes this persistent-only hook.
func configurePersistentMempool(a *evmd.EVMD, opts options) error {
	old, ok := a.EVMMempool.(*evmmempool.Mempool)
	if !ok || old == nil {
		return fmt.Errorf("pinned EVM mempool required")
	}
	if err := old.Close(); err != nil {
		return err
	}
	logger := a.Logger()
	config := evmserver.ResolveMempoolConfig(a.GetAnteHandler(), opts, logger)
	if err := evmserver.ValidateReapBounds(opts, config.BlockGasLimit); err != nil {
		return err
	}
	encoder := evmmempool.NewTxEncoder(a.GetTxConfig())
	pool := evmmempool.NewMempool(
		func(height int64, prove bool) (sdk.Context, error) { return committedMempoolContext(a, height, prove) },
		logger, a.EVMKeeper, a.FeeMarketKeeper, a.GetTxConfig(),
		evmmempool.NewTxRechecker(config.AnteHandler, encoder),
		evmmempool.NewTxRechecker(config.AnteHandler, encoder),
		config, evmserver.GetCosmosPoolMaxTx(opts, logger),
	)
	a.EVMMempool = pool
	handler := baseapp.NewDefaultProposalHandler(pool, evmd.NewNoCheckProposalTxVerifier(a.BaseApp))
	a.SetPrepareProposal(handler.PrepareProposalHandler())
	a.SetProcessProposal(handler.ProcessProposalHandler())
	a.SetInsertTxHandler(pool.NewInsertTxHandler(a.TxDecode))
	a.SetReapTxsHandler(pool.NewReapTxsHandler())
	a.SetCheckTxHandler(pool.NewCheckTxHandler(a.TxDecode, evmserver.GetMempoolCheckTxTimeout(opts, logger)))
	a.SetMempool(pool)
	a.SetPrepareCheckStater(func(_ sdk.Context) {
		if !pool.HasEventBus() {
			pool.NotifyNewBlock()
		}
	})
	return nil
}

func privatePersistentPath(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("absolute clean persistent path required")
	}
	current := "/"
	for _, component := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("nonsymlink directory required")
		}
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm() != 0700 {
		return fmt.Errorf("persistent directory must have mode 0700")
	}
	return nil
}

func privatePersistentFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return fmt.Errorf("private identity file required")
	}
	return nil
}
