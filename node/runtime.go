//go:build linux

// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0
package node

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"cosmossdk.io/log/v2"
	"github.com/LQC-labs/LQC-Mainnet-Development/app"
	chainconfig "github.com/LQC-labs/LQC-Mainnet-Development/chain/config"
	"github.com/LQC-labs/LQC-Mainnet-Development/genesis"
	dbm "github.com/cosmos/cosmos-db"
	sdked25519 "github.com/cosmos/cosmos-sdk/crypto/keys/ed25519"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	genutiltypes "github.com/cosmos/cosmos-sdk/x/genutil/types"
	"golang.org/x/sys/unix"
)

// RuntimeOptions enables prepared, explicitly isolated local test nodes.
// This is NOT a public Mainnet launcher or a key/Genesis generation API.
type RuntimeOptions struct {
	Network               chainconfig.NetworkKind
	Profile               chainconfig.RuntimeConfig
	GenesisPath           string
	ExpectedGenesisSHA256 string
	LocalTestOnly         bool
	CometRPCListen        string
	P2PListen             string
	EVMRPCListen          string
	Role                  NodeRole
	EnableP2P             bool
	Seeds                 string
	PersistentPeers       string
	MaxInboundPeers       int
	MaxOutboundPeers      int
}

func DecodeRuntimeConfig(raw []byte, network chainconfig.NetworkKind) (chainconfig.RuntimeConfig, error) {
	var cfg chainconfig.RuntimeConfig
	if network == chainconfig.NetworkMainnet {
		return genesis.DecodeMainnetConfig(raw)
	}
	if network != chainconfig.NetworkDevnet || len(raw) > genesis.MaxMainnetConfigBytes {
		return cfg, fmt.Errorf("explicit supported network and bounded config required")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return cfg, err
	}
	if dec.Decode(new(interface{})) != io.EOF {
		return cfg, fmt.Errorf("trailing runtime config")
	}
	if cfg.Chain.NetworkKind != network {
		return cfg, fmt.Errorf("requested network/profile mismatch")
	}
	return cfg, cfg.Validate()
}

func (o RuntimeOptions) validate() error {
	if !o.LocalTestOnly {
		return fmt.Errorf("local-test-only acknowledgement required; public Mainnet runtime is unavailable")
	}
	if o.Network != chainconfig.NetworkDevnet && o.Network != chainconfig.NetworkMainnet {
		return fmt.Errorf("explicit network required")
	}
	if o.Profile.Chain.NetworkKind != o.Network {
		return fmt.Errorf("requested network/profile mismatch")
	}
	if err := o.Profile.Validate(); err != nil {
		return err
	}
	h, err := hex.DecodeString(o.ExpectedGenesisSHA256)
	if err != nil || len(h) != sha256.Size || hex.EncodeToString(h) != o.ExpectedGenesisSHA256 || o.GenesisPath == "" {
		return fmt.Errorf("explicit Genesis path and lowercase SHA-256 required")
	}
	for _, address := range []string{o.CometRPCListen, o.P2PListen, o.EVMRPCListen} {
		if address != "" {
			if err := validateEVMRPCAddress(address); err != nil {
				return err
			}
		}
	}
	return o.validateCluster()
}

// OpenRuntime validates and opens a prepared home but never starts consensus.
// CLI performs PreflightRuntime in a separate process BEFORE calling this.
// Application/Genesis validation is repeated on the persistent app before Start.
func OpenRuntime(home string, options RuntimeOptions) (*Node, error) {
	if err := options.validate(); err != nil {
		return nil, err
	}
	return openConfigured(home, options, nil, true)
}

type RuntimePreflightResult struct {
	ChainID            string `json:"chain_id"`
	GenesisSHA256      string `json:"genesis_sha256"`
	ProfileSHA256      string `json:"profile_sha256"`
	ConsensusPublicKey string `json:"consensus_public_key"`
	LocalTestOnly      bool   `json:"local_test_only"`
	Role               string `json:"role"`
}

func runtimeProfileSHA256(profile chainconfig.RuntimeConfig) string {
	raw, _ := json.Marshal(profile)
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

// PreflightRuntime uses a memory app and no-follow reads only. It never opens
// the prepared home's DBs, writes its identity, starts a listener, or signs.
// Execute in a fresh process: the SDK/EVM process-global guards remain intact.
func PreflightRuntime(home string, options RuntimeOptions) (*RuntimePreflightResult, error) {
	if err := options.validate(); err != nil {
		return nil, err
	}
	fd, err := openDevnetHome(home)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, fmt.Errorf("home already in use: %w", err)
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	if err := rejectDBSymlinks(filepath.Join(home, "data")); err != nil {
		return nil, err
	}
	raw, err := readDevnetFile(fd, "config", "genesis.json")
	if err != nil {
		return nil, err
	}
	document, validate, err := runtimeGenesis(raw, options, nil, true)
	if err != nil {
		return nil, err
	}
	pv, nk, _, err := loadRoleKeys(fd, home, document.ChainID, options.EffectiveRole())
	if err != nil {
		return nil, err
	}
	identity, err := roleIdentity(document.ChainID, raw, pv, nk, options, document)
	if err != nil {
		return nil, err
	}
	if _, err := checkRuntimeIdentity(fd, home, identity, signedHeight(pv)); err != nil {
		return nil, err
	}
	if err := checkRuntimeApplicationIdentity(fd, home, options.Profile); err != nil {
		return nil, err
	}
	if err := clusterSafetyBeforeDB(home, fd, options, document, pv, nk); err != nil {
		return nil, err
	}
	scratch, err := os.MkdirTemp("", "lqc-runtime-preflight-")
	if err != nil {
		return nil, err
	}
	db := dbm.NewMemDB()
	a, err := app.NewWithConfig(log.NewNopLogger(), db, scratch, options.Profile)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	var public cryptotypes.PubKey
	if pv != nil {
		public = &sdked25519.PubKey{Key: pv.Key.PubKey.Bytes()}
	}
	validationErr := validate(a, raw, public)
	closeErr := a.Close()
	if validationErr != nil {
		return nil, validationErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return &RuntimePreflightResult{ChainID: document.ChainID, GenesisSHA256: identity.GenesisSHA256, ProfileSHA256: runtimeProfileSHA256(options.Profile), ConsensusPublicKey: identity.ConsensusPublicKey, LocalTestOnly: true, Role: string(options.EffectiveRole())}, nil
}

func runtimeGenesis(raw []byte, options RuntimeOptions, legacy func(*app.App, []byte, cryptotypes.PubKey) error, explicit bool) (genutiltypes.AppGenesis, func(*app.App, []byte, cryptotypes.PubKey) error, error) {
	var zero genutiltypes.AppGenesis
	if explicit {
		digest := sha256.Sum256(raw)
		if hex.EncodeToString(digest[:]) != options.ExpectedGenesisSHA256 {
			return zero, nil, fmt.Errorf("Genesis SHA-256 mismatch")
		}
		external, err := genesis.ReadMainnetInputFile(options.GenesisPath, genesis.MaxMainnetGenesisBytes)
		if err != nil {
			return zero, nil, err
		}
		if !bytes.Equal(raw, external) {
			return zero, nil, fmt.Errorf("explicit Genesis differs from prepared home Genesis")
		}
	}
	if options.Network == chainconfig.NetworkMainnet {
		loaded, err := genesis.LoadMainnet(bytes.NewReader(raw), options.Profile, options.ExpectedGenesisSHA256)
		if err != nil {
			return zero, nil, err
		}
		var doc genesis.MainnetDocument
		if err := json.Unmarshal(loaded.Bytes(), &doc); err != nil {
			return zero, nil, err
		}
		var state map[string]json.RawMessage
		if err := json.Unmarshal(doc.AppState, &state); err != nil {
			return zero, nil, err
		}
		// SDK protobuf JSON uses gen_txs, while the generated Go JSON tag
		// is gentxs. Read the wire field explicitly before opening any DB.
		var gen struct {
			GenTxs []json.RawMessage `json:"gen_txs"`
		}
		if err := json.Unmarshal(state[genutiltypes.ModuleName], &gen); err != nil {
			return zero, nil, err
		}
		if !options.EnableP2P && (len(gen.GenTxs) != 1 || len(doc.Consensus.Validators) > 1) {
			return zero, nil, fmt.Errorf("single-validator local runtime only; multi-validator Mainnet startup remains unavailable")
		}
		validator := func(a *app.App, _ []byte, public cryptotypes.PubKey) error {
			report, err := genesis.ValidateMainnet(a, loaded)
			if err != nil {
				return err
			}
			if options.EnableP2P {
				if options.EffectiveRole() == RoleFullNode {
					if public != nil {
						return fmt.Errorf("Full Node must not load consensus key")
					}
					return nil
				}
				if public != nil {
					for _, validator := range report.Validators {
						if validator.ConsensusPublicKey == hex.EncodeToString(public.Bytes()) {
							return nil
						}
					}
				}
				return fmt.Errorf("validator key is not in Genesis set")
			}
			if len(report.Validators) != 1 || public == nil || report.Validators[0].ConsensusPublicKey != hex.EncodeToString(public.Bytes()) {
				return fmt.Errorf("stored consensus key does not match single Genesis validator")
			}
			return nil
		}
		return doc.AppGenesis, validator, nil
	}
	var doc genesis.Document
	if err := json.Unmarshal(raw, &doc); err != nil {
		return zero, nil, fmt.Errorf("invalid genesis document")
	}
	if doc.Profile.Validate() != nil || chainconfig.RuntimeFromDevnet(doc.Profile) != options.Profile || doc.ChainID != options.Profile.Chain.CosmosChainID {
		return zero, nil, fmt.Errorf("fixed Devnet chain identity required")
	}
	if legacy == nil {
		legacy = validateDevnetGenesis
	}
	return doc.AppGenesis, legacy, nil
}

func runtimeNodeIdentity(chain string, raw, consensus []byte, nodeID string, profile chainconfig.RuntimeConfig) nodeIdentity {
	digest := sha256.Sum256(raw)
	identity := nodeIdentity{ChainID: chain, GenesisSHA256: hex.EncodeToString(digest[:]), ConsensusPublicKey: hex.EncodeToString(consensus), NodeID: nodeID}
	// Preserve the exact legacy Devnet identity. Mainnet binds every runtime
	// profile field as well; the app identity independently checks the profile.
	if profile.Chain.NetworkKind == chainconfig.NetworkMainnet {
		identity.ProfileSHA256 = runtimeProfileSHA256(profile)
	}
	return identity
}

func checkRuntimeIdentity(fd int, home string, expected nodeIdentity, signedHeight int64) (bool, error) {
	raw, err := readDevnetFile(fd, "data", "node.identity.json")
	if err == nil {
		var stored nodeIdentity
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if dec.Decode(&stored) != nil || dec.Decode(new(interface{})) != io.EOF || stored != expected {
			return false, fmt.Errorf("stored DB chain/Genesis/key identity mismatch")
		}
		return true, nil
	}
	if !errors.Is(err, unix.ENOENT) {
		return false, err
	}
	for _, name := range []string{"application.db", "state.db", "blockstore.db", "evidence.db", "tx_index.db"} {
		if _, err := os.Lstat(filepath.Join(home, "data", name)); !os.IsNotExist(err) {
			return false, fmt.Errorf("existing DB without trusted node identity")
		}
	}
	if signedHeight != 0 {
		return false, fmt.Errorf("signed history without node identity")
	}
	return false, nil
}

// Wait returns on cancellation or an unexpected Comet shutdown. Close remains
// the sole ordered cleanup path, including signal cancellation.
func (n *Node) Wait(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("live context required")
	}
	n.mu.Lock()
	started := n.node
	n.mu.Unlock()
	if started == nil {
		return fmt.Errorf("node not started")
	}
	select {
	case <-ctx.Done():
		return nil
	case <-started.Quit():
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("node stopped unexpectedly")
	}
}

// Inspect identity files before opening Comet or application databases.
func checkRuntimeApplicationIdentity(fd int, home string, profile chainconfig.RuntimeConfig) error {
	raw, err := readDevnetFile(fd, "data", "application.identity.json")
	if err == nil {
		stored, err := DecodeRuntimeConfig(raw, profile.Chain.NetworkKind)
		if err != nil || stored != profile {
			return fmt.Errorf("stored application chain identity mismatch")
		}
		return nil
	}
	if !errors.Is(err, unix.ENOENT) {
		return err
	}
	if _, err := os.Lstat(filepath.Join(home, "data/application.db")); !os.IsNotExist(err) {
		return fmt.Errorf("existing application DB has no trusted chain identity")
	}
	return nil
}
