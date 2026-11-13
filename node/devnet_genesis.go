//go:build linux

// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0

package node

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/LQC-labs/LQC-Mainnet-Development/app"
	"github.com/LQC-labs/LQC-Mainnet-Development/genesis"
	cmtjson "github.com/cometbft/cometbft/libs/json"
	"github.com/cometbft/cometbft/p2p"
	"github.com/cometbft/cometbft/privval"

	sdked25519 "github.com/cosmos/cosmos-sdk/crypto/keys/ed25519"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	genutiltypes "github.com/cosmos/cosmos-sdk/x/genutil/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"github.com/cosmos/evm/crypto/ethsecp256k1"
	"golang.org/x/sys/unix"
)

// InitDevnetHome creates a NEW TEST-only home using the unchanged CreateHome
// permissions/key policy and the signed-gentx generator from Core ③. Consensus
// and P2P keys are retained; the independent account signer is memory-only.
// This is preparation only: no InitChain, disk DB, listener or node is started.
// The caller supplies and owns one disposable app; reuse it for preparation
// and validation instead of reinitializing process-global EVM configuration.
// On failure the partial new home is preserved and cannot be overwritten.
func InitDevnetHome(application *app.App, path string) error {
	if application == nil {
		return fmt.Errorf("disposable app required")
	}
	if err := CreateHome(path); err != nil {
		return err
	}
	home, err := openDevnetHome(path)
	if err != nil {
		return err
	}
	defer unix.Close(home)
	consensus, err := loadDevnetKeys(home)
	if err != nil {
		return err
	}
	account, err := ethsecp256k1.GenerateKey()
	if err != nil {
		return fmt.Errorf("generate test account signer")
	}
	content, err := genesis.NewSingleValidator(application, account, consensus)
	if err != nil {
		return fmt.Errorf("generate signed test genesis: %w", err)
	}
	if err = validateDevnetGenesis(application, content, consensus); err != nil {
		return err
	}
	config, err := unix.Openat(home, "config", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open config: %w", err)
	}
	defer unix.Close(config)
	if err = writePrivateFile(config, "genesis.json", content); err != nil {
		return err
	}
	if err = unix.Fsync(config); err != nil {
		return fmt.Errorf("sync genesis directory: %w", err)
	}
	return nil
}

// ValidateDevnetHome reads an unstarted home without changing permissions,
// keys, signing state or Genesis. Missing/corrupt keys are never regenerated.
// The unsigned-state requirement intentionally makes this a PRE-START check;
// validation of a running/restarted node belongs to the following stage.
func ValidateDevnetHome(application *app.App, path string) error {
	if application == nil {
		return fmt.Errorf("disposable app required")
	}
	home, err := openDevnetHome(path)
	if err != nil {
		return err
	}
	defer unix.Close(home)
	consensus, err := loadDevnetKeys(home)
	if err != nil {
		return err
	}
	content, err := readDevnetFile(home, "config", "genesis.json")
	if err != nil {
		return err
	}
	return validateDevnetGenesis(application, content, consensus)
}

func validateDevnetGenesis(a *app.App, content []byte, consensus cryptotypes.PubKey) error {
	// The existing validator enforces the fixed Cosmos/EVM IDs, Bech32, denom,
	// 18-decimal metadata, one signed gentx, funding, and no prebonded injection.
	if err := genesis.ValidateSingleValidator(a, content); err != nil {
		return fmt.Errorf("invalid test genesis: %w", err)
	}
	var document genesis.Document
	if err := json.Unmarshal(content, &document); err != nil {
		return fmt.Errorf("invalid test genesis document")
	}
	var state map[string]json.RawMessage
	if err := json.Unmarshal(document.AppState, &state); err != nil {
		return fmt.Errorf("invalid app state")
	}
	var gen genutiltypes.GenesisState
	if err := a.SDK.AppCodec().UnmarshalJSON(state[genutiltypes.ModuleName], &gen); err != nil {
		return fmt.Errorf("invalid gentx state")
	}
	transaction, err := a.SDK.GetTxConfig().TxJSONDecoder()(gen.GenTxs[0])
	if err != nil {
		return fmt.Errorf("invalid gentx")
	}
	message, ok := transaction.GetMsgs()[0].(*stakingtypes.MsgCreateValidator)
	if !ok {
		return fmt.Errorf("expected create-validator gentx")
	}
	var publicKey cryptotypes.PubKey
	if err = a.SDK.AppCodec().UnpackAny(message.Pubkey, &publicKey); err != nil {
		return fmt.Errorf("invalid gentx consensus public key")
	}
	if !publicKey.Equals(consensus) {
		return fmt.Errorf("stored consensus key does not match gentx validator public key")
	}
	return nil
}

func openDevnetHome(path string) (int, error) {
	if !filepath.IsAbs(path) || path == "/" || strings.HasSuffix(path, "/") || strings.IndexByte(path, 0) >= 0 {
		return -1, fmt.Errorf("absolute nonsymlink home required")
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			unix.Close(fd)
			return -1, fmt.Errorf("invalid home component")
		}
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if openErr != nil {
			return -1, fmt.Errorf("open nonsymlink home: %w", openErr)
		}
		fd = next
	}
	if err = requirePrivateMode(fd, true); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func requirePrivateMode(fd int, directory bool) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	mode, kind := uint32(0600), uint32(unix.S_IFREG)
	if directory {
		mode, kind = 0700, unix.S_IFDIR
	}
	if stat.Mode&unix.S_IFMT != kind || stat.Mode&07777 != mode || stat.Uid != uint32(os.Geteuid()) || (!directory && stat.Nlink != 1) {
		return fmt.Errorf("Devnet files must be owner-only, correctly permissioned and not hard-linked")
	}
	return nil
}

func readDevnetFile(home int, directory, name string) ([]byte, error) {
	dir, err := unix.Openat(home, directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open private directory: %w", err)
	}
	defer unix.Close(dir)
	if err = requirePrivateMode(dir, true); err != nil {
		return nil, err
	}
	fd, err := unix.Openat(dir, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", name, err)
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	if err = requirePrivateMode(fd, false); err != nil {
		return nil, err
	}
	// Bound all configuration reads; errors never include file contents.
	content, err := io.ReadAll(io.LimitReader(file, 16*1024*1024+1))
	if err != nil || len(content) > 16*1024*1024 {
		return nil, fmt.Errorf("cannot read bounded %s", name)
	}
	return content, nil
}

func loadDevnetKeys(home int) (cryptotypes.PubKey, error) {
	keyBytes, err := readDevnetFile(home, "config", "priv_validator_key.json")
	if err != nil {
		return nil, err
	}
	var consensus privval.FilePVKey
	if err = cmtjson.Unmarshal(keyBytes, &consensus); err != nil {
		return nil, fmt.Errorf("invalid stored consensus key encoding")
	}
	if consensus.PrivKey == nil || consensus.PrivKey.Type() != "ed25519" || len(consensus.PrivKey.Bytes()) != 64 || consensus.PubKey == nil || !consensus.PrivKey.PubKey().Equals(consensus.PubKey) || !bytes.Equal(consensus.Address, consensus.PubKey.Address()) {
		return nil, fmt.Errorf("inconsistent stored consensus key")
	}
	nodeBytes, err := readDevnetFile(home, "config", "node_key.json")
	if err != nil {
		return nil, err
	}
	var nodeKey p2p.NodeKey
	if err = cmtjson.Unmarshal(nodeBytes, &nodeKey); err != nil {
		return nil, fmt.Errorf("invalid stored node key encoding")
	}
	if nodeKey.PrivKey == nil || nodeKey.PrivKey.Type() != "ed25519" || len(nodeKey.PrivKey.Bytes()) != 64 || nodeKey.PubKey().Equals(consensus.PubKey) {
		return nil, fmt.Errorf("independent Ed25519 node key required")
	}
	stateBytes, err := readDevnetFile(home, "data", "priv_validator_state.json")
	if err != nil {
		return nil, err
	}
	var state privval.FilePVLastSignState
	if err = cmtjson.Unmarshal(stateBytes, &state); err != nil {
		return nil, fmt.Errorf("invalid signing state encoding")
	}
	if state.Height != 0 || state.Round != 0 || state.Step != 0 || len(state.Signature) != 0 || len(state.SignBytes) != 0 {
		return nil, fmt.Errorf("unstarted signing state required")
	}
	// Convert the Comet public key to the SDK public key expected by gentx.
	return &sdked25519.PubKey{Key: consensus.PubKey.Bytes()}, nil
}
