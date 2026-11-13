//go:build linux

// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0
package node

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	chainconfig "github.com/LQC-labs/LQC-Mainnet-Development/chain/config"
	cmtdb "github.com/cometbft/cometbft-db"
	cmtcfg "github.com/cometbft/cometbft/config"
	cmtcrypto "github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/ed25519"
	cmtjson "github.com/cometbft/cometbft/libs/json"
	"github.com/cometbft/cometbft/p2p"
	"github.com/cometbft/cometbft/privval"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	cmtstate "github.com/cometbft/cometbft/state"
	cmtstore "github.com/cometbft/cometbft/store"
	cmttypes "github.com/cometbft/cometbft/types"
	genutiltypes "github.com/cosmos/cosmos-sdk/x/genutil/types"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

type NodeRole string

const RoleValidator NodeRole = "validator"
const RoleFullNode NodeRole = "fullnode"

func (o RuntimeOptions) EffectiveRole() NodeRole {
	if o.Role == "" {
		return RoleValidator
	}
	return o.Role
}

func (o RuntimeOptions) validateCluster() error {
	role := o.EffectiveRole()
	if role != RoleValidator && role != RoleFullNode {
		return fmt.Errorf("explicit supported node role required")
	}
	if !o.EnableP2P {
		if role != RoleValidator || o.Seeds != "" || o.PersistentPeers != "" || o.MaxInboundPeers != 0 || o.MaxOutboundPeers != 0 {
			return fmt.Errorf("role/peers require explicit local P2P mode")
		}
		return nil
	}
	if o.Network != chainconfig.NetworkMainnet {
		return fmt.Errorf("local cluster requires Mainnet-format Genesis; legacy Devnet remains single-validator")
	}
	if o.CometRPCListen == "" || o.P2PListen == "" {
		return fmt.Errorf("explicit local cluster listeners required")
	}
	if o.MaxInboundPeers < 0 || o.MaxOutboundPeers < 0 || o.MaxInboundPeers > 64 || o.MaxOutboundPeers > 64 {
		return fmt.Errorf("local peer limits must be 0..64")
	}
	seen := map[string]bool{}
	for _, list := range []string{o.Seeds, o.PersistentPeers} {
		peers, err := localPeerList(list)
		if err != nil {
			return err
		}
		if len(peers) > 0 && o.MaxOutboundPeers == 0 {
			return fmt.Errorf("outbound peer limit required for configured peers")
		}
		for _, peer := range peers {
			id := strings.Split(peer, "@")[0]
			if seen[id] {
				return fmt.Errorf("duplicate configured peer ID")
			}
			seen[id] = true
		}
	}
	// Comet excludes persistent peers from its outbound counter. With PEX
	// disabled, bound the entire explicit dial set, including bootstrap seeds.
	if len(seen) > o.MaxOutboundPeers {
		return fmt.Errorf("configured peers exceed outbound limit")
	}
	return nil
}

func localPeerList(list string) ([]string, error) {
	if list == "" {
		return nil, nil
	}
	result := strings.Split(list, ",")
	for _, peer := range result {
		parts := strings.Split(peer, "@")
		if len(parts) != 2 || len(parts[0]) != 40 {
			return nil, fmt.Errorf("peer requires nodeID@127.0.0.1:port")
		}
		id, err := hex.DecodeString(parts[0])
		if err != nil || hex.EncodeToString(id) != parts[0] {
			return nil, fmt.Errorf("lowercase hexadecimal peer ID required")
		}
		host, port, err := net.SplitHostPort(parts[1])
		if err != nil || host != "127.0.0.1" {
			return nil, fmt.Errorf("peers must use numeric IPv4 loopback")
		}
		p, err := strconv.Atoi(port)
		if err != nil || p <= 0 || p > 65535 {
			return nil, fmt.Errorf("invalid peer port")
		}
	}
	return result, nil
}

func applyClusterConfig(cfg *cmtcfg.Config, o RuntimeOptions, self string) error {
	if !o.EnableP2P {
		return nil
	}
	if err := o.validateCluster(); err != nil {
		return err
	}
	for _, list := range []string{o.Seeds, o.PersistentPeers} {
		peers, _ := localPeerList(list)
		for _, peer := range peers {
			if strings.Split(peer, "@")[0] == self {
				return fmt.Errorf("self peer configuration forbidden")
			}
		}
	}
	cfg.P2P.Seeds = o.Seeds
	cfg.P2P.PersistentPeers = o.PersistentPeers
	cfg.P2P.MaxNumInboundPeers = o.MaxInboundPeers
	cfg.P2P.MaxNumOutboundPeers = o.MaxOutboundPeers
	// Several independent local nodes share 127.0.0.1. No PEX is enabled: seed
	// addresses are explicitly dialled once, without learning remote addresses.
	cfg.P2P.AllowDuplicateIP = true
	cfg.P2P.AddrBookStrict = false
	cfg.P2P.PexReactor = false
	return cfg.ValidateBasic()
}

// Comet's constructor unconditionally requests a public key, even for nodes
// outside its validator set. This adapter contains public bytes only and can
// NEVER sign; it is not a dummy consensus private key or a FilePV reset.
type observerValidator struct{ public ed25519.PubKey }

func (v observerValidator) GetPubKey() (cmtcrypto.PubKey, error) {
	return ed25519.PubKey(bytes.Clone(v.public)), nil
}
func (observerValidator) SignVote(string, *cmtproto.Vote) error {
	return fmt.Errorf("Full Node cannot sign votes")
}
func (observerValidator) SignProposal(string, *cmtproto.Proposal) error {
	return fmt.Errorf("Full Node cannot sign proposals")
}

func loadRoleKeys(fd int, home, chain string, role NodeRole) (*privval.FilePV, *p2p.NodeKey, cmttypes.PrivValidator, error) {
	if role == RoleValidator {
		pv, nk, err := loadRuntimeKeysForChain(fd, home, chain)
		if err != nil {
			return nil, nil, nil, err
		}
		return pv, nk, pv, nil
	}
	if role != RoleFullNode {
		return nil, nil, nil, fmt.Errorf("unsupported role")
	}
	for _, rel := range []string{"config/priv_validator_key.json", "data/priv_validator_state.json"} {
		if _, err := os.Lstat(filepath.Join(home, rel)); !os.IsNotExist(err) {
			return nil, nil, nil, fmt.Errorf("Full Node must not contain consensus key or signing state")
		}
	}
	raw, err := readDevnetFile(fd, "config", "node_key.json")
	if err != nil {
		return nil, nil, nil, err
	}
	var nk p2p.NodeKey
	if cmtjson.Unmarshal(raw, &nk) != nil || nk.PrivKey == nil || nk.PrivKey.Type() != "ed25519" || len(nk.PrivKey.Bytes()) != 64 {
		return nil, nil, nil, fmt.Errorf("invalid Full Node P2P key")
	}
	return nil, &nk, observerValidator{public: ed25519.PubKey(bytes.Clone(nk.PubKey().Bytes()))}, nil
}

func roleIdentity(chain string, raw []byte, pv *privval.FilePV, nk *p2p.NodeKey, o RuntimeOptions, doc genutiltypes.AppGenesis) (nodeIdentity, error) {
	var public []byte
	if pv != nil {
		public = pv.Key.PubKey.Bytes()
	}
	id := runtimeNodeIdentity(chain, raw, public, string(nk.ID()), o.Profile)
	if o.EnableP2P {
		vals, err := initialClusterValidators(doc)
		if err != nil {
			return id, err
		}
		id.Role = string(o.EffectiveRole())
		id.ValidatorSetSHA256 = validatorSetSHA256(vals)
	}
	return id, nil
}

func initialClusterValidators(doc genutiltypes.AppGenesis) (map[string]int64, error) {
	if doc.Consensus == nil || len(doc.Consensus.Validators) == 0 {
		return nil, fmt.Errorf("cluster requires explicit initial consensus validator set")
	}
	result := map[string]int64{}
	var total int64
	for _, v := range doc.Consensus.Validators {
		if v.PubKey == nil || v.PubKey.Type() != "ed25519" || len(v.PubKey.Bytes()) != 32 || !bytes.Equal(v.Address, v.PubKey.Address()) || v.Power <= 0 || v.Power > cmttypes.MaxTotalVotingPower-total {
			return nil, fmt.Errorf("invalid initial consensus validator")
		}
		key := hex.EncodeToString(v.PubKey.Bytes())
		if _, ok := result[key]; ok {
			return nil, fmt.Errorf("duplicate initial consensus key")
		}
		result[key] = v.Power
		total += v.Power
	}
	return result, nil
}

func validatorSetSHA256(vals map[string]int64) string {
	keys := make([]string, 0, len(vals))
	for k := range vals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	rows := make([]string, 0, len(keys))
	for _, k := range keys {
		rows = append(rows, fmt.Sprintf("%s:%d", k, vals[k]))
	}
	raw, _ := json.Marshal(rows)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

func (n *Node) validateClusterSet(state cmtstate.State) error {
	if !n.cluster {
		return nil
	}
	if state.IsEmpty() {
		return nil
	}
	if state.ChainID != n.genesisChainID {
		return fmt.Errorf("cluster consensus chain mismatch")
	}
	for name, set := range map[string]*cmttypes.ValidatorSet{"current": state.Validators, "next": state.NextValidators, "last": state.LastValidators} {
		if name == "last" && state.LastBlockHeight == 0 {
			continue
		}
		if set == nil || set.Size() != len(n.initialValidators) {
			return fmt.Errorf("%s validator set differs from approved initial set", name)
		}
		if err := set.ValidateBasic(); err != nil {
			return err
		}
		for _, v := range set.Validators {
			if v.PubKey == nil || n.initialValidators[hex.EncodeToString(v.PubKey.Bytes())] != v.VotingPower {
				return fmt.Errorf("%s validator key/power differs from initial Genesis; validator-set changes require separate support", name)
			}
		}
	}
	var key []byte
	if n.validator != nil {
		key = n.validator.Key.PubKey.Bytes()
	} else {
		key = n.nodeKey.PubKey().Bytes()
	}
	_, member := n.initialValidators[hex.EncodeToString(key)]
	if (n.role == RoleValidator) != member {
		return fmt.Errorf("node role does not match consensus validator membership")
	}
	return nil
}

// Validate retained committed signatures against the actual persisted HRS. A
// lagging validator is allowed only when no retained commit proves a later
// local signature. Interrupted commits and unavailable history fail closed.
func (n *Node) checkClusterSigning(state cmtstate.State) error {
	if !n.cluster {
		return nil
	}
	if err := n.validateClusterSet(state); err != nil {
		return err
	}
	// Even at height zero, an existing blockstore must agree. Do not silently
	// replay an interrupted first commit through this normal-start path.
	if _, err := os.Lstat(filepath.Join(n.home, "data/blockstore.db")); os.IsNotExist(err) && state.LastBlockHeight == 0 {
		return nil
	}
	db, err := cmtdb.NewGoLevelDBWithOpts("blockstore", filepath.Join(n.home, "data"), &opt.Options{ReadOnly: true, ErrorIfMissing: true})
	if err != nil {
		return err
	}
	defer db.Close()
	store := cmtstore.NewBlockStore(db)
	if store.Height() != state.LastBlockHeight {
		return fmt.Errorf("blockstore/consensus heights differ; recovery required")
	}
	if state.LastBlockHeight == 0 || n.validator == nil {
		return nil
	}
	h := n.validator.LastSignState.Height
	if h > state.LastBlockHeight+1 {
		return fmt.Errorf("signing state ahead of committed history")
	}
	if h < store.Base()-1 {
		return fmt.Errorf("signing history unavailable; recovery required")
	}
	for height := state.LastBlockHeight; height >= h && height >= store.Base(); height-- {
		commit := store.LoadSeenCommit(height)
		if commit == nil {
			commit = store.LoadBlockCommit(height)
		}
		if commit == nil {
			return fmt.Errorf("retained commit missing; recovery required")
		}
		for _, sig := range commit.Signatures {
			if len(sig.Signature) > 0 && bytes.Equal(sig.ValidatorAddress, n.validator.Key.Address) {
				saved := n.validator.LastSignState
				if height > h || (height == h && (commit.Round > saved.Round || (commit.Round == saved.Round && (saved.Step < 3 || !bytes.Equal(sig.Signature, saved.Signature))))) {
					return fmt.Errorf("signing state rollback: retained commit proves later or different local signature at height %d", height)
				}
			}
		}
	}
	return nil
}

func clusterSafetyBeforeDB(home string, fd int, o RuntimeOptions, doc genutiltypes.AppGenesis, pv *privval.FilePV, nk *p2p.NodeKey) error {
	if !o.EnableP2P {
		return nil
	}
	vals, err := initialClusterValidators(doc)
	if err != nil {
		return err
	}
	n := &Node{home: home, validator: pv, nodeKey: nk, cluster: true, role: o.EffectiveRole(), initialValidators: vals, genesisChainID: doc.ChainID}
	var key []byte
	if pv != nil {
		key = pv.Key.PubKey.Bytes()
	} else {
		key = nk.PubKey().Bytes()
	}
	_, member := vals[hex.EncodeToString(key)]
	if (o.EffectiveRole() == RoleValidator) != member {
		return fmt.Errorf("node role does not match initial validator set")
	}
	if err := applyClusterConfig(localConfig(home), o, string(nk.ID())); err != nil {
		return err
	}
	state, _, err := n.existingCometState()
	if err != nil {
		return err
	}
	return n.checkClusterSigning(state)
}

func signedHeight(pv *privval.FilePV) int64 {
	if pv == nil {
		return 0
	}
	return pv.LastSignState.Height
}

// Ensure the full-node loader cannot silently fall back to a missing FilePV.
var _ cmttypes.PrivValidator = observerValidator{}
