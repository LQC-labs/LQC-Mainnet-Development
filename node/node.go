//go:build linux

// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0
package node

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"cosmossdk.io/log/v2"
	"github.com/LQC-labs/LQC-Mainnet-Development/app"
	chainconfig "github.com/LQC-labs/LQC-Mainnet-Development/chain/config"
	cmtdb "github.com/cometbft/cometbft-db"
	abciclient "github.com/cometbft/cometbft/abci/client"
	cmtcfg "github.com/cometbft/cometbft/config"
	cmtjson "github.com/cometbft/cometbft/libs/json"
	cmtlog "github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/libs/protoio"
	cmtnode "github.com/cometbft/cometbft/node"
	"github.com/cometbft/cometbft/p2p"
	"github.com/cometbft/cometbft/privval"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cometbft/cometbft/proxy"
	cmtstate "github.com/cometbft/cometbft/state"
	cmttypes "github.com/cometbft/cometbft/types"
	sdked25519 "github.com/cosmos/cosmos-sdk/crypto/keys/ed25519"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	sdkserver "github.com/cosmos/cosmos-sdk/server"
	genutiltypes "github.com/cosmos/cosmos-sdk/x/genutil/types"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"golang.org/x/sys/unix"
)

// Node owns the home flock, app and every Comet DB. Open only prepares these;
// Start explicitly creates/handshakes/starts CometBFT. Close is idempotent.
type Node struct {
	mu                sync.Mutex
	home              string
	fd                int
	application       *app.App
	config            *cmtcfg.Config
	genesis           *cmttypes.GenesisDoc
	validator         *privval.FilePV
	nodeKey           *p2p.NodeKey
	node              *cmtnode.Node
	databases         []cmtdb.DB
	cancel            context.CancelFunc
	closed            bool
	attempted         bool
	clients           *trackedCreator
	startDone         chan struct{}
	closeDone         chan struct{}
	closeErr          error
	evmRPC            *evmRPCServer
	signer            cmttypes.PrivValidator
	role              NodeRole
	cluster           bool
	initialValidators map[string]int64
	genesisChainID    string
	stateDB           cmtdb.DB
	seedPeers         []string
}

type nodeIdentity struct {
	ChainID            string `json:"chain_id"`
	GenesisSHA256      string `json:"genesis_sha256"`
	ConsensusPublicKey string `json:"consensus_public_key"`
	NodeID             string `json:"node_id"`
	ProfileSHA256      string `json:"profile_sha256,omitempty"`
	Role               string `json:"role,omitempty"`
	ValidatorSetSHA256 string `json:"validator_set_sha256,omitempty"`
}

// Open validates a prepared TEST home and opens its persistent application.
// It NEVER calls NewNode, InitChain, Start, FinalizeBlock or Commit.
func Open(home string) (*Node, error) {
	return openValidated(home, validateDevnetGenesis)
}

func openValidated(home string, validate func(*app.App, []byte, cryptotypes.PubKey) error) (*Node, error) {
	return openConfigured(home, RuntimeOptions{Network: chainconfig.NetworkDevnet, Profile: chainconfig.RuntimeFromDevnet(chainconfig.TestOnlyDevnetConfig()), LocalTestOnly: true}, validate, false)
}

func openConfigured(home string, options RuntimeOptions, validate func(*app.App, []byte, cryptotypes.PubKey) error, explicit bool) (result *Node, err error) {
	fd, err := openDevnetHome(home)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("home already in use: %w", err)
	}
	n := &Node{home: home, fd: fd, role: options.EffectiveRole(), cluster: options.EnableP2P}
	defer func() {
		if recover() != nil {
			result = nil
			err = fmt.Errorf("invalid or inconsistent node state")
		}
		if err != nil {
			_ = n.Close()
		}
	}()
	if err = rejectDBSymlinks(filepath.Join(home, "data")); err != nil {
		return nil, err
	}
	raw, err := readDevnetFile(fd, "config", "genesis.json")
	if err != nil {
		return nil, err
	}
	document, validate, err := runtimeGenesis(raw, options, validate, explicit)
	if err != nil {
		return nil, err
	}
	n.genesisChainID = document.ChainID
	if n.cluster {
		n.initialValidators, err = initialClusterValidators(document)
		if err != nil {
			return nil, err
		}
	}
	n.validator, n.nodeKey, n.signer, err = loadRoleKeys(fd, home, document.ChainID, options.EffectiveRole())
	if err != nil {
		return nil, err
	}
	identity, err := roleIdentity(document.ChainID, raw, n.validator, n.nodeKey, options, document)
	if err != nil {
		return nil, err
	}
	hasIdentity, err := checkRuntimeIdentity(fd, home, identity, signedHeight(n.validator))
	if err != nil {
		return nil, err
	}
	if err := checkRuntimeApplicationIdentity(fd, home, options.Profile); err != nil {
		return nil, err
	}
	if err := clusterSafetyBeforeDB(home, fd, options, document, n.validator, n.nodeKey); err != nil {
		return nil, err
	}
	if err = n.checkCometState(document); err != nil {
		return nil, err
	}
	n.application, err = app.OpenPersistentWithConfig(log.NewNopLogger(), home, options.Profile)
	if err != nil {
		return nil, err
	}
	var public cryptotypes.PubKey
	if n.validator != nil {
		public = &sdked25519.PubKey{Key: n.validator.Key.PubKey.Bytes()}
	}
	if err = validate(n.application, raw, public); err != nil {
		return nil, err
	}
	// Exact-height checks apply to a clean normal shutdown. Recovery of an
	// interrupted commit is deliberately rejected pending a separate procedure.
	if err = n.checkAppHeight(); err != nil {
		return nil, err
	}
	n.genesis, err = document.ToGenesisDoc()
	if err != nil {
		return nil, err
	}
	if !hasIdentity {
		content, marshalErr := json.Marshal(identity)
		if marshalErr != nil {
			return nil, marshalErr
		}
		data, openErr := unix.Openat(fd, "data", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if openErr != nil {
			return nil, openErr
		}
		writeErr := writePrivateFile(data, "node.identity.json", content)
		syncErr := unix.Fsync(data)
		unix.Close(data)
		if writeErr != nil {
			return nil, writeErr
		}
		if syncErr != nil {
			return nil, syncErr
		}
	}
	n.config = localConfig(home)
	if options.CometRPCListen != "" {
		n.config.RPC.ListenAddress = "tcp://" + options.CometRPCListen
	}
	if options.P2PListen != "" {
		n.config.P2P.ListenAddress = "tcp://" + options.P2PListen
	}
	if err := applyClusterConfig(n.config, options, string(n.nodeKey.ID())); err != nil {
		return nil, err
	}
	n.seedPeers, _ = localPeerList(options.Seeds)
	if err := n.config.ValidateBasic(); err != nil {
		return nil, err
	}
	return n, nil
}

func localConfig(home string) *cmtcfg.Config {
	cfg := cmtcfg.DefaultConfig().SetRoot(home)
	cfg.DBBackend = "goleveldb"
	cfg.RPC.ListenAddress = "tcp://127.0.0.1:26657"
	cfg.RPC.GRPCListenAddress = ""
	cfg.RPC.Unsafe = false
	cfg.RPC.CORSAllowedOrigins = nil
	cfg.P2P.ListenAddress = "tcp://127.0.0.1:26656"
	cfg.P2P.ExternalAddress = ""
	cfg.P2P.Seeds = ""
	cfg.P2P.PersistentPeers = ""
	cfg.P2P.PexReactor = false
	cfg.P2P.SeedMode = false
	cfg.P2P.MaxNumInboundPeers = 0
	cfg.P2P.MaxNumOutboundPeers = 0
	cfg.StateSync.Enable = false
	cfg.Instrumentation.Prometheus = false
	cfg.RPC.PprofListenAddress = ""
	cfg.Consensus.CreateEmptyBlocks = true
	return cfg
}

// Start is the ONLY method that starts consensus. It is intentionally never
// invoked by normal unit tests; runtime tests require explicit opt-in.
// Caller must Close even when context cancels.
func (n *Node) Start(ctx context.Context) (err error) {
	n.mu.Lock()
	if n.closed || n.attempted {
		n.mu.Unlock()
		return fmt.Errorf("node closed or start already attempted")
	}
	if ctx == nil || ctx.Err() != nil {
		n.mu.Unlock()
		return fmt.Errorf("live context required")
	}
	n.attempted = true
	runtimeContext, cancel := context.WithCancel(ctx)
	n.cancel = cancel
	n.startDone = make(chan struct{})
	finished := n.startDone
	n.mu.Unlock()
	// Start exclusively owns resource fields until finished closes. Close can
	// cancel immediately, then waits for that ownership transfer WITHOUT mu.
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("node startup failed")
		}
		close(finished)
		if err != nil {
			err = errors.Join(err, n.Close())
		}
	}()
	n.clients = &trackedCreator{ClientCreator: proxy.NewLocalClientCreator(sdkserver.NewCometABCIWrapper(n.application.SDK))}
	provider := func(dbctx *cmtcfg.DBContext) (cmtdb.DB, error) {
		database, openErr := cmtcfg.DefaultDBProvider(dbctx)
		if openErr != nil {
			return nil, openErr
		}
		wrapped := &closingDB{DB: database}
		n.databases = append(n.databases, wrapped)
		if dbctx.ID == "state" {
			n.stateDB = wrapped
		}
		return wrapped, nil
	}
	n.node, err = cmtnode.NewNodeWithContext(runtimeContext, n.config, n.signer, n.nodeKey,
		n.clients,
		func() (*cmttypes.GenesisDoc, error) { return n.genesis, nil }, provider,
		cmtnode.DefaultMetricsProvider(n.config.Instrumentation), cmtlog.NewNopLogger())
	if err != nil {
		return err
	}
	if n.cluster {
		state, loadErr := cmtstate.NewStore(n.stateDB, cmtstate.StoreOptions{}).Load()
		if loadErr != nil {
			return loadErr
		}
		if state.IsEmpty() {
			return fmt.Errorf("cluster InitChain did not initialize consensus state")
		}
		if err := n.validateClusterSet(state); err != nil {
			return err
		}
	}
	if err = n.node.Start(); err != nil {
		return err
	}
	if len(n.seedPeers) > 0 {
		if err := n.node.Switch().DialPeersAsync(n.seedPeers); err != nil {
			return err
		}
	}
	if err = runtimeContext.Err(); err != nil {
		return err
	}
	// Parent cancellation also performs ordered resource cleanup. Close cancels
	// this watcher, which may safely call the idempotent Close again.
	go func() { <-runtimeContext.Done(); _ = n.Close() }()
	return nil
}

func (n *Node) Close() error {
	n.mu.Lock()
	if n.closeDone != nil {
		done := n.closeDone
		n.mu.Unlock()
		<-done
		n.mu.Lock()
		err := n.closeErr
		n.mu.Unlock()
		return err
	}
	n.closed = true
	n.closeDone = make(chan struct{})
	done, started, cancel := n.closeDone, n.startDone, n.cancel
	n.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if started != nil {
		<-started
	}
	err := n.releaseResources()
	n.mu.Lock()
	n.closeErr = err
	close(done)
	n.mu.Unlock()
	return err
}

// Called by exactly one closer after the startup resource owner has finished.
// No lifecycle mutex is held across Comet/app shutdown or DB close operations.
func (n *Node) releaseResources() error {
	var err error
	// Stop admitting requests before stopping consensus or closing the app DB.
	if n.evmRPC != nil {
		err = errors.Join(err, n.evmRPC.Close())
	}
	if n.node != nil {
		if n.node.IsRunning() {
			err = errors.Join(err, n.node.Stop())
			n.node.Wait()
		} else {
			n.node.OnStop()
		}
	}
	if n.clients != nil {
		for _, client := range n.clients.clients {
			if client.IsRunning() {
				err = errors.Join(err, client.Stop())
			}
		}
	}
	// Comet may already have closed some DBs. The tracked wrappers below make
	// closure idempotent, including constructor failures before Node is returned.
	for _, database := range n.databases {
		err = errors.Join(err, database.Close())
	}
	if n.application != nil {
		err = errors.Join(err, n.application.Close())
	}
	if n.fd >= 0 {
		err = errors.Join(err, unix.Flock(n.fd, unix.LOCK_UN), unix.Close(n.fd))
		n.fd = -1
	}
	return err
}

func loadRuntimeKeys(fd int, home string) (*privval.FilePV, *p2p.NodeKey, error) {
	return loadRuntimeKeysForChain(fd, home, chainconfig.TestOnlyDevnetConfig().Chain.CosmosChainID)
}

func loadRuntimeKeysForChain(fd int, home string, chainID string) (*privval.FilePV, *p2p.NodeKey, error) {
	raw, err := readDevnetFile(fd, "config", "priv_validator_key.json")
	if err != nil {
		return nil, nil, err
	}
	var key privval.FilePVKey
	if cmtjson.Unmarshal(raw, &key) != nil || key.PrivKey == nil || key.PrivKey.Type() != "ed25519" || len(key.PrivKey.Bytes()) != 64 || key.PubKey == nil || !key.PrivKey.PubKey().Equals(key.PubKey) || !bytes.Equal(key.Address, key.PubKey.Address()) {
		return nil, nil, fmt.Errorf("invalid stored consensus key")
	}
	raw, err = readDevnetFile(fd, "config", "node_key.json")
	if err != nil {
		return nil, nil, err
	}
	var nodeKey p2p.NodeKey
	if cmtjson.Unmarshal(raw, &nodeKey) != nil || nodeKey.PrivKey == nil || nodeKey.PrivKey.Type() != "ed25519" || len(nodeKey.PrivKey.Bytes()) != 64 || nodeKey.PubKey().Equals(key.PubKey) {
		return nil, nil, fmt.Errorf("invalid independent node key")
	}
	raw, err = readDevnetFile(fd, "data", "priv_validator_state.json")
	if err != nil {
		return nil, nil, err
	}
	var state privval.FilePVLastSignState
	if cmtjson.Unmarshal(raw, &state) != nil {
		return nil, nil, fmt.Errorf("invalid signing state encoding")
	}
	if err = checkSigningStateForChain(key, state, chainID); err != nil {
		return nil, nil, err
	}
	pv := privval.NewFilePV(key.PrivKey, filepath.Join(home, "config/priv_validator_key.json"), filepath.Join(home, "data/priv_validator_state.json"))
	// Preserve NewFilePV's private filePath fields; never use LoadOrGen or Reset.
	pv.LastSignState.Height, pv.LastSignState.Round, pv.LastSignState.Step = state.Height, state.Round, state.Step
	pv.LastSignState.Signature, pv.LastSignState.SignBytes = state.Signature, state.SignBytes
	return pv, &nodeKey, nil
}

func checkSigningState(key privval.FilePVKey, state privval.FilePVLastSignState) error {
	return checkSigningStateForChain(key, state, chainconfig.TestOnlyDevnetConfig().Chain.CosmosChainID)
}

func checkSigningStateForChain(key privval.FilePVKey, state privval.FilePVLastSignState, chainID string) error {
	if chainID == "" {
		return fmt.Errorf("explicit signing chain required")
	}
	if state.Height < 0 || state.Round < 0 || state.Step < 0 || state.Step > 3 {
		return fmt.Errorf("invalid signing HRS")
	}
	if state.Height == 0 {
		if state.Round != 0 || state.Step != 0 || len(state.Signature) != 0 || len(state.SignBytes) != 0 {
			return fmt.Errorf("invalid unsigned state")
		}
		return nil
	}
	if state.Step == 0 || !key.PubKey.VerifySignature(state.SignBytes, state.Signature) {
		return fmt.Errorf("invalid signing state signature")
	}
	reader := bytes.NewReader(state.SignBytes)
	decoder := protoio.NewDelimitedReader(reader, 16*1024*1024)
	var chain string
	var height, round int64
	if state.Step == 1 {
		var proposal cmtproto.CanonicalProposal
		if _, err := decoder.ReadMsg(&proposal); err != nil {
			return fmt.Errorf("invalid signed proposal")
		}
		if proposal.Type != cmtproto.ProposalType {
			return fmt.Errorf("wrong signing proposal type")
		}
		chain, height, round = proposal.ChainID, proposal.Height, proposal.Round
	} else {
		var vote cmtproto.CanonicalVote
		if _, err := decoder.ReadMsg(&vote); err != nil {
			return fmt.Errorf("invalid signed vote")
		}
		if int32(vote.Type) != int32(state.Step-1) {
			return fmt.Errorf("wrong signing vote type")
		}
		chain, height, round = vote.ChainID, vote.Height, vote.Round
	}
	if reader.Len() != 0 || chain != chainID || height != state.Height || round != int64(state.Round) {
		return fmt.Errorf("signing state chain/HRS mismatch")
	}
	return nil
}

func (n *Node) existingCometState() (state cmtstate.State, storedGenesis []byte, err error) {
	path := filepath.Join(n.home, "data/state.db")
	if _, statErr := os.Lstat(path); os.IsNotExist(statErr) {
		return state, nil, nil
	}
	if err = rejectDBSymlinks(path); err != nil {
		return state, nil, err
	}
	database, err := cmtdb.NewGoLevelDBWithOpts("state", filepath.Join(n.home, "data"), &opt.Options{ReadOnly: true, ErrorIfMissing: true})
	if err != nil {
		return state, nil, err
	}
	defer database.Close()
	state, err = cmtstate.NewStore(database, cmtstate.StoreOptions{}).Load()
	if err != nil {
		return state, nil, err
	}
	storedGenesis, err = database.Get([]byte("genesisDoc"))
	return state, storedGenesis, err
}

func (n *Node) checkCometState(document genutiltypes.AppGenesis) error {
	state, storedGenesis, err := n.existingCometState()
	if err != nil {
		return err
	}
	if len(storedGenesis) > 0 {
		var stored cmttypes.GenesisDoc
		if cmtjson.Unmarshal(storedGenesis, &stored) != nil {
			return fmt.Errorf("stored Comet Genesis mismatch")
		}
		expected, convertErr := document.ToGenesisDoc()
		if convertErr != nil {
			return convertErr
		}
		expectedJSON, marshalErr := cmtjson.Marshal(expected)
		if marshalErr != nil {
			return marshalErr
		}
		storedJSON, marshalErr := cmtjson.Marshal(&stored)
		if marshalErr != nil {
			return marshalErr
		}
		if !bytes.Equal(storedJSON, expectedJSON) {
			return fmt.Errorf("stored Comet Genesis mismatch")
		}
	}
	if n.cluster {
		return n.checkClusterSigning(state)
	}
	if !state.IsEmpty() {
		if state.ChainID != document.ChainID || state.Validators == nil || state.Validators.Size() != 1 || !state.Validators.Validators[0].PubKey.Equals(n.validator.Key.PubKey) || state.Validators.Validators[0].VotingPower <= 0 {
			return fmt.Errorf("stored Comet chain/validator mismatch")
		}
	}
	return nil
}

func (n *Node) checkAppHeight() error {
	state, _, err := n.existingCometState()
	if err != nil {
		return err
	}
	height := n.application.SDK.LastBlockHeight()
	if state.LastBlockHeight != height {
		return fmt.Errorf("application/Comet heights differ; recovery required")
	}
	if height > 0 && !bytes.Equal(state.AppHash, n.application.SDK.LastCommitID().Hash) {
		return fmt.Errorf("application/Comet app hashes differ; recovery required")
	}
	if n.cluster {
		if err := n.checkClusterSigning(state); err != nil {
			return err
		}
		if n.validator == nil {
			return nil
		}
		signed := n.validator.LastSignState.Height
		if height == 0 && signed != 0 || signed > height+1 {
			return fmt.Errorf("signing state inconsistent with committed height")
		}
		return nil
	}
	signed := n.validator.LastSignState.Height
	if height == 0 && signed != 0 || height > 0 && (signed < height || signed > height+1) {
		return fmt.Errorf("signing state inconsistent with committed height")
	}
	return nil
}

func rejectDBSymlinks(path string) error {
	return filepath.WalkDir(path, func(_ string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink in node DB forbidden")
		}
		return nil
	})
}

type closingDB struct {
	cmtdb.DB
	once sync.Once
	err  error
}

func (db *closingDB) Close() error { db.once.Do(func() { db.err = db.DB.Close() }); return db.err }

type trackedCreator struct {
	proxy.ClientCreator
	clients []abciclient.Client
}

func (creator *trackedCreator) NewABCIClient() (abciclient.Client, error) {
	client, err := creator.ClientCreator.NewABCIClient()
	if err == nil {
		creator.clients = append(creator.clients, client)
	}
	return client, err
}
