//go:build linux

// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0
package node

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"cosmossdk.io/log/v2"
	cmtlocal "github.com/cometbft/cometbft/rpc/client/local"
	"github.com/cosmos/cosmos-sdk/client"
	sdkserver "github.com/cosmos/cosmos-sdk/server"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	evmmempool "github.com/cosmos/evm/mempool"
	"github.com/cosmos/evm/rpc/backend"
	rpctypes "github.com/cosmos/evm/rpc/types"
	evmflags "github.com/cosmos/evm/server/flags"
	evmtypes "github.com/cosmos/evm/x/vm/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	gethrpc "github.com/ethereum/go-ethereum/rpc"
	"github.com/spf13/viper"
)

// StartEVMRPC opts a running node into the local HTTP query and signed-transaction surface.
// Only a numeric IPv4 loopback address is allowed (port 0 selects a free port).
// It uses the pinned EVM backend over Comet's in-process client: no separate DB,
// external endpoint, wallet, websocket, stream or separate EVM indexer is created.
// Close owns cleanup, including startup failures and parent cancellation.
func (n *Node) StartEVMRPC(ctx context.Context, address string) (string, error) {
	if ctx == nil || ctx.Err() != nil {
		return "", fmt.Errorf("live RPC context required")
	}
	if err := validateEVMRPCAddress(address); err != nil {
		return "", err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed || n.evmRPC != nil || n.startDone == nil {
		return "", fmt.Errorf("running node and unused RPC required")
	}
	select {
	case <-n.startDone:
	default:
		return "", fmt.Errorf("node startup not complete")
	}
	if n.node == nil || !n.node.IsRunning() {
		return "", fmt.Errorf("running node required")
	}
	if err := n.application.Profile.Validate(); err != nil {
		return "", err
	}
	chainID := n.application.Profile.Chain.EVMChainID
	if err := validateEVMRPCIdentity(n.genesis.ChainID, chainID, evmtypes.GetEthChainConfig().ChainID); err != nil {
		return "", err
	}
	v := viper.New()
	v.Set(evmflags.EVMChainID, chainID)
	srvCtx := &sdkserver.Context{Viper: v, Config: n.config, Logger: log.NewNopLogger()}
	a := n.application.SDK
	clientCtx := client.Context{}.WithChainID(n.genesis.ChainID).WithHomeDir(n.home).
		WithCodec(a.AppCodec()).WithInterfaceRegistry(a.InterfaceRegistry()).
		WithTxConfig(a.GetTxConfig()).WithAccountRetriever(authtypes.AccountRetriever{}).
		WithClient(cmtlocal.New(n.node)).WithCmdContext(ctx)
	pool, ok := a.EVMMempool.(*evmmempool.Mempool)
	if !ok {
		return "", fmt.Errorf("persistent EVM mempool required")
	}
	b := backend.NewBackend(srvCtx, clientCtx, nil, pool)
	if b.EvmChainID.Uint64() != chainID {
		return "", fmt.Errorf("RPC backend chain identity mismatch")
	}
	rpc, err := openEVMRPC(ctx, address, &evmReadAPI{backend: b})
	if err != nil {
		return "", err
	}
	n.evmRPC = rpc
	return rpc.address, nil
}

func validateEVMRPCIdentity(cosmos string, evm uint64, runtime *big.Int) error {
	if cosmos != "lqc-devnet-test-1" || evm != 917001 || runtime == nil || runtime.Cmp(new(big.Int).SetUint64(evm)) != 0 {
		return fmt.Errorf("RPC Devnet chain identity mismatch")
	}
	return nil
}

func validateEVMRPCAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host != "127.0.0.1" {
		return fmt.Errorf("RPC must bind numeric IPv4 loopback")
	}
	value, err := strconv.Atoi(port)
	if err != nil || value < 0 || value > 65535 {
		return fmt.Errorf("invalid RPC port")
	}
	return nil
}

// Every exported method delegates state/height semantics to the pinned backend.
// Registering this narrow adapter avoids exposing upstream signing/debug APIs.
type evmReadAPI struct{ backend *backend.Backend }

func (a *evmReadAPI) ChainId(ctx context.Context) (*hexutil.Big, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	// Use upstream's committed height and on-chain hydrated chain config, without
	// its configured-ID fallback when a state query fails.
	height, err := a.backend.BlockNumber(ctx)
	if err != nil {
		return nil, err
	}
	config := a.backend.ChainConfig()
	if config == nil || config.ChainID == nil || config.ChainID.Cmp(big.NewInt(917001)) != 0 {
		return nil, fmt.Errorf("RPC runtime chain identity mismatch")
	}
	if !config.IsEIP155(new(big.Int).SetUint64(uint64(height))) {
		return nil, fmt.Errorf("chain not synced beyond EIP-155 fork")
	}
	return (*hexutil.Big)(new(big.Int).Set(config.ChainID)), nil
}
func (a *evmReadAPI) BlockNumber(ctx context.Context) (hexutil.Uint64, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return a.backend.BlockNumber(ctx)
}
func (a *evmReadAPI) GetBalance(ctx context.Context, address common.Address, block rpctypes.BlockNumberOrHash) (*hexutil.Big, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return a.backend.GetBalance(ctx, address, block)
}
func (a *evmReadAPI) GetTransactionCount(ctx context.Context, address common.Address, block rpctypes.BlockNumberOrHash) (*hexutil.Uint64, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	number, err := a.backend.BlockNumberFromComet(ctx, block)
	if err != nil {
		return nil, err
	}
	return a.backend.GetTransactionCount(ctx, address, number)
}

type evmRPCServer struct {
	address   string
	http      *http.Server
	rpc       *gethrpc.Server
	cancel    context.CancelFunc
	done      chan struct{}
	serveErr  error
	closeOnce sync.Once
	closeErr  error
}

func openEVMRPC(parent context.Context, address string, api *evmReadAPI) (*evmRPCServer, error) {
	if err := validateEVMRPCAddress(address); err != nil {
		return nil, err
	}
	rpc := gethrpc.NewServer()
	rpc.SetBatchLimits(16, 2*1024*1024)
	rpc.SetHTTPBodyLimit(1024 * 1024)
	if err := rpc.RegisterName("eth", api); err != nil {
		rpc.Stop()
		return nil, err
	}
	listener, err := net.Listen("tcp4", address)
	if err != nil {
		rpc.Stop()
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	result := &evmRPCServer{address: listener.Addr().String(), rpc: rpc, cancel: cancel, done: make(chan struct{})}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, e := net.SplitHostPort(r.Host)
		if e != nil {
			host = r.Host
		}
		if (host != "127.0.0.1" && host != "localhost") || r.Header.Get("Origin") != "" {
			http.Error(w, "local RPC requests only", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != "/" {
			http.Error(w, "POST / required", http.StatusMethodNotAllowed)
			return
		}
		rpc.ServeHTTP(w, r)
	})
	result.http = &http.Server{Handler: handler, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 8192, BaseContext: func(net.Listener) context.Context { return ctx }}
	go func() {
		err := result.http.Serve(listener)
		if !errors.Is(err, http.ErrServerClosed) {
			result.serveErr = err
		}
		close(result.done)
	}()
	go func() {
		select {
		case <-ctx.Done():
		case <-result.done:
		}
		_ = result.Close()
	}()
	return result, nil
}

func (s *evmRPCServer) Close() error {
	s.closeOnce.Do(func() {
		s.cancel()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.closeErr = s.http.Shutdown(ctx)
		if s.closeErr != nil {
			s.closeErr = errors.Join(s.closeErr, s.http.Close())
		}
		s.rpc.Stop()
		<-s.done
		s.closeErr = errors.Join(s.closeErr, s.serveErr)
	})
	return s.closeErr
}
