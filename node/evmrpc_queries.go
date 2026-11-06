//go:build linux

// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0
package node

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"time"

	rpctypes "github.com/cosmos/evm/rpc/types"
	evmtypes "github.com/cosmos/evm/x/vm/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth/filters"
	gethrpc "github.com/ethereum/go-ethereum/rpc"
)

const rpcGasCap uint64 = 10_000_000
const rpcLogBlockCap int64 = 128
const rpcLogResultCap = 1024

type rpcInputError string

func (e rpcInputError) Error() string  { return string(e) }
func (e rpcInputError) ErrorCode() int { return -32602 }

func (a *evmReadAPI) GasPrice(ctx context.Context) (*hexutil.Big, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return a.backend.GasPrice(ctx)
}

// ethers v6 getFeeData requests this alongside gasPrice and the latest block.
func (a *evmReadAPI) MaxPriorityFeePerGas(ctx context.Context) (*hexutil.Big, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	head, err := a.backend.CurrentHeader(ctx)
	if err != nil {
		return nil, err
	}
	tip, err := a.backend.SuggestGasTipCap(ctx, head.BaseFee)
	return (*hexutil.Big)(tip), err
}

// No state overrides or pending-state simulation are advertised. Upstream's
// pending estimate uses latest committed state, without applying pool entries.
func (a *evmReadAPI) EstimateGas(ctx context.Context, args evmtypes.TransactionArgs, block *rpctypes.BlockNumberOrHash) (hexutil.Uint64, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if args.Gas != nil && uint64(*args.Gas) > rpcGasCap {
		return 0, rpcInputError("gas exceeds local RPC cap")
	}
	if block != nil {
		if _, err := a.backend.BlockNumberFromComet(ctx, *block); err != nil {
			return 0, err
		}
	}
	return a.backend.EstimateGas(ctx, args, block, nil)
}

func (a *evmReadAPI) GetBlockByNumber(ctx context.Context, selector gethrpc.BlockNumber, full bool) (map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	number := rpctypes.BlockNumber(selector)
	latest, err := a.backend.BlockNumber(ctx)
	if err != nil {
		return nil, err
	}
	if number > rpctypes.BlockNumber(latest) {
		return nil, nil
	}
	// This node has no synthetic pending block: pending resolves to the same
	// committed head as the pinned backend. No uncommitted transaction is implied.
	if number == rpctypes.EthPendingBlockNumber {
		number = rpctypes.EthLatestBlockNumber
	}
	block, err := a.backend.CometBlockByNumber(ctx, number)
	if err != nil {
		return nil, err
	}
	if block == nil || block.Block == nil {
		return nil, nil
	}
	results, err := a.backend.RPCClient.BlockResults(ctx, &block.Block.Height)
	if err != nil {
		return nil, err
	}
	return a.backend.RPCBlockFromCometBlock(ctx, block, results, full)
}

func (a *evmReadAPI) GetTransactionByHash(ctx context.Context, hash common.Hash) (*rpctypes.RPCTransaction, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	// Upstream falls back to pending on ANY index error. Only not-found may do
	// so here; cancellation, DB and index failures must remain visible.
	if _, err := a.backend.GetTxByEthHash(ctx, hash); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !strings.Contains(err.Error(), "ethereum tx not found") {
			return nil, err
		}
		if a.pool != nil {
			if tx := a.pool.GetTxPool().Get(hash); tx != nil {
				msg := new(evmtypes.MsgEthereumTx)
				msg.FromEthereumTx(tx)
				return rpctypes.NewTransactionFromMsg(msg, common.Hash{}, 0, 0, 0, nil, a.backend.ChainConfig()), nil
			}
		}
		// Check Comet's Cosmos pool too, without upstream's error-to-null fallback.
		txs, err := a.backend.PendingTransactions(ctx)
		if err != nil {
			return nil, err
		}
		for _, tx := range txs {
			msg, err := evmtypes.UnwrapEthereumMsg(tx, hash)
			if err == nil && msg.Hash() == hash {
				return rpctypes.NewTransactionFromMsg(msg, common.Hash{}, 0, 0, 0, nil, a.backend.ChainConfig()), nil
			}
		}
		return nil, nil
	}
	return a.backend.GetTransactionByHash(ctx, hash)
}

func validateLogCriteria(q filters.FilterCriteria) error {
	if q.BlockHash != nil && (q.FromBlock != nil || q.ToBlock != nil) {
		return rpcInputError("blockHash conflicts with block range")
	}
	if len(q.Addresses) > 64 || len(q.Topics) > 4 {
		return rpcInputError("log filter exceeds local limits")
	}
	for _, topics := range q.Topics {
		if len(topics) > 64 {
			return rpcInputError("too many topic alternatives")
		}
	}
	return nil
}
func logHeight(n *big.Int, latest int64) (int64, error) {
	if n == nil {
		return latest, nil
	}
	if !n.IsInt64() {
		return 0, rpcInputError("invalid log block number")
	}
	h := n.Int64()
	if h == int64(rpctypes.EthLatestBlockNumber) || h == int64(rpctypes.EthSafeBlockNumber) || h == int64(rpctypes.EthFinalizedBlockNumber) {
		return latest, nil
	}
	if h < 0 {
		return 0, rpcInputError("pending log queries are not supported")
	}
	if h == 0 {
		return 1, nil
	}
	return h, nil
}
func matchesLog(l *ethtypes.Log, q filters.FilterCriteria) bool {
	if len(q.Addresses) > 0 {
		found := false
		for _, a := range q.Addresses {
			found = found || l.Address == a
		}
		if !found {
			return false
		}
	}
	if len(q.Topics) > len(l.Topics) {
		return false
	}
	for i, alts := range q.Topics {
		if len(alts) == 0 {
			continue
		}
		found := false
		for _, v := range alts {
			found = found || l.Topics[i] == v
		}
		if !found {
			return false
		}
	}
	return true
}

// Bounded committed-log scan, using upstream receipt construction to preserve
// transaction hashes, EVM transaction indices and global log indices exactly.
func (a *evmReadAPI) GetLogs(ctx context.Context, q filters.FilterCriteria) ([]*ethtypes.Log, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out := make([]*ethtypes.Log, 0)
	if err := validateLogCriteria(q); err != nil {
		return nil, err
	}
	latest, err := a.backend.BlockNumber(ctx)
	if err != nil {
		return nil, err
	}
	from, err := logHeight(q.FromBlock, int64(latest))
	if err != nil {
		return nil, err
	}
	to, err := logHeight(q.ToBlock, int64(latest))
	if err != nil {
		return nil, err
	}
	if q.BlockHash != nil {
		b, e := a.backend.CometBlockByHash(ctx, *q.BlockHash)
		if e != nil {
			return nil, e
		}
		if b == nil || b.Block == nil {
			return nil, fmt.Errorf("block not found")
		}
		from = b.Block.Height
		to = from
	}
	if from > to {
		return nil, rpcInputError("fromBlock exceeds toBlock")
	}
	if to-from >= rpcLogBlockCap {
		return nil, rpcInputError("log range exceeds 128 blocks")
	}
	if to > int64(latest) {
		to = int64(latest)
	}
	for h := from; h <= to; h++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		block, err := a.backend.CometBlockByNumber(ctx, rpctypes.BlockNumber(h))
		if err != nil {
			return nil, err
		}
		if block == nil || block.Block == nil {
			return nil, fmt.Errorf("log block unavailable")
		}
		results, err := a.backend.RPCClient.BlockResults(ctx, &h)
		if err != nil {
			return nil, err
		}
		msgs := a.backend.EthMsgsFromCometBlock(ctx, block, results)
		receipts, err := a.backend.ReceiptsFromCometBlock(ctx, block, results, msgs)
		if err != nil {
			return nil, err
		}
		for _, receipt := range receipts {
			for _, l := range receipt.Logs {
				if matchesLog(l, q) {
					if len(out) >= rpcLogResultCap {
						return nil, rpcInputError("log result exceeds 1024 entries")
					}
					out = append(out, l)
				}
			}
		}
	}
	return out, nil
}
