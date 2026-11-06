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
)

// SendRawTransaction accepts client-signed native EVM transactions only. Keys
// remain with the caller. The pinned backend converts the envelope to
// MsgEthereumTx and inserts it into the existing app-side EVM mempool; the
// existing proposal/ante/FinalizeBlock/Commit path owns execution and fees.
func (a *evmReadAPI) SendRawTransaction(ctx context.Context, data hexutil.Bytes) (common.Hash, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := validateRawEVMTransaction(data); err != nil {
		return common.Hash{}, err
	}
	if _, err := a.ChainId(ctx); err != nil {
		return common.Hash{}, err
	}
	return a.backend.SendRawTransaction(ctx, data)
}

func validateRawEVMTransaction(data []byte) error {
	var tx ethtypes.Transaction
	if err := tx.UnmarshalBinary(data); err != nil {
		return fmt.Errorf("invalid raw EVM transaction: %w", err)
	}
	// Compare the complete integer (not Uint64), and require replay protection.
	if !tx.Protected() || tx.ChainId().Cmp(big.NewInt(917001)) != 0 {
		return fmt.Errorf("replay-protected EVM chain ID 917001 required")
	}
	if _, err := ethtypes.Sender(ethtypes.LatestSignerForChainID(big.NewInt(917001)), &tx); err != nil {
		return fmt.Errorf("invalid EVM transaction signature: %w", err)
	}
	return nil
}

// GetTransactionReceipt uses the existing Comet transaction index and pinned
// receipt construction. An unindexed/pending hash returns null immediately:
// upstream's receipt method otherwise sleeps/retries for up to 51 seconds,
// including after context cancellation. Other lookup failures remain errors.
func (a *evmReadAPI) GetTransactionReceipt(ctx context.Context, hash common.Hash) (map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	indexed, err := a.backend.GetTxByEthHash(ctx, hash)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if strings.Contains(err.Error(), "ethereum tx not found") {
			return nil, nil
		}
		return nil, err
	}
	block, err := a.backend.CometBlockByNumber(ctx, rpctypes.BlockNumber(indexed.Height))
	if err != nil {
		return nil, err
	}
	if block == nil || block.Block == nil || uint64(indexed.TxIndex) >= uint64(len(block.Block.Txs)) {
		return nil, fmt.Errorf("receipt transaction index outside committed block")
	}
	tx, err := a.backend.ClientCtx.TxConfig.TxDecoder()(block.Block.Txs[indexed.TxIndex])
	if err != nil {
		return nil, err
	}
	if uint64(indexed.MsgIndex) >= uint64(len(tx.GetMsgs())) {
		return nil, fmt.Errorf("receipt message index outside transaction")
	}
	msg, ok := tx.GetMsgs()[indexed.MsgIndex].(*evmtypes.MsgEthereumTx)
	if !ok {
		return nil, fmt.Errorf("receipt requires EVM transaction")
	}
	results, err := a.backend.RPCClient.BlockResults(ctx, &indexed.Height)
	if err != nil {
		return nil, err
	}
	receipts, err := a.backend.ReceiptsFromCometBlock(ctx, block, results, []*evmtypes.MsgEthereumTx{msg})
	if err != nil {
		return nil, err
	}
	if len(receipts) != 1 {
		return nil, fmt.Errorf("expected one EVM receipt")
	}
	ethTx := msg.AsTransaction()
	var signer ethtypes.Signer = ethtypes.FrontierSigner{}
	if ethTx.Protected() {
		signer = ethtypes.LatestSignerForChainID(ethTx.ChainId())
	}
	from, err := msg.GetSenderLegacy(signer)
	if err != nil {
		return nil, err
	}
	return rpctypes.RPCMarshalReceipt(receipts[0], ethTx, from)
}
