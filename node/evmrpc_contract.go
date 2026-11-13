//go:build linux

// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0
package node

import (
	"context"
	"fmt"
	"time"

	rpctypes "github.com/cosmos/evm/rpc/types"
	evmtypes "github.com/cosmos/evm/x/vm/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

// GetCode and GetStorageAt read committed EVM state through the same backend
// and block selector semantics as the existing balance/nonce queries.
func (a *evmReadAPI) GetCode(ctx context.Context, address common.Address, block rpctypes.BlockNumberOrHash) (hexutil.Bytes, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return a.backend.GetCode(ctx, address, block)
}

func (a *evmReadAPI) GetStorageAt(ctx context.Context, address common.Address, key string, block rpctypes.BlockNumberOrHash) (hexutil.Bytes, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return a.backend.GetStorageAt(ctx, address, key, block)
}

// Call uses pinned DoCall's gas cap, EVM timeout and revert translation. State
// writes run in its simulation cache and are never committed. No wallet,
// signing service, state override or external endpoint is introduced.
func (a *evmReadAPI) Call(ctx context.Context, args evmtypes.TransactionArgs, block rpctypes.BlockNumberOrHash) (hexutil.Bytes, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	number, err := a.backend.BlockNumberFromComet(ctx, block)
	if err != nil {
		return nil, err
	}
	result, err := a.backend.DoCall(ctx, args, number, nil)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, fmt.Errorf("missing EVM call result")
	}
	return hexutil.Bytes(result.Ret), nil
}
