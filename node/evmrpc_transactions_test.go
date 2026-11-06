//go:build linux

// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0
package node

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

func TestRawEVMReplayProtectionAndSignature(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal("generate disposable signer")
	}
	to := common.HexToAddress("0x1000000000000000000000000000000000000001")
	unsigned := ethtypes.NewTx(&ethtypes.DynamicFeeTx{ChainID: big.NewInt(917001), Nonce: 1, To: &to, Gas: 21000, GasFeeCap: big.NewInt(1_000_000_000), GasTipCap: big.NewInt(1), Value: big.NewInt(1)})
	good, err := ethtypes.SignTx(unsigned, ethtypes.LatestSignerForChainID(big.NewInt(917001)), key)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := good.MarshalBinary()
	if err = validateRawEVMTransaction(raw); err != nil {
		t.Fatal(err)
	}
	badChain, _ := ethtypes.SignNewTx(key, ethtypes.LatestSignerForChainID(big.NewInt(917033)), &ethtypes.DynamicFeeTx{ChainID: big.NewInt(917033), To: &to, Gas: 21000, GasFeeCap: big.NewInt(1), GasTipCap: big.NewInt(1)})
	// Same low 64 bits must not bypass chain validation.
	huge := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(917001))
	hugeTx, _ := ethtypes.SignNewTx(key, ethtypes.LatestSignerForChainID(huge), &ethtypes.DynamicFeeTx{ChainID: huge, To: &to, Gas: 21000, GasFeeCap: big.NewInt(1), GasTipCap: big.NewInt(1)})
	legacy, _ := ethtypes.SignTx(ethtypes.NewTransaction(1, to, big.NewInt(1), 21000, big.NewInt(1), nil), ethtypes.HomesteadSigner{}, key)
	for name, tx := range map[string]*ethtypes.Transaction{"wrong-chain": badChain, "overflow-chain": hugeTx, "zero-signature": unsigned, "unprotected": legacy} {
		t.Run(name, func(t *testing.T) {
			raw, _ := tx.MarshalBinary()
			if validateRawEVMTransaction(raw) == nil {
				t.Fatal("invalid envelope accepted")
			}
		})
	}
	for _, raw := range [][]byte{nil, {0xff}, {0x02, 0xc0}} {
		if validateRawEVMTransaction(raw) == nil {
			t.Fatal("malformed envelope accepted")
		}
	}
}
