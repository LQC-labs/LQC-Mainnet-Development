package mvpsafety

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
)

type ReadOnlyChain interface {
	Endpoint() string
	ChainID(context.Context) (uint64, error)
	Receipt(context.Context, common.Hash) (*ethtypes.Receipt, error)
	Destination(context.Context, common.Hash) (common.Address, error)
	Code(context.Context, common.Address) ([]byte, error)
	Call(context.Context, common.Address, []byte) ([]byte, error)
}

func runtime(a Artifact, values map[string]common.Address) ([]byte, error) {
	raw, e := hex.DecodeString(strings.TrimPrefix(a.DeployedBytecode, "0x"))
	if e != nil {
		return nil, e
	}
	for id, refs := range a.ImmutableReferences {
		name := a.ImmutableNames[id]
		value, ok := values[name]
		if !ok {
			return nil, fmt.Errorf("missing immutable")
		}
		for _, r := range refs {
			if r.Length != 32 || r.Start < 0 || r.Start+32 > len(raw) {
				return nil, fmt.Errorf("invalid immutable reference")
			}
			copy(raw[r.Start:r.Start+32], common.LeftPadBytes(value.Bytes(), 32))
		}
	}
	return raw, nil
}
func VerifyPair(ctx context.Context, c Config, chain ReadOnlyChain, factory, tokenA, tokenB common.Address, hash common.Hash) (common.Address, error) {
	fail := func(e error) (common.Address, error) { return common.Address{}, e }
	if e := c.Validate(); e != nil {
		return fail(e)
	}
	if e := ctx.Err(); e != nil {
		return fail(e)
	}
	if chain.Endpoint() != c.Profile.Network.RPCURLs[0] {
		return fail(fmt.Errorf("external/mismatched RPC"))
	}
	for _, a := range []common.Address{factory, tokenA, tokenB} {
		if _, e := LocalAddress(a.Hex()); e != nil {
			return fail(e)
		}
	}
	if tokenA == tokenB {
		return fail(fmt.Errorf("identical tokens"))
	}
	id, e := chain.ChainID(ctx)
	if e != nil || id != EVMID {
		return fail(fmt.Errorf("observed chain mismatch"))
	}
	receipt, e := chain.Receipt(ctx, hash)
	if e != nil || receipt == nil || receipt.Status != 1 || receipt.TxHash != hash || receipt.ContractAddress != (common.Address{}) || receipt.BlockNumber == nil || receipt.BlockNumber.Sign() <= 0 || receipt.BlockHash == (common.Hash{}) {
		return fail(fmt.Errorf("invalid internal CREATE receipt"))
	}
	dest, e := chain.Destination(ctx, hash)
	if e != nil || dest != factory {
		return fail(fmt.Errorf("receipt not Factory"))
	}
	fi, e := abi.JSON(bytes.NewReader(c.Artifacts["LQCFlowFactory"].ABI))
	if e != nil {
		return fail(e)
	}
	pi, e := abi.JSON(bytes.NewReader(c.Artifacts["LQCFlowPair"].ABI))
	if e != nil {
		return fail(e)
	}
	token0, token1 := tokenA, tokenB
	if bytes.Compare(token0[:], token1[:]) > 0 {
		token0, token1 = token1, token0
	}
	event := fi.Events["PairCreated"]
	matches := 0
	var pair common.Address
	for _, log := range receipt.Logs {
		if log.Address != factory || len(log.Topics) != 3 || log.Topics[0] != event.ID || common.BytesToAddress(log.Topics[1].Bytes()[12:]) != token0 || common.BytesToAddress(log.Topics[2].Bytes()[12:]) != token1 {
			continue
		}
		values, e := event.Inputs.NonIndexed().Unpack(log.Data)
		if e != nil || len(values) != 2 {
			return fail(fmt.Errorf("malformed PairCreated"))
		}
		p, ok := values[0].(common.Address)
		count, ok2 := values[1].(*big.Int)
		if !ok || !ok2 || count.Sign() <= 0 {
			return fail(fmt.Errorf("invalid PairCreated"))
		}
		pair = p
		matches++
	}
	if matches != 1 {
		return fail(fmt.Errorf("missing/ambiguous Factory event"))
	}
	if _, e = LocalAddress(pair.Hex()); e != nil {
		return fail(e)
	}
	for _, args := range [][]any{{tokenA, tokenB}, {tokenB, tokenA}} {
		data, e := fi.Pack("getPair", args...)
		if e != nil {
			return fail(e)
		}
		raw, e := chain.Call(ctx, factory, data)
		if e != nil {
			return fail(e)
		}
		values, e := fi.Unpack("getPair", raw)
		if e != nil || len(values) != 1 || values[0].(common.Address) != pair {
			return fail(fmt.Errorf("bidirectional mapping mismatch"))
		}
	}
	for addr, artifact := range map[common.Address]Artifact{factory: c.Artifacts["LQCFlowFactory"], pair: c.Artifacts["LQCFlowPair"]} {
		expected, e := runtime(artifact, map[string]common.Address{"factory": factory, "token0": token0, "token1": token1})
		if e != nil {
			return fail(e)
		}
		actual, e := chain.Code(ctx, addr)
		if e != nil || len(actual) == 0 || !bytes.Equal(actual, expected) {
			return fail(fmt.Errorf("runtime/immutable mismatch"))
		}
	}
	for name, wanted := range map[string]common.Address{"factory": factory, "token0": token0, "token1": token1} {
		data, e := pi.Pack(name)
		if e != nil {
			return fail(e)
		}
		raw, e := chain.Call(ctx, pair, data)
		if e != nil {
			return fail(e)
		}
		values, e := pi.Unpack(name, raw)
		if e != nil || len(values) != 1 || values[0].(common.Address) != wanted {
			return fail(fmt.Errorf("Pair getter mismatch"))
		}
	}
	if e = ctx.Err(); e != nil {
		return fail(e)
	}
	return pair, nil
}

type FreshBindings struct {
	ChainID        uint64
	RunID          string
	NewlyGenerated bool
	Addresses      map[string]string
}
type UnsignedOperation struct {
	ID, Kind           string
	To                 *common.Address
	Data               []byte
	ChainID            uint64
	GasLimit           uint64
	ProductionApproved bool
}

func (c Config) EncodeStep(plan Plan, id string, b FreshBindings) (UnsignedOperation, error) {
	if e := c.Validate(); e != nil {
		return UnsignedOperation{}, e
	}
	if !plan.intact() || b.ChainID != EVMID || b.RunID != plan.RunID || !b.NewlyGenerated {
		return UnsignedOperation{}, fmt.Errorf("fresh isolated binding required")
	}
	allowed := map[string]bool{"deployer": true}
	for _, x := range IDs {
		allowed[x] = true
	}
	for key, value := range b.Addresses {
		if !allowed[key] {
			return UnsignedOperation{}, fmt.Errorf("Router2/unknown binding")
		}
		a, e := LocalAddress(value)
		if e != nil {
			return UnsignedOperation{}, e
		}
		for _, old := range c.Policy.ExistingAccounts {
			if common.IsHexAddress(old) && common.HexToAddress(old) == a {
				return UnsignedOperation{}, fmt.Errorf("existing account forbidden")
			}
		}
	}
	get := func(key string) (common.Address, error) { return LocalAddress(b.Addresses[key]) }
	contract, ok := c.Manifest.Contracts[id]
	if !ok {
		return UnsignedOperation{}, fmt.Errorf("MVP slot required")
	}
	a := c.Artifacts[contract.Artifact]
	parsed, e := abi.JSON(bytes.NewReader(a.ABI))
	if e != nil {
		return UnsignedOperation{}, e
	}
	op := UnsignedOperation{ID: id, Kind: contract.CreationKind, ChainID: EVMID, GasLimit: c.Policy.MaxGasPerTx}
	var args []any
	switch id {
	case "mvp.tokenA", "mvp.tokenB":
		owner, e := get("deployer")
		if e != nil {
			return op, e
		}
		d := uint8(18)
		symbol := "LQCA"
		if id == "mvp.tokenB" {
			d = 6
			symbol = "LQCB"
		}
		args = []any{"LQC Local Test", symbol, d, owner}
	case "mvp.wrappedNative":
		args = []any{}
	case "mvp.factory":
		owner, e := get("deployer")
		if e != nil {
			return op, e
		}
		args = []any{owner}
	case "mvp.router":
		f, e := get("mvp.factory")
		if e != nil {
			return op, e
		}
		v, e := get("mvp.wrappedNative")
		if e != nil {
			return op, e
		}
		args = []any{f, v}
	case "mvp.pair", "mvp.pairNative":
		f, e := get("mvp.factory")
		if e != nil {
			return op, e
		}
		x, e := get("mvp.tokenA")
		if e != nil {
			return op, e
		}
		ref := "mvp.tokenB"
		if id == "mvp.pairNative" {
			ref = "mvp.wrappedNative"
		}
		y, e := get(ref)
		if e != nil {
			return op, e
		}
		if x == y {
			return op, fmt.Errorf("identical Pair tokens")
		}
		fa, e := abi.JSON(bytes.NewReader(c.Artifacts["LQCFlowFactory"].ABI))
		if e != nil {
			return op, e
		}
		op.To = &f
		op.Data, e = fa.Pack("createPair", x, y)
		return op, e
	}
	encoded, e := parsed.Constructor.Inputs.Pack(args...)
	if e != nil {
		return op, e
	}
	raw, e := hex.DecodeString(strings.TrimPrefix(a.Bytecode, "0x"))
	if e != nil {
		return op, e
	}
	op.Data = append(raw, encoded...)
	// Conservative mandatory Shanghai creation/code-deposit lower bound only;
	// an actual local estimate is still required before budget reservation.
	runtimeBytes := uint64(len(strings.TrimPrefix(a.DeployedBytecode, "0x")) / 2)
	floor := uint64(53000) + runtimeBytes*200 + 2*((uint64(len(op.Data))+31)/32)
	for _, b := range op.Data {
		if b == 0 {
			floor += 4
		} else {
			floor += 16
		}
	}
	if op.GasLimit < floor {
		return op, fmt.Errorf("BLOCKED: gas cap below mandatory creation lower bound; never raise automatically")
	}
	return op, nil
}
