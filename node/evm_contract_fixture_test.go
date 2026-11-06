//go:build linux

// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0
package node

import (
	"encoding/binary"
	"github.com/ethereum/go-ethereum/crypto"
)

// This TEST-only EVM assembly is intentionally independent of solc downloads.
// ABI: get() returns slot 0; set(uint256) stores slot 0 and emits the unindexed
// ValueChanged(uint256) event; fail() and unknown selectors write/emit 99 and
// then REVERT, so tests can prove that intermediate storage/logs roll back.
// No owner, external call, delegatecall, selfdestruct, private key or network.
// set accepts exactly one ABI word. Initial storage is the EVM default zero.
func contractFixtureBytecode() (creation, runtime []byte) {
	labels := map[string]int{}
	type fixup struct {
		offset int
		label  string
	}
	var fixups []fixup
	push := func(value byte) { runtime = append(runtime, 0x60, value) }
	jump := func(label string, conditional bool) {
		runtime = append(runtime, 0x61, 0, 0)
		fixups = append(fixups, fixup{len(runtime) - 2, label})
		if conditional {
			runtime = append(runtime, 0x57)
		} else {
			runtime = append(runtime, 0x56)
		}
	}
	label := func(name string) { labels[name] = len(runtime); runtime = append(runtime, 0x5b) }
	push(0)
	runtime = append(runtime, 0x35)
	push(224)
	runtime = append(runtime, 0x1c) // calldata[0:4]
	for _, entry := range []struct{ signature, label string }{{"get()", "get"}, {"set(uint256)", "set"}, {"fail()", "fail"}} {
		runtime = append(runtime, 0x80, 0x63)
		runtime = append(runtime, crypto.Keccak256([]byte(entry.signature))[:4]...)
		runtime = append(runtime, 0x14)
		jump(entry.label, true)
	}
	jump("fail", false)
	label("get")
	runtime = append(runtime, 0x50)
	push(0)
	runtime = append(runtime, 0x54)
	push(0)
	runtime = append(runtime, 0x52)
	push(32)
	push(0)
	runtime = append(runtime, 0xf3)
	label("set")
	runtime = append(runtime, 0x50, 0x36)
	push(36)
	runtime = append(runtime, 0x14, 0x15)
	jump("fail", true)
	push(4)
	runtime = append(runtime, 0x35, 0x80)
	push(0)
	runtime = append(runtime, 0x55)
	push(0)
	runtime = append(runtime, 0x52)
	runtime = append(runtime, 0x7f)
	runtime = append(runtime, crypto.Keccak256([]byte("ValueChanged(uint256)"))...)
	push(32)
	push(0)
	runtime = append(runtime, 0xa1)
	push(0)
	push(0)
	runtime = append(runtime, 0xf3)
	label("fail")
	push(99)
	push(0)
	runtime = append(runtime, 0x55)
	push(99)
	push(0)
	runtime = append(runtime, 0x52)
	runtime = append(runtime, 0x7f)
	runtime = append(runtime, crypto.Keccak256([]byte("ValueChanged(uint256)"))...)
	push(32)
	push(0)
	runtime = append(runtime, 0xa1)
	push(0)
	push(0)
	runtime = append(runtime, 0xfd)
	for _, f := range fixups {
		binary.BigEndian.PutUint16(runtime[f.offset:f.offset+2], uint16(labels[f.label]))
	}
	// 15-byte init code: CODECOPY runtime from this envelope and RETURN it.
	creation = []byte{0x61, byte(len(runtime) >> 8), byte(len(runtime)), 0x61, 0, 15, 0x60, 0, 0x39, 0x61, byte(len(runtime) >> 8), byte(len(runtime)), 0x60, 0, 0xf3}
	creation = append(creation, runtime...)
	return creation, runtime
}
