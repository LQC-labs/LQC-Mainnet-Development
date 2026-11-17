// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import { validateNetworkConfig } from './index.mjs';

const valid = Object.freeze({
  cosmosChainId: 'lqc-fixture-1',
  evmChainId: 423456781,
  bech32Prefix: 'lqctest',
  nativeDenom: 'atest',
  rpcUrl: 'https://rpc.example.invalid/'
});

test('explicit offline config accepted without RPC access', () => {
  const result = validateNetworkConfig(valid);
  assert.equal(result.rpcUrl, 'https://rpc.example.invalid');
  assert.ok(Object.isFrozen(result));
});
test('reserved EVM IDs rejected', () => {
  for (const evmChainId of [0, 56, 97, 9001, -1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => validateNetworkConfig({ ...valid, evmChainId }));
  }
});
test('invalid Cosmos chain IDs rejected', () => {
  for (const cosmosChainId of ['', 'mainnet', 'UPPER-1', 'bad--id-1', 'bad-foo']) {
    assert.throws(() => validateNetworkConfig({ ...valid, cosmosChainId }));
  }
});
test('invalid network metadata rejected', () => {
  for (const input of [
    { ...valid, bech32Prefix: '' },
    { ...valid, bech32Prefix: 'UPPER' },
    { ...valid, nativeDenom: '1invalid' },
    { ...valid, nativeDenom: '' },
    null,
    []
  ]) assert.throws(() => validateNetworkConfig(input));
});
test('insecure or credential-bearing RPC endpoints rejected', () => {
  for (const rpcUrl of [
    'http://rpc.example.invalid',
    'https://user:secret@rpc.example.invalid',
    'https://rpc.example.invalid/?token=secret',
    'https://rpc.example.invalid/#secret',
    'https://rpc.example.invalid/other',
    'file:///tmp/socket',
    'not-a-url'
  ]) assert.throws(() => validateNetworkConfig({ ...valid, rpcUrl }));
});
