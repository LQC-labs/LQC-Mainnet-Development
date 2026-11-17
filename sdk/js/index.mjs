// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0
// Offline network configuration validation only. No keys, signing or RPC calls.
const RESERVED_EVM_IDS = new Set([56, 97, 9001]);
const CHAIN_ID_PATTERN = /^[a-z0-9][a-z0-9-]*-[0-9]+$/;
const DENOM_PATTERN = /^[a-zA-Z][a-zA-Z0-9/:._-]*$/;

export function validateNetworkConfig(input) {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) {
    throw new TypeError('network config object required');
  }
  const { cosmosChainId, evmChainId, bech32Prefix, nativeDenom, rpcUrl } = input;
  if (typeof cosmosChainId !== 'string' || !CHAIN_ID_PATTERN.test(cosmosChainId) || cosmosChainId.includes('--')) {
    throw new Error('invalid Cosmos chain ID');
  }
  if (!Number.isSafeInteger(evmChainId) || evmChainId <= 0 || RESERVED_EVM_IDS.has(evmChainId)) {
    throw new Error('invalid or reserved EVM chain ID');
  }
  if (typeof bech32Prefix !== 'string' || !/^[a-z][a-z0-9]*$/.test(bech32Prefix) || bech32Prefix.length > 83) {
    throw new Error('invalid Bech32 prefix');
  }
  if (typeof nativeDenom !== 'string' || nativeDenom.length > 128 || !DENOM_PATTERN.test(nativeDenom)) {
    throw new Error('invalid native denomination');
  }
  if (typeof rpcUrl !== 'string') throw new Error('RPC URL required');
  let url;
  try { url = new URL(rpcUrl); } catch { throw new Error('invalid RPC URL'); }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || url.pathname !== '/') {
    throw new Error('RPC URL must be HTTPS origin without credentials or parameters');
  }
  return Object.freeze({ cosmosChainId, evmChainId, bech32Prefix, nativeDenom, rpcUrl: url.origin });
}
