/*
 * Copyright 2026 MMXlabs & LQC LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import test from "node:test";
import assert from "node:assert/strict";
import { getQuoteChainId } from "./flow-quote-adapter.mjs";
import networksExample from "../config/networks.example.json" with { type: "json" };

test("accepts BSC Mainnet Chain ID 56", () => {
  assert.equal(getQuoteChainId("bscMainnet", networksExample), 56);
});

test("accepts BSC Testnet Chain ID 97", () => {
  assert.equal(getQuoteChainId("bscTestnet", networksExample), 97);
});

test("rejects invalid BSC Chain IDs", async (t) => {
  for (const [network, chainId] of [["bscMainnet", 97], ["bscTestnet", 56]]) {
    await t.test(`${network} rejects ${chainId}`, () => {
      assert.throws(() => getQuoteChainId(network, { [network]: { chainId } }), /Invalid BSC/);
    });
  }
});

test("rejects an unset LQC Chain ID", () => {
  for (const network of ["lqcDevnet", "lqcMainnet"]) {
    assert.throws(() => getQuoteChainId(network, { [network]: { chainId: null } }), /Chain ID not configured/);
  }
});

test("rejects reserved EVM Chain IDs for either LQC network", async (t) => {
  for (const network of ["lqcDevnet", "lqcMainnet"]) {
    for (const chainId of [56, 97, 9001]) {
      await t.test(`${network} rejects ${chainId}`, () => {
        assert.throws(() => getQuoteChainId(network, { [network]: { chainId } }), /Chain ID conflict/);
      });
    }
  }
});

test("rejects the Devnet EVM Chain ID in Mainnet regardless of the Devnet entry", async (t) => {
  for (const [name, devnet] of [
    ["missing Devnet", {}],
    ["null Devnet", { lqcDevnet: null }],
    ["empty Devnet", { lqcDevnet: {} }],
    ["unset Devnet Chain ID", { lqcDevnet: { chainId: null } }],
    ["configured Devnet", { lqcDevnet: { chainId: 917001 } }],
  ]) {
    await t.test(name, () => {
      assert.throws(
        () => getQuoteChainId("lqcMainnet", { ...devnet, lqcMainnet: { chainId: 917001 } }),
        /Devnet Chain ID cannot be used by LQC Mainnet/,
      );
    });
  }
});

test("accepts the Devnet EVM Chain ID for Devnet with Mainnet unset", () => {
  const networks = { lqcDevnet: { chainId: 917001 }, lqcMainnet: { chainId: null } };
  assert.equal(getQuoteChainId("lqcDevnet", networks), 917001);
  assert.throws(() => getQuoteChainId("lqcMainnet", networks), /Chain ID not configured/);
});

test("rejects identical Devnet and Mainnet Chain IDs", () => {
  const networks = { lqcDevnet: { chainId: 12345 }, lqcMainnet: { chainId: 12345 } };
  assert.throws(() => getQuoteChainId("lqcDevnet", networks), /LQC networks conflict/);
  assert.throws(() => getQuoteChainId("lqcMainnet", networks), /LQC networks conflict/);
});

test("keeps Devnet usable alongside a distinct Mainnet ID", () => {
  const temporaryNetworks = {
    lqcDevnet: { chainId: 12345 },
    lqcMainnet: { chainId: 54321 },
  };
  assert.equal(getQuoteChainId("lqcDevnet", temporaryNetworks), 12345);
  assert.throws(() => getQuoteChainId("lqcMainnet", temporaryNetworks), /Mainnet RPC is not enabled/);
});

test("blocks Mainnet quotes with approved identity while RPC deployment is disabled", () => {
  assert.equal(networksExample.lqcMainnet.chainId, 768167);
  assert.deepEqual(networksExample.lqcMainnet.rpcUrls, []);
  assert.throws(() => getQuoteChainId("lqcMainnet", networksExample), /Mainnet RPC is not enabled/);
  const injected = { ...networksExample, lqcMainnet: { ...networksExample.lqcMainnet, rpcUrls: ["http://192.0.2.10:8545"] } };
  assert.throws(() => getQuoteChainId("lqcMainnet", injected), /Mainnet RPC is not enabled/);
});

test("rejects an unknown network name", () => {
  assert.throws(() => getQuoteChainId("unknownNetwork", { unknownNetwork: { chainId: 12345 } }), /Unknown network/);
});

test("rejects invalid Chain ID values for LQC networks", async (t) => {
  const invalidChainIds = [
    ["zero", 0],
    ["negative", -1],
    ["string", "12345"],
    ["fraction", 1.5],
    ["unsafe integer", Number.MAX_SAFE_INTEGER + 1],
  ];

  for (const network of ["lqcDevnet", "lqcMainnet"]) {
    for (const [label, chainId] of invalidChainIds) {
      await t.test(`${network} rejects ${label}`, () => {
        assert.throws(() => getQuoteChainId(network, { [network]: { chainId } }), /Chain ID not configured/);
      });
    }
  }
});
