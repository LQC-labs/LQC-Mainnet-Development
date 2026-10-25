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

test("rejects BSC Chain IDs for either LQC network", async (t) => {
  for (const network of ["lqcDevnet", "lqcMainnet"]) {
    for (const chainId of [56, 97]) {
      await t.test(`${network} rejects ${chainId}`, () => {
        assert.throws(() => getQuoteChainId(network, { [network]: { chainId } }), /Chain ID conflict/);
      });
    }
  }
});

test("rejects identical Devnet and Mainnet Chain IDs", () => {
  const networks = { lqcDevnet: { chainId: 12345 }, lqcMainnet: { chainId: 12345 } };
  assert.throws(() => getQuoteChainId("lqcDevnet", networks), /LQC networks conflict/);
  assert.throws(() => getQuoteChainId("lqcMainnet", networks), /LQC networks conflict/);
});

test("accepts distinct valid temporary LQC Chain IDs", () => {
  const temporaryNetworks = {
    lqcDevnet: { chainId: 12345 },
    lqcMainnet: { chainId: 54321 },
  };
  assert.equal(getQuoteChainId("lqcDevnet", temporaryNetworks), 12345);
  assert.equal(getQuoteChainId("lqcMainnet", temporaryNetworks), 54321);
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
