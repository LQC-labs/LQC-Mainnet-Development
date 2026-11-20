/*
 * Copyright 2026 MMXlabs & LQC LLC
 * SPDX-License-Identifier: Apache-2.0
 */

export function getQuoteChainId(name, networks) {
  const allowed = ["bscMainnet", "bscTestnet", "lqcDevnet", "lqcMainnet"];
  if (!allowed.includes(name)) throw new Error("Unknown network");
  const id = networks?.[name]?.chainId;
  if (!Number.isSafeInteger(id) || id <= 0) throw new Error("Chain ID not configured");
  if (name === "bscMainnet" && id !== 56) throw new Error("Invalid BSC Mainnet");
  if (name === "bscTestnet" && id !== 97) throw new Error("Invalid BSC Testnet");
  if (name.startsWith("lqc") && [56, 97, 9001].includes(id)) throw new Error("Chain ID conflict");
  if (name === "lqcMainnet" && id === 917001) throw new Error("Devnet Chain ID cannot be used by LQC Mainnet");
  const other = name === "lqcDevnet" ? "lqcMainnet" : "lqcDevnet";
  if (name.startsWith("lqc") && networks?.[other]?.chainId === id) throw new Error("LQC networks conflict");
  if (name === "lqcMainnet") throw new Error("Mainnet RPC is not enabled");
  return id;
}