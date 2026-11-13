/* Copyright 2026 MMXlabs & LQC LLC
 * SPDX-License-Identifier: Apache-2.0
 */

// Configuration/preflight primitives only. No wallet, transaction broadcast or
// deployment API. WebCrypto makes the same hash checks usable by Node/browser.
const FLOW_COMMIT = "8db16368b3e09a94bfd500a17e33e3e9ef62ed51";
const CORE_COMMIT = "957889bdb2e5709ce23e71f7c5536936ee187851";
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const HASH = /^0x[0-9a-fA-F]{64}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;

// Recorded/configured BSC addresses, not a claim to enumerate every BSC
// deployment. Chain identity + local runtime/receipt verification is also
// mandatory; an unknown address must never become trusted by omission here.
const BSC_ADDRESSES = new Set([
  "0xA3E1fbe94055e7A8971b3994C7025B3c16273a24",
  "0xae13d989daC2f0dEbFf460aC112a837C89BAa7cd",
  "0x84a30A66cFCbb15453C83204B7e6eC436a0718Fc",
  "0xfbd1c5c8dbbdadf3eb834f351366daf55f2d73b0",
  "0xb532c65294a7b35ca510a7df025e934fa17c8d7e",
  "0xbf6a446c5e17228e70e45645ab47f751bdfc4b41",
  "0xe4f1320c8709631776c7e39e0916584935882525",
  "0xFc6c31cB14332592562396fef995c03c9F1E173C",
  "0x7867d6E8A50d40389DA64CaDC2d053D04ffaaB52"
].map(a => a.toLowerCase()));

function requireValue(ok, message) { if (!ok) throw new Error(message); }
function localUrl(value, origin = false) {
  requireValue(typeof value === "string", "local URL required");
  let url; try { url = new URL(value); } catch { throw new Error("local URL required"); }
  requireValue(["http:", "https:"].includes(url.protocol) &&
    ["localhost", "127.0.0.1"].includes(url.hostname) && !url.username && !url.password &&
    url.pathname === "/" && !url.search && !url.hash, "loopback URL required");
  requireValue(origin ? value === url.origin : value === url.origin || value === url.origin + "/", "canonical local URL required");
  requireValue(!url.port || (Number(url.port) >= 1 && Number(url.port) <= 65535), "explicit nonzero port required");
  // Core's listener is numeric IPv4. Browser Origins may use localhost.
  requireValue(origin || url.hostname === "127.0.0.1", "numeric loopback RPC required");
  requireValue(origin || url.protocol === "http:", "Core local RPC uses HTTP");
  return value;
}
function address(value) {
  requireValue(typeof value === "string" && ADDRESS.test(value) && !/^0x0{40}$/i.test(value), "nonzero EVM address required");
  requireValue(!BSC_ADDRESSES.has(value.toLowerCase()), "BSC address mixing rejected");
  return value.toLowerCase();
}

export function validateProfile(p) {
  requireValue(p?.schemaVersion === 1 && p.profile === "lqc-devnet", "Devnet profile required");
  requireValue(p.chainId === 917001 && p.chainIdHex === "0xdfe09" && p.cosmosChainId === "lqc-devnet-test-1", "Devnet chain identity mismatch");
  requireValue(p.bech32Prefix === "lqctest" && p.baseDenom === "atest" && p.baseExponent === 0 && p.displayDenom === "test" && p.decimals === 18, "native denomination mismatch");
  requireValue(p.mainnetChainId === null, "Mainnet Chain ID remains undecided");
  requireValue(p.nativeCurrency?.name === "LQC Devnet Test" && p.nativeCurrency.symbol === "TEST" && p.nativeCurrency.decimals === 18, "native wallet metadata mismatch");
  requireValue(p.source?.coreCommit === CORE_COMMIT && p.source.flowCommit === FLOW_COMMIT && p.source.flowRepository === "LQC-labs/LQC-Liquidity-chain", "source baseline mismatch");
  requireValue(p.preservedNetworks?.bscMainnet === 56 && p.preservedNetworks.bscTestnet === 97, "BSC network identity changed");
  requireValue(Array.isArray(p.rpcUrls) && p.rpcUrls.length === 1, "one explicit local RPC required");
  p.rpcUrls.forEach(v => localUrl(v));
  requireValue(Array.isArray(p.allowedOrigins) && p.allowedOrigins.length > 0 && p.allowedOrigins.length <= 16 && new Set(p.allowedOrigins).size === p.allowedOrigins.length, "explicit Origins required");
  p.allowedOrigins.forEach(v => localUrl(v, true));
  const a = p.assets;
  requireValue(a && Object.keys(a).sort().join(",") === "flowToken,native,wrappedNative", "asset inventory mismatch");
  requireValue(a?.native?.kind === "native" && a.native.chainId === 917001 && a.native.address === null && a.native.baseDenom === "atest" && a.native.displayDenom === "test" && a.native.decimals === 18, "native asset is not ERC20");
  const seen = new Set();
  for (const [name, kind] of [["flowToken", "erc20"], ["wrappedNative", "wrapped-native"]]) {
    const item = a[name];
    requireValue(item?.kind === kind && item.chainId === 917001, "asset chain/kind mismatch");
    if (item.address !== null) {
      const key = address(item.address);
      requireValue(!seen.has(key), "distinct assets required"); seen.add(key);
      requireValue(Number.isInteger(item.decimals) && item.decimals >= 0 && item.decimals <= 36, "ERC20 decimals required");
    } else if (name === "flowToken") { requireValue(item.decimals === null, "undeployed Flow token decimals remain unconfirmed"); }
    if (name === "wrappedNative") requireValue(item.decimals === 18, "wrapped native decimals mismatch");
  }
  return true;
}

export async function sha256Bytes(bytes) {
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  return "sha256:" + Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, "0")).join("");
}
export async function abiDigest(abi) { return sha256Bytes(new TextEncoder().encode(JSON.stringify(abi))); }

export async function validateRegistry(r) {
  requireValue(r?.schemaVersion === 1 && r.sourceRepository === "LQC-labs/LQC-Liquidity-chain" && r.sourceCommit === FLOW_COMMIT && r.interfaces && Object.keys(r.interfaces).length > 0, "ABI source mismatch");
  for (const [name, item] of Object.entries(r.interfaces)) {
    requireValue(item?.version === `${name}-subset-v1` && item.format === "ethers-human-readable" && item.coverage === "subset", "versioned ABI subset required");
    requireValue(item.sourceCommit === FLOW_COMMIT && typeof item.sourcePath === "string" && item.sourcePath.startsWith("dex/contracts/") && !item.sourcePath.includes(".."), "ABI source path mismatch");
    requireValue(typeof item.sourceBlobSha === "string" && /^[0-9a-f]{40}$/.test(item.sourceBlobSha), "pinned source blob required");
    requireValue(Array.isArray(item.abi) && item.abi.length > 0 && item.abi.every(x => typeof x === "string" && x.startsWith("function ")), "ABI missing");
    requireValue(DIGEST.test(item.abiSha256) && item.abiSha256 === await abiDigest(item.abi), "ABI digest mismatch");
  }
  return true;
}

export async function validateBundle(p, r, m) {
  validateProfile(p); await validateRegistry(r);
  requireValue(m?.schemaVersion === 1 && m.chainId === p.chainId && m.cosmosChainId === p.cosmosChainId && ["unconfigured", "candidates"].includes(m.status), "manifest chain/status mismatch");
  const expected = [...Object.keys(r.interfaces), "launchpad"].sort();
  requireValue(m.contracts && JSON.stringify(Object.keys(m.contracts).sort()) === JSON.stringify(expected), "manifest contracts mismatch");
  const seen = new Set();
  for (const [name, record] of Object.entries(m.contracts)) {
    requireValue(record?.chainId === 917001, "contract chain mismatch");
    if (name === "launchpad") {
      requireValue(record.status === "unimplemented" && record.abiVersion === null, "Launchpad implementation unconfirmed");
    } else {
      requireValue(record.abiVersion === r.interfaces[name]?.version, "ABI version mismatch");
      requireValue(["unconfigured", "candidate"].includes(record.status), "runtime verification is not a manifest status flag");
    }
    if (record.status !== "candidate") {
      requireValue(record.contractAddress === null && record.transactionHash === null && record.runtimeBytecodeSha256 === null, "undeployed record must remain null");
    } else {
      requireValue(m.status === "candidates", "candidate manifest status required");
      const key = address(record.contractAddress);
      requireValue(!seen.has(key), "duplicate contract address"); seen.add(key);
      requireValue(typeof record.transactionHash === "string" && HASH.test(record.transactionHash) && !/^0x0{64}$/i.test(record.transactionHash) && DIGEST.test(record.runtimeBytecodeSha256), "deployment evidence missing");
    }
  }
  for (const name of ["flowToken", "wrappedNative"]) {
    const target = m.contracts[name].contractAddress;
    requireValue(p.assets[name].address?.toLowerCase() === target?.toLowerCase(), "asset/manifest address mismatch");
  }
  return true;
}

export function walletRequests(p) {
  validateProfile(p);
  return {
    add: { method: "wallet_addEthereumChain", params: [{ chainId: p.chainIdHex, chainName: "LQC Local Devnet", nativeCurrency: { ...p.nativeCurrency }, rpcUrls: [...p.rpcUrls] }] },
    switch: { method: "wallet_switchEthereumChain", params: [{ chainId: p.chainIdHex }] }
  };
}

// Explicit opt-in bridge to the existing Core quote adapter. The original
// networks object/example remains untouched; no Mainnet identifier is adopted.
export function quoteNetworksForDevnet(p, existing) {
  validateProfile(p);
  requireValue(existing?.bscMainnet?.chainId === 56 && existing.bscTestnet?.chainId === 97 && existing.lqcMainnet?.chainId === null, "original BSC/unadopted Mainnet settings required");
  requireValue(existing.lqcDevnet?.chainId === null || existing.lqcDevnet?.chainId === 917001, "conflicting Devnet configuration");
  return { ...existing, bscMainnet: { ...existing.bscMainnet }, bscTestnet: { ...existing.bscTestnet }, lqcMainnet: { ...existing.lqcMainnet }, lqcDevnet: { ...existing.lqcDevnet, chainId: p.chainId } };
}

// Exact decimal strings only; no IEEE-754 conversion or rounding of funds.
export function displayToBase(value) {
  requireValue(typeof value === "string" && /^(0|[1-9][0-9]*)(\.[0-9]{1,18})?$/.test(value), "exact nonnegative display amount required");
  const [whole, fraction = ""] = value.split(".");
  return (BigInt(whole) * 10n ** 18n + BigInt(fraction.padEnd(18, "0"))).toString();
}
export function baseToDisplay(value) {
  requireValue(typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value), "integer atest amount required");
  const n = BigInt(value), scale = 10n ** 18n;
  const fraction = (n % scale).toString().padStart(18, "0").replace(/0+$/, "");
  return (n / scale).toString() + (fraction ? "." + fraction : "");
}

// Read-only transport must be bound by the caller to the validated local URL.
// Returns ephemeral verification evidence, never marks a manifest deployed or
// enables trading. Governance, wiring, liquidity and full ABI remain separate.
export async function verifyLocalDeployment(p, r, m, name, transport) {
  await validateBundle(p, r, m);
  requireValue(transport?.url === p.rpcUrls[0] && typeof transport.request === "function", "validated local RPC transport required");
  const record = m.contracts[name];
  requireValue(record?.status === "candidate" && r.interfaces[name], "address or ABI missing: transactions disabled");
  const request = (method, params) => transport.request({ method, params });
  requireValue(await request("eth_chainId", []) === "0xdfe09", "RPC chain mismatch");
  const code = await request("eth_getCode", [record.contractAddress, "latest"]);
  requireValue(typeof code === "string" && code.length <= 2*1024*1024+2 && /^0x(?:[0-9a-fA-F]{2})+$/.test(code), "runtime bytecode missing or oversized");
  const bytes = Uint8Array.from(code.slice(2).match(/../g), h => parseInt(h, 16));
  requireValue(await sha256Bytes(bytes) === record.runtimeBytecodeSha256, "runtime bytecode hash mismatch");
  const receipt = await request("eth_getTransactionReceipt", [record.transactionHash]);
  requireValue(receipt?.status === "0x1" && receipt.transactionHash?.toLowerCase() === record.transactionHash.toLowerCase() && receipt.contractAddress?.toLowerCase() === record.contractAddress.toLowerCase() && HASH.test(receipt.blockHash) && /^0x[1-9a-f][0-9a-f]*$/i.test(receipt.blockNumber), "deployment receipt mismatch");
  return { deploymentVerified: true, transactionsEnabled: false, reason: "Flow integration and permissions NOT TESTED", chainId: 917001, contractAddress: record.contractAddress, abiVersion: record.abiVersion, runtimeBytecodeSha256: record.runtimeBytecodeSha256, blockHash: receipt.blockHash };
}

export function transactionGate() {
  return { transactionsEnabled: false, reason: "Configuration scaffolding only; deployment, ABI and integration approval required" };
}

export function localRPCTransport(p, fetcher = globalThis.fetch) {
  validateProfile(p);
  const url = p.rpcUrls[0]; let id = 0;
  return Object.freeze({ url, async request({ method, params }) {
    requireValue(["eth_chainId", "eth_getCode", "eth_getTransactionReceipt"].includes(method), "read-only preflight method required");
    const current = ++id, controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 3000);
    try {
      const response = await fetcher(url, { method: "POST", headers: { "Content-Type": "application/json" }, credentials: "omit", redirect: "error", signal: controller.signal,
        body: JSON.stringify({ jsonrpc: "2.0", id: current, method, params }) });
      requireValue(response.ok, "local RPC HTTP request rejected");
      const payload = await response.json();
      requireValue(payload?.jsonrpc === "2.0" && payload.id === current && !payload.error && Object.hasOwn(payload, "result"), "invalid or failed RPC response");
      return payload.result;
    } finally { clearTimeout(timer); }
  }});
}
