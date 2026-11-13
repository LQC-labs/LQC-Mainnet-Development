/* Copyright 2026 MMXlabs & LQC LLC
 * SPDX-License-Identifier: Apache-2.0
 */
import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { validateProfile, validateRegistry, validateBundle, walletRequests, displayToBase, baseToDisplay, verifyLocalDeployment, sha256Bytes, transactionGate, localRPCTransport, quoteNetworksForDevnet } from "./flow-devnet-profile.mjs";
import { getQuoteChainId } from "./flow-quote-adapter.mjs";

const load = async name => JSON.parse(await readFile(new URL(`../config/flow/${name}`, import.meta.url), "utf8"));
const profile = await load("lqc-devnet.json"), registry = await load("abi-registry.json"), manifest = await load("deployments.lqc-devnet.json");
const clone = x => structuredClone(x);
const addr = "0x1111111111111111111111111111111111111111";
const tx = "0x" + "11".repeat(32), block = "0x" + "22".repeat(32);

test("shipped Devnet bundle is unconfigured and never enables transactions", async () => {
  assert.equal(await validateBundle(profile, registry, manifest), true);
  assert.equal(transactionGate().transactionsEnabled, false);
  for (const record of Object.values(manifest.contracts)) {
    assert.equal(record.contractAddress, null); assert.equal(record.transactionHash, null); assert.equal(record.runtimeBytecodeSha256, null);
  }
  assert.equal(profile.assets.wrappedNative.address, null);
  assert.equal(profile.assets.flowToken.decimals, null);
  assert.equal(profile.mainnetChainId, null);
});

test("original BSC examples and unadopted Mainnet remain unchanged", async () => {
  const original = JSON.parse(await readFile(new URL("../config/networks.example.json", import.meta.url), "utf8"));
  assert.deepEqual(original, { bscMainnet: { chainId: 56 }, bscTestnet: { chainId: 97 }, lqcDevnet: { chainId: null }, lqcMainnet: { chainId: null } });
  assert.deepEqual(profile.preservedNetworks, { bscMainnet: 56, bscTestnet: 97 });
  const before=JSON.stringify(original),networks=quoteNetworksForDevnet(profile,original);
  assert.equal(getQuoteChainId("lqcDevnet",networks),917001);
  assert.equal(getQuoteChainId("bscMainnet",networks),56);assert.equal(getQuoteChainId("bscTestnet",networks),97);
  assert.equal(networks.lqcMainnet.chainId,null);assert.equal(JSON.stringify(original),before);
  assert.throws(()=>quoteNetworksForDevnet(profile,{...original,lqcDevnet:{chainId:97}}));
});

test("reject wrong chain IDs, denom, decimals, prefix and premature Mainnet", async t => {
  for (const [key, value] of [["chainId",56],["chainId",97],["chainId",917002],["chainIdHex","0xdfe29"],["cosmosChainId","lqc-mainnet-1"],["baseDenom","ulqc"],["baseExponent",18],["displayDenom","LQC"],["decimals",6],["bech32Prefix","lqc"],["mainnetChainId",917001]]) {
    await t.test(`${key}=${value}`, () => { const p = clone(profile); p[key] = value; assert.throws(() => validateProfile(p)); });
  }
});

test("reject remote RPC, credentials, DNS lookalikes and malformed Origins", async t => {
  for (const value of ["https://bsc-testnet.drpc.org", "http://0.0.0.0:8545", "http://localhost:8545", "http://127.0.0.1.evil:8545", "http://user@127.0.0.1:8545", "http://127.0.0.1:8545/path", "http://127.0.0.1:8545?x=1", "https://127.0.0.1:8545", "http://127.0.0.1:0"]) {
    await t.test(value, () => { const p = clone(profile); p.rpcUrls = [value]; assert.throws(() => validateProfile(p)); });
  }
  for (const value of ["*","null","https://evil.example","http://localhost.evil:3000","http://localhost:3000/","http://localhost:3000?x=1","http://localhost:0"]) {
    const p = clone(profile); p.allowedOrigins = [value]; assert.throws(() => validateProfile(p));
  }
});

test("BSC token/router mixing and Bech32 contract addresses rejected", async () => {
  for (const a of ["0x84a30A66cFCbb15453C83204B7e6eC436a0718Fc", "0xae13d989daC2f0dEbFf460aC112a837C89BAa7cd", "0xA3E1fbe94055e7A8971b3994C7025B3c16273a24", "lqctest1notanevmaddress"]) {
    const p = clone(profile); p.assets.flowToken.address = a; p.assets.flowToken.decimals = 18;
    assert.throws(() => validateProfile(p));
  }
  const p = clone(profile); p.assets.native.address = addr; assert.throws(() => validateProfile(p), /native asset/);
});

test("atest/test exact conversion never rounds through Number", () => {
  for (const [display, base] of [["0","0"],["1","1000000000000000000"],["0.000000000000000001","1"],["9007199254740993.000000000000000001","9007199254740993000000000000000001"]]) {
    assert.equal(displayToBase(display), base); assert.equal(baseToDisplay(base), display);
  }
  for (const bad of [1, -1, "-1", "1e18", "1.0000000000000000001", "NaN", "01", " 1", "1."]) assert.throws(() => displayToBase(bad));
  for (const bad of [1, "-1", "1.1", "01", "1e18"]) assert.throws(() => baseToDisplay(bad));
});

test("wallet add/switch uses only Devnet metadata and local RPC", () => {
  const request = walletRequests(profile);
  assert.equal(request.add.method, "wallet_addEthereumChain");
  assert.equal(request.add.params[0].chainId, "0xdfe09");
  assert.deepEqual(request.add.params[0].rpcUrls, ["http://127.0.0.1:8545"]);
  assert.deepEqual(request.add.params[0].nativeCurrency, { name: "LQC Devnet Test", symbol: "TEST", decimals: 18 });
  assert.deepEqual(request.switch, { method: "wallet_switchEthereumChain", params: [{ chainId: "0xdfe09" }] });
  request.add.params[0].rpcUrls[0] = "http://evil.example";
  assert.equal(profile.rpcUrls[0], "http://127.0.0.1:8545");
});

test("ABI digest, source pin and record version are checked", async () => {
  assert.equal(await validateRegistry(registry), true);
  let r = clone(registry); r.interfaces.vault.abi[0] = "function invented()"; await assert.rejects(validateRegistry(r), /digest/);
  r = clone(registry); r.sourceCommit = "wrong"; await assert.rejects(validateRegistry(r));
  r = clone(registry); r.interfaces.vault.abi = []; await assert.rejects(validateRegistry(r), /ABI missing/);
  const m = clone(manifest); m.contracts.vault.abiVersion = "other-version"; await assert.rejects(validateBundle(profile, registry, m), /ABI version/);
});

test("missing ABI/address fails before any RPC and preserves disabled state", async () => {
  let called = false;
  await assert.rejects(verifyLocalDeployment(profile, registry, manifest, "vault", { url:profile.rpcUrls[0], request:async () => { called=true; } }), /disabled/);
  assert.equal(called, false); assert.equal(transactionGate().transactionsEnabled, false);
  const r = clone(registry); delete r.interfaces.vault;
  await assert.rejects(validateBundle(profile, r, manifest), /contracts mismatch/);
});

async function candidate() {
  const p=clone(profile),m=clone(manifest);m.status="candidates";
  m.contracts.vault={chainId:917001,contractAddress:addr,transactionHash:tx,runtimeBytecodeSha256:await sha256Bytes(new Uint8Array([0x60,0x00])),abiVersion:"vault-subset-v1",status:"candidate"};
  return {p,m};
}
const receipt = () => ({status:"0x1",transactionHash:tx,contractAddress:addr,blockHash:block,blockNumber:"0x3"});
function mockTransport(values={}) {
  const calls=[]; return {url:profile.rpcUrls[0],calls,async request({method,params}){calls.push({method,params});return Object.hasOwn(values,method)?values[method]:({eth_chainId:"0xdfe09",eth_getCode:"0x6000",eth_getTransactionReceipt:receipt()})[method];}};
}

test("mock runtime/receipt verification never marks manifest deployed or enables trading", async () => {
  const {p,m}=await candidate(),before=JSON.stringify(m),transport=mockTransport();
  const result=await verifyLocalDeployment(p,registry,m,"vault",transport);
  assert.equal(result.deploymentVerified,true);assert.equal(result.transactionsEnabled,false);
  assert.equal(JSON.stringify(m),before);assert.equal(m.contracts.vault.status,"candidate");
  assert.deepEqual(transport.calls.map(c=>c.method),["eth_chainId","eth_getCode","eth_getTransactionReceipt"]);
});

test("reject wrong runtime/chain/receipt and remote transport (mock evidence only)", async t => {
  for (const [name,values] of [
    ["BSC chain",{eth_chainId:"0x61"}], ["no bytecode",{eth_getCode:"0x"}], ["wrong bytecode",{eth_getCode:"0x6001"}],
    ["pending receipt",{eth_getTransactionReceipt:null}], ["reverted receipt",{eth_getTransactionReceipt:{...receipt(),status:"0x0"}}],
    ["wrong deployment address",{eth_getTransactionReceipt:{...receipt(),contractAddress:"0x"+"22".repeat(20)}}],
    ["wrong transaction hash",{eth_getTransactionReceipt:{...receipt(),transactionHash:block}}]
  ]) await t.test(name,async()=>{const {p,m}=await candidate();await assert.rejects(verifyLocalDeployment(p,registry,m,"vault",mockTransport(values)));});
  const {p,m}=await candidate();await assert.rejects(verifyLocalDeployment(p,registry,m,"vault",{...mockTransport(),url:"https://evil.example"}),/local RPC/);
});

test("manifest cannot self-assert verified deployment or carry BSC records", async () => {
  for (const mutate of [m=>m.contracts.vault.status="verified",m=>m.contracts.vault.chainId=97,m=>m.contracts.vault.contractAddress=addr,m=>m.contracts.launchpad.status="candidate"]) {
    const m=clone(manifest);mutate(m);await assert.rejects(validateBundle(profile,registry,m));
  }
  const {p,m}=await candidate();m.contracts.vault.contractAddress="0xe4f1320c8709631776c7e39e0916584935882525";
  await assert.rejects(validateBundle(p,registry,m),/BSC address/);
});

test("read-only browser transport uses POST, rejects redirects/errors and never signs", async () => {
  const calls=[];
  const transport=localRPCTransport(profile,async(url,opts)=>{calls.push({url,opts});const req=JSON.parse(opts.body);return {ok:true,json:async()=>({jsonrpc:"2.0",id:req.id,result:"0xdfe09"})};});
  assert.equal(await transport.request({method:"eth_chainId",params:[]}),"0xdfe09");
  assert.equal(calls[0].url,profile.rpcUrls[0]);assert.equal(calls[0].opts.method,"POST");assert.equal(calls[0].opts.credentials,"omit");assert.equal(calls[0].opts.redirect,"error");assert.ok(calls[0].opts.signal instanceof AbortSignal);
  assert.equal(calls[0].opts.headers["Content-Type"],"application/json");assert.equal(calls[0].opts.headers.Origin,undefined);
  await assert.rejects(transport.request({method:"eth_sendRawTransaction",params:[]}),/read-only/);
  const failed=localRPCTransport(profile,async()=>({ok:false}));await assert.rejects(failed.request({method:"eth_chainId",params:[]}),/rejected/);
  const wrong=localRPCTransport(profile,async()=>({ok:true,json:async()=>({jsonrpc:"2.0",id:99,result:"0xdfe09"})}));await assert.rejects(wrong.request({method:"eth_chainId",params:[]}),/invalid/);
});
