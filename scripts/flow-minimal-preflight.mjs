/* Copyright 2026 MMXlabs & LQC LLC
 * SPDX-License-Identifier: Apache-2.0
 */
// Explicit local test evidence exporter. No signer, deploy or broadcast API.
import fs from "node:fs/promises";
import path from "node:path";
import assert from "node:assert/strict";
import {validateBundle, verifyLocalDeployment, localRPCTransport, abiDigest, sha256Bytes} from "./flow-devnet-profile.mjs";

// FLOW is maintained by a separate team. Read explicitly supplied data only;
// do not import or execute code from the external bundle.
const explicitAssets=process.env.LQC_FLOW_ASSET_ROOT;
if(explicitAssets)assert.ok(path.isAbsolute(explicitAssets),'absolute FLOW asset bundle required');
const assetURL=rel=>explicitAssets?path.join(explicitAssets,rel):new URL("../"+rel,import.meta.url);
const input=JSON.parse(await fs.readFile(process.argv[2],"utf8"));
const root=await fs.realpath(input.root);
assert.ok(path.basename(root).startsWith("lqc-flow-minimal."));
assert.ok(["first","restart"].includes(input.phase));
const load=async name=>JSON.parse(await fs.readFile(assetURL("config/flow/"+name),"utf8"));
const profile=await load("lqc-devnet.json"),registry=await load("abi-registry.json"),manifest=await load("deployments.lqc-devnet.json");
profile.rpcUrls=[input.rpc];manifest.status="candidates";
const state=input.state;
const sourceProvenance=JSON.parse(await fs.readFile(assetURL("node/testdata/flow-minimal/SOURCE.json"),"utf8"));
for(const [slot,name] of [["flowToken","token18"],["wrappedNative","wrapper"]]){
 const tx=state.Receipts["deploy-"+name];
 manifest.contracts[slot]={...manifest.contracts[slot],status:"candidate",contractAddress:state.Contracts[name],transactionHash:tx.hash,runtimeBytecodeSha256:state.CodeHashes[name]};
 profile.assets[slot].address=state.Contracts[name];profile.assets[slot].decimals=18;
}
manifest.flowMinimal={status:"local-test-only",flowCommit:registry.sourceCommit,localPatches:sourceProvenance.patched_sources??{},contracts:{}};
for(const [name,transaction] of [["factory","deploy-factory"],["pair","create-pair"],["router","deploy-router"],["token6","deploy-token6"]]){
 manifest.flowMinimal.contracts[name]={chainId:917001,contractAddress:state.Contracts[name],transactionHash:state.Receipts[transaction].hash,runtimeBytecodeSha256:state.CodeHashes[name],creationKind:name==="pair"?"factory-internal-create":"top-level-create",abiArtifact:name==="token6"?"LQCTestToken":"LQCFlow"+name[0].toUpperCase()+name.slice(1)};
}
await validateBundle(profile,registry,manifest);
const transport=localRPCTransport(profile);
const checks={};
for(const slot of ["flowToken","wrappedNative"])checks[slot]=await verifyLocalDeployment(profile,registry,manifest,slot,transport);
const full={schemaVersion:1,flowCommit:registry.sourceCommit,compiler:"0.8.30+commit.73712a01",format:"solc-json-abi",contracts:{}};
for(const name of ["LQCFlowFactory","LQCFlowPair","LQCFlowRouter","LQCTestToken","MockWBNB","FlowCallbackToken","FlowWithdrawalProbe"]){
 const artifact=JSON.parse(await fs.readFile(assetURL("node/testdata/flow-minimal/artifacts/"+name+".json"),"utf8"));
 full.contracts[name]={version:name+"-solc0.8.30"+(name==="LQCFlowRouter"?"-min-guard":"")+"-v1",sourceName:artifact.sourceName,origin:name==="LQCFlowRouter"?"local-minimum-guard-patch":name.startsWith("Flow")?"local-adversarial-fixture":"pinned-flow",abi:artifact.abi,abiSha256:await abiDigest(artifact.abi)};
}
for(const [name,receiptName] of [["factory","deploy-factory"],["router","deploy-router"]]){
 const address=state.Contracts[name],code=await transport.request({method:"eth_getCode",params:[address,"latest"]});
 assert.equal(await sha256Bytes(Buffer.from(code.slice(2),"hex")),state.CodeHashes[name]);
 const receipt=await transport.request({method:"eth_getTransactionReceipt",params:[state.Receipts[receiptName].hash]});
 assert.equal(receipt.contractAddress.toLowerCase(),address.toLowerCase());assert.equal(receipt.status,"0x1");
}
for(const [name,content] of [["profile",profile],["manifest",manifest],["full-abi",full]]){
 await fs.writeFile(path.join(root,input.phase+"-flow-"+name+".json"),JSON.stringify(content,null,2)+"\n",{mode:0o600,flag:"wx"});
}
console.log(JSON.stringify({phase:input.phase,chainId:917001,codeAndReceiptChecks:checks,transactionsEnabled:false,realFlowUI:"NOT TESTED"}));
