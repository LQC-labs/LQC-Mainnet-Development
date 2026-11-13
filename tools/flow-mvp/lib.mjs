import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {Interface,getAddress,ZeroAddress,zeroPadValue,toBeHex,isHexString} from 'ethers';

export const CORE='b79394246a8819a7651275bd07c88b83bccdd8df';
export const FLOW='013d159f05ed6a924ee965ec41ef193a069da122';
export const OVERLAY='b24bfb2000eaf3510a6e0b49ab30a0a2de74a4969337b3355886f2faa49032dd';
export const IDS=['mvp.tokenA','mvp.tokenB','mvp.wrappedNative','mvp.factory','mvp.pair','mvp.pairNative','mvp.router'];
export const ARTIFACTS=['LQCTestToken','MockWBNB','LQCFlowFactory','LQCFlowPair','LQCFlowRouter'];
// Existing Flow97 config plus official BNB/Pancake56/97 reference addresses.
// https://developer.pancakeswap.finance/contracts/v2/addresses
// https://docs.bnbchain.org/bnb-smart-chain/benchmark/design-reference/
const BSC=new Set(['0xae13d989dac2f0debff460ac112a837c89baa7cd','0x84a30a66cfcbb15453c83204b7e6ec436a0718fc','0xa3e1fbe94055e7a8971b3994c7025b3c16273a24','0xd99d1c33f9fc3444f8101754abc46c52416550d1','0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c','0x10ed43c718714eb63d5aa57b78b54704e256024e','0xca143ce32fe78f1f7019d7d551a6402fc5350c73','0x6725f303b657a9451d8ba641348b6761a6cc7a17'].map(x=>x.toLowerCase()));
export const sha=b=>createHash('sha256').update(b).digest('hex');
const jsonHash=x=>sha(Buffer.from(JSON.stringify(x)));
function keys(o,wanted,label){assert(o&&typeof o==='object'&&!Array.isArray(o),label+' object required');assert.deepEqual(Object.keys(o).sort(),[...wanted].sort(),label+' keys');}
export function address(x,label='address'){
 assert.equal(typeof x,'string',label+' required');assert(!BSC.has(x.toLowerCase()),'BSC configured address forbidden');const a=getAddress(x);assert.notEqual(a,ZeroAddress,'zero address forbidden');return a;
}
export function network(n){
 keys(n,['chainId','chainIdHex','cosmosChainId','bech32Prefix','baseDenom','displayDenom','decimals','rpcUrls','allowedOrigins'],'network');
 assert.equal(n.chainId,917001,'only chain 917001');assert.equal(n.chainIdHex,'0xdfe09','chain hex');assert.equal(n.cosmosChainId,'lqc-devnet-test-1','Cosmos chain');assert.equal(n.bech32Prefix,'lqctest','prefix');assert.equal(n.baseDenom,'atest','denom');assert.equal(n.displayDenom,'test','display denom');assert.equal(n.decimals,18,'native decimals');
 assert(Array.isArray(n.rpcUrls)&&n.rpcUrls.length===1,'one local RPC required');
 const u=new URL(n.rpcUrls[0]);assert(u.protocol==='http:'&&['127.0.0.1','[::1]'].includes(u.hostname),'literal loopback HTTP only');assert(!u.username&&!u.password&&!u.search&&!u.hash&&u.pathname==='/'&&Number(u.port)>0&&Number(u.port)<=65535,'RPC URL credentials/path/port');
 assert.deepEqual(n.allowedOrigins,['http://localhost:3000'],'exact Origin allowlist');return true;
}
function provenance(s){keys(s,['coreCommit','flowCommit','overlayArchiveSha256','candidateState','productionApproved'],'source');assert.equal(s.coreCommit,CORE);assert.equal(s.flowCommit,FLOW);assert.equal(s.overlayArchiveSha256,OVERLAY);assert.equal(s.candidateState,'draft-unmerged');assert.equal(s.productionApproved,false,'PR is not operationally approved');}
export function validateProfile(p){
 keys(p,['schemaVersion','profile','deploymentEnabled','transactionsEnabled','network','source','assets','wrappedNative','dependencies','limits'],'profile');assert.equal(p.schemaVersion,1);assert.equal(p.profile,'lqc-devnet-mvp');assert.equal(p.deploymentEnabled,false,'deployment disabled');assert.equal(p.transactionsEnabled,false,'transactions disabled');network(p.network);provenance(p.source);
 assert.deepEqual(p.assets,{native:{kind:'native',address:null,decimals:18,denom:'atest'},tokenA:{kind:'test-erc20',address:null,decimals:18,contractRef:'mvp.tokenA'},tokenB:{kind:'test-erc20',address:null,decimals:6,contractRef:'mvp.tokenB'},wrappedNative:{kind:'test-wrapped-native',address:null,decimals:18,contractRef:'mvp.wrappedNative',canonical:false}},'initial assets/decimals');
 assert.deepEqual(p.wrappedNative,{artifact:'MockWBNB',canonical:false,onChainSymbol:'WBNB',displayAlias:'Wrapped TEST (test-only)'},'test wrapper only');assert.deepEqual(p.dependencies,{pancakeLookup:false,bscAddressReuse:false,externalRpc:false},'no BSC/Pancake dependencies');assert.deepEqual(p.limits,{gasCap:10000000,simulationTimeoutMs:2000,nodeLifetimeSeconds:240},'fixed limits');return true;
}
const artifactFor=id=>({'mvp.tokenA':'LQCTestToken','mvp.tokenB':'LQCTestToken','mvp.wrappedNative':'MockWBNB','mvp.factory':'LQCFlowFactory','mvp.pair':'LQCFlowPair','mvp.pairNative':'LQCFlowPair','mvp.router':'LQCFlowRouter'})[id];
export function validateManifest(m){
 keys(m,['schemaVersion','interfaceFamily','chainId','status','transactionsEnabled','source','contracts'],'manifest');assert.equal(m.schemaVersion,1);assert.equal(m.interfaceFamily,'mvp','Router2 namespace forbidden');assert.equal(m.chainId,917001);assert.equal(m.status,'unconfigured');assert.equal(m.transactionsEnabled,false);provenance(m.source);keys(m.contracts,IDS,'MVP contracts');
 for(const id of IDS){const c=m.contracts[id];keys(c,['artifact','abiVersion','chainId','address','transactionHash','runtimeBytecodeSha256','status','creationKind'],'contract '+id);assert.equal(c.artifact,artifactFor(id));assert(c.abiVersion.startsWith('mvp.'),'MVP ABI version');assert.equal(c.chainId,917001);assert.equal(c.address,null,'initial address must remain null');assert.equal(c.transactionHash,null,'initial transaction null');assert.equal(c.runtimeBytecodeSha256,null,'initial code hash null');assert.equal(c.status,'unconfigured');assert.equal(c.creationKind,id.startsWith('mvp.pair')?'factory-internal-create':'top-level-create');}return true;
}
const ctorTypes={LQCTestToken:['string','string','uint8','address'],MockWBNB:[],LQCFlowFactory:['address'],LQCFlowPair:['address','address'],LQCFlowRouter:['address','address']};
export function validateArtifacts(artifacts,registry,build){
 keys(artifacts,ARTIFACTS,'artifacts');assert.equal(build.compiler,'0.8.30+commit.73712a01');assert.deepEqual(build.settings,{optimizer:{enabled:true,runs:200},viaIR:true,evmVersion:'shanghai'});assert.equal(build.flowCommit,FLOW);assert.equal(build.productionApproved,false);
 assert.equal(registry.interfaceFamily,'mvp');assert.equal(registry.flowCommit,FLOW);keys(registry.contracts,ARTIFACTS,'ABI registry');
 for(const n of ARTIFACTS){const a=artifacts[n],r=registry.contracts[n],proof=build.artifacts[n];assert.equal(a.contractName,n);assert(isHexString(a.bytecode)&&a.bytecode.length>2,'creation bytecode');assert(isHexString(a.deployedBytecode)&&a.deployedBytecode.length>2,'runtime bytecode');assert.equal(sha(Buffer.from(a.bytecode.slice(2),'hex')),proof.creationSha256,'creation artifact mismatch');assert.equal(sha(Buffer.from(a.deployedBytecode.slice(2),'hex')),proof.runtimeTemplateSha256,'runtime artifact mismatch');assert.equal(jsonHash(a.abi),proof.abiSha256,'ABI build mismatch');assert.equal(jsonHash(a.abi),r.abiSha256,'ABI registry mismatch');assert.deepEqual(a.abi,r.abi);assert(r.version.startsWith('mvp.'));assert.deepEqual((a.abi.find(x=>x.type==='constructor')?.inputs??[]).map(x=>x.type),ctorTypes[n],'constructor '+n);for(const id of Object.keys(a.immutableReferences??{}))assert(a.immutableNames[id],'immutable name mapping required');}
 const router=new Interface(artifacts.LQCFlowRouter.abi);for(const name of ['addLiquidity','addLiquidityBNB','getAmountsOut','swapExactTokensForTokens'])assert(router.getFunction(name));assert(router.getError('InsufficientAmount'));assert(new Interface(artifacts.LQCFlowFactory.abi).getEvent('PairCreated'));return true;
}
export function validateBundle(b){validateProfile(b.profile);validateManifest(b.manifest);validateArtifacts(b.artifacts,b.registry,b.build);for(const id of IDS)assert.equal(b.manifest.contracts[id].abiVersion,b.registry.contracts[artifactFor(id)].version);return {valid:true,deploymentEnabled:false,transactionsEnabled:false,sourceStatus:'draft-unmerged'};}
const ref=x=>({ref:x});
export function buildPlan(bundle){
 validateBundle(bundle);
 const steps=[
  {id:'mvp.tokenA',artifact:'LQCTestToken',kind:'top-level-create',args:['LQC Local Token A','LQCA',18,ref('deployer')],requires:[]},
  {id:'mvp.tokenB',artifact:'LQCTestToken',kind:'top-level-create',args:['LQC Local Token B','LQCB',6,ref('deployer')],requires:[]},
  {id:'mvp.wrappedNative',artifact:'MockWBNB',kind:'top-level-create',args:[],requires:[]},
  {id:'mvp.factory',artifact:'LQCFlowFactory',kind:'top-level-create',args:[ref('deployer')],requires:[]},
  {id:'mvp.pair',artifact:'LQCFlowPair',kind:'factory-internal-create',args:[ref('mvp.tokenA'),ref('mvp.tokenB')],requires:['mvp.factory','mvp.tokenA','mvp.tokenB']},
  {id:'mvp.pairNative',artifact:'LQCFlowPair',kind:'factory-internal-create',args:[ref('mvp.tokenA'),ref('mvp.wrappedNative')],requires:['mvp.factory','mvp.tokenA','mvp.wrappedNative']},
  {id:'mvp.router',artifact:'LQCFlowRouter',kind:'top-level-create',args:[ref('mvp.factory'),ref('mvp.wrappedNative')],requires:['mvp.factory','mvp.wrappedNative']}
 ];
 const plan={mode:'offline-symbolic-only',chainId:917001,productionApproved:false,steps};validatePlan(plan);return plan;
}
export function validatePlan(p){
 assert.equal(p.mode,'offline-symbolic-only');assert.equal(p.chainId,917001);assert.equal(p.productionApproved,false);assert.deepEqual(p.steps.map(x=>x.id),IDS,'fixed dependency order');const seen=new Set();for(const s of p.steps){assert.equal(s.artifact,artifactFor(s.id));assert.equal(s.kind,s.id.startsWith('mvp.pair')?'factory-internal-create':'top-level-create','Pair must be Factory-created');for(const d of s.requires)assert(seen.has(d),'dependency not ready');seen.add(s.id);}assert.equal(p.steps[0].args[2],18);assert.equal(p.steps[1].args[2],6);return true;
}
export function resolveStep(bundle,step,bindings){
 validateBundle(bundle);assert.equal(bindings.chainId,917001,'binding chain');const allowed=['chainId','deployer',...IDS];assert(Object.keys(bindings).every(k=>allowed.includes(k)),'unknown/Pancake/Router2 binding');assert.equal(step.artifact,artifactFor(step.id));assert.equal(step.kind,step.id.startsWith('mvp.pair')?'factory-internal-create':'top-level-create');
 const values=step.args.map(x=>x&&typeof x==='object'&&'ref'in x?address(bindings[x.ref],x.ref):x);let result={id:step.id,mode:'offline-encoding-only',deploymentExecuted:false};
 if(step.kind==='factory-internal-create'){const factory=address(bindings['mvp.factory']);const [token0,token1]=[...values].sort((a,b)=>BigInt(a)<BigInt(b)?-1:1);assert.notEqual(token0,token1,'identical tokens');const i=new Interface(bundle.artifacts.LQCFlowFactory.abi);return {...result,to:factory,data:i.encodeFunctionData('createPair',values),expectedPairConstructor:{factory,token0,token1},creationKind:'factory-internal-create'};}
 const i=new Interface(bundle.artifacts[step.artifact].abi),constructorData=i.encodeDeploy(values);return {...result,constructorArgs:values,constructorData,creationData:bundle.artifacts[step.artifact].bytecode+constructorData.slice(2)};
}
export function runtimeWithImmutables(a,values){
 const bytes=Buffer.from(a.deployedBytecode.slice(2),'hex');for(const [id,refs]of Object.entries(a.immutableReferences??{})){const name=a.immutableNames[id];assert(Object.hasOwn(values,name),'missing immutable '+name);const encoded=Buffer.from(zeroPadValue(toBeHex(BigInt(values[name])),32).slice(2),'hex');for(const r of refs){assert.equal(r.length,32);assert(r.start>=0&&r.start+r.length<=bytes.length);encoded.copy(bytes,r.start);}}return '0x'+bytes.toString('hex');
}
// A provider is injected by the caller. This module creates no RPC transport,
// signer or deployer. Synthetic observations are never labelled live deployment.
export async function verifyPairObservations(bundle,provider,{factory,tokenA,tokenB,transactionHash}){
 validateBundle(bundle);assert.equal(provider.rpcUrl,bundle.profile.network.rpcUrls[0],'provider endpoint must match configured loopback');factory=address(factory);tokenA=address(tokenA);tokenB=address(tokenB);assert.notEqual(tokenA,tokenB);assert(isHexString(transactionHash,32));assert.equal(BigInt((await provider.getNetwork()).chainId),917001n,'observed chain');
 const receipt=await provider.getTransactionReceipt(transactionHash);assert(receipt,'receipt missing');assert.equal(BigInt(receipt.status),1n,'receipt failure');assert.equal((receipt.hash??receipt.transactionHash).toLowerCase(),transactionHash.toLowerCase(),'transaction hash');assert.equal(address(receipt.to),factory,'receipt not Factory');assert.equal(receipt.contractAddress,null,'Pair is internal CREATE');assert(BigInt(receipt.blockNumber)>0n);assert(isHexString(receipt.blockHash,32));
 const [token0,token1]=[tokenA,tokenB].sort((a,b)=>BigInt(a)<BigInt(b)?-1:1),fi=new Interface(bundle.artifacts.LQCFlowFactory.abi),pi=new Interface(bundle.artifacts.LQCFlowPair.abi);const events=[];
 for(const log of receipt.logs){if(log.address.toLowerCase()!==factory.toLowerCase())continue;let event;try{event=fi.parseLog(log)}catch{continue}if(event?.name==='PairCreated'&&event.args.token0===token0&&event.args.token1===token1)events.push(event);}
 assert.equal(events.length,1,'one matching Factory PairCreated required');const pair=address(events[0].args.pair);assert(events[0].args.pairCount>0n);
 for(const args of [[tokenA,tokenB],[tokenB,tokenA]]){const raw=await provider.call({to:factory,data:fi.encodeFunctionData('getPair',args)});assert.equal(address(fi.decodeFunctionResult('getPair',raw)[0]),pair,'bidirectional getPair mismatch');}
 const factoryCode=await provider.getCode(factory);assert.equal(factoryCode.toLowerCase(),bundle.artifacts.LQCFlowFactory.deployedBytecode.toLowerCase(),'Factory runtime mismatch');
 const code=await provider.getCode(pair);assert(code&&code!=='0x','Pair runtime absent');assert.equal(code.toLowerCase(),runtimeWithImmutables(bundle.artifacts.LQCFlowPair,{factory,token0,token1}).toLowerCase(),'Pair runtime/immutables mismatch');
 for(const [name,wanted]of Object.entries({factory,token0,token1})){const raw=await provider.call({to:pair,data:pi.encodeFunctionData(name)});assert.equal(address(pi.decodeFunctionResult(name,raw)[0]),wanted,'Pair getter mismatch');}
 return {observationsConsistent:true,observationKind:provider.observationKind??'untrusted-input',pair,chainId:917001,runtimeSha256:sha(Buffer.from(code.slice(2),'hex')),deploymentExecuted:false,productionApproved:false};
}
export async function loadBundle(){
 const read=async p=>JSON.parse(await readFile(new URL(p,import.meta.url),'utf8'));
 const profile=await read('../../config/flow/mvp/lqc-devnet.json'),manifest=await read('../../config/flow/mvp/deployments.lqc-devnet.json'),registry=await read('../../config/flow/mvp/abi-registry.json'),build=await read('./build-manifest.json'),artifacts={};for(const n of ARTIFACTS)artifacts[n]=await read('./artifacts/'+n+'.json');return {profile,manifest,registry,build,artifacts};
}
