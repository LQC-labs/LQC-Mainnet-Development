'use strict';
const {createHash}=require('node:crypto');
const e=require('ethers');
const sha=b=>createHash('sha256').update(b).digest('hex');
const hash=x=>typeof x==='string'&&/^0x[0-9a-fA-F]{64}$/.test(x);
const addr=x=>e.isAddress(x)&&x.toLowerCase()!==e.ZeroAddress;
function collect(identity,receipt,expected,abi){
 if(identity?.chainId!==917001||!/^[a-f0-9]{32}$/.test(identity.runId||'')||!/^[a-f0-9]{64}$/.test(identity.genesisSHA256||''))throw Error('RunBinding');
 if(!receipt)return {status:'INCOMPLETE',events:null,reason:'MISSING_RECEIPT'};
 if(expected.runId!==identity.runId||expected.genesisSHA256!==identity.genesisSHA256||expected.chainId!==917001)throw Error('ExpectedBinding');
 if(!hash(expected.txHash)||!addr(expected.address)||!hash(expected.blockHash)||!Number.isSafeInteger(expected.blockNumber)||expected.blockNumber<1)throw Error('ExpectedObservedLink');
 if(typeof receipt.blockNumber!=='string'||!/^0x[1-9a-f][0-9a-f]*$/.test(receipt.blockNumber))throw Error('ReceiptBlockQuantity');
 if(receipt.status!=='0x1'||receipt.transactionHash!==expected.txHash||receipt.blockHash!==expected.blockHash||Number(BigInt(receipt.blockNumber))!==expected.blockNumber||receipt.contractAddress?.toLowerCase()!==expected.address.toLowerCase())throw Error('ReceiptLink');
 if(!Array.isArray(receipt.logs)||!Array.isArray(expected.requiredEvents))throw Error('LogEvidenceMissing');
 const iface=new e.Interface(abi),seen=new Set(),events=[];
 for(const log of receipt.logs){
  if(log.removed!==false||log.address?.toLowerCase()!==expected.address.toLowerCase()||log.transactionHash!==expected.txHash||log.blockHash!==expected.blockHash||log.blockNumber!==receipt.blockNumber)throw Error('LogLink');
  if(!/^0x(?:0|[1-9a-f][0-9a-f]*)$/.test(log.logIndex)||seen.has(log.logIndex))throw Error('LogIndex');
  seen.add(log.logIndex);
  if(!Array.isArray(log.topics)||!log.topics.every(hash)||typeof log.data!=='string'||!/^0x(?:[a-fA-F0-9]{2})*$/.test(log.data))throw Error('LogEncoding');
  const decoded=iface.parseLog({topics:log.topics,data:log.data});if(!decoded)throw Error('UnknownEvent');
  const encoded=iface.encodeEventLog(decoded.fragment,decoded.args);
  if(encoded.data.toLowerCase()!==log.data.toLowerCase()||JSON.stringify(encoded.topics.map(x=>x.toLowerCase()))!==JSON.stringify(log.topics.map(x=>x.toLowerCase())))throw Error('NonCanonicalEvent');
  events.push({name:decoded.name,signature:decoded.signature,address:log.address.toLowerCase(),logIndex:log.logIndex,topics:encoded.topics,data:encoded.data});
 }
 for(const name of expected.requiredEvents)if(!events.some(x=>x.name===name))throw Error('RequiredEventMissing');
 const projection={runId:identity.runId,chainId:917001,genesisSHA256:identity.genesisSHA256,transactionHash:expected.txHash,blockHash:expected.blockHash,blockNumber:receipt.blockNumber,address:receipt.contractAddress.toLowerCase(),status:receipt.status,events};
 return {status:'EVENTS_VERIFIED_ONLY_NOT_DEPLOYMENT_PASS',projection,eventsSHA256:sha(JSON.stringify(projection))};
}
module.exports={collect};
