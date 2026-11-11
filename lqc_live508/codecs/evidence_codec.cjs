'use strict';
// Local ABI codec only. Reuses the original receipt event collector unchanged.
const fs = require('node:fs');
const e = require('ethers');
const {collect} = require('./receipt_events.cjs');
const need = (value) => { if (!value) throw Error('EvidenceRejected'); };
const plain = value => typeof value === 'bigint' ? value.toString() : Array.isArray(value) ? value.map(plain) :
  typeof value === 'string' && /^0x/.test(value) ? value.toLowerCase() : value;

async function plan(tx, operation, artifacts) {
  need(operation.kind === (tx.to === null ? 'CREATE' : 'CALL'));
  const target = tx.to === null ? e.getCreateAddress({from: tx.from, nonce: tx.nonce}).toLowerCase() : tx.to;
  need(target === operation.target);
  const targetContract = operation.contracts.find(c => c.address === target);
  need(targetContract);
  const artifact = artifacts[targetContract.artifactId], iface = new e.Interface(artifact.abi);
  if (tx.to === null) {
    need(operation.call === null && Array.isArray(operation.constructorArgs));
    const unsigned = await new e.ContractFactory(artifact.abi, artifact.bytecode).getDeployTransaction(...operation.constructorArgs);
    need(unsigned.data.toLowerCase() === tx.data);
  } else {
    need(operation.constructorArgs === null && operation.call &&
         iface.encodeFunctionData(operation.call.function, operation.call.args).toLowerCase() === tx.data);
  }
  const contracts = {};
  for (const c of operation.contracts) {
    const abi = new e.Interface(artifacts[c.artifactId].abi);
    const queries = c.getters.map(g => {
      const fragment = abi.getFunction(g.function);
      need(fragment && ['view', 'pure'].includes(fragment.stateMutability));
      const expected = abi.encodeFunctionResult(fragment, g.expected).toLowerCase();
      const decoded = abi.decodeFunctionResult(fragment, expected);
      return {name: g.name, data: abi.encodeFunctionData(fragment, g.args).toLowerCase(), gas: '0x' + BigInt(g.gas).toString(16),
              expectedResult: expected, expectedValue: plain(decoded.length === 1 ? decoded[0] : decoded)};
    });
    const events = c.events.map(v => {
      const fragment = abi.getEvent(v.signature); need(fragment);
      const encoded = abi.encodeEventLog(fragment, v.args);
      return {name: fragment.name, topics: encoded.topics.map(x => x.toLowerCase()), data: encoded.data.toLowerCase()};
    });
    contracts[c.address] = {queries, events};
  }
  return {kind: operation.kind, target, contracts};
}

async function dispatch(input) {
  need(['plan', 'verify'].includes(input.action));
  const prepared = await plan(input.tx, input.operation, input.artifacts);
  if (input.action === 'plan') return prepared;
  const receipt = input.receipt, emitters = {}, getters = {};
  need(receipt.status === '0x1');
  const allowed = new Set(input.operation.contracts.map(c => c.address));
  need(receipt.logs.every(log => allowed.has(log.address.toLowerCase())));
  for (const c of input.operation.contracts) {
    const abi = new e.Interface(input.artifacts[c.artifactId].abi);
    // Explicit emitter-only projection. Original CREATE/CALL receipt is retained.
    const projection = structuredClone(receipt);
    projection.logs = receipt.logs.filter(log => log.address.toLowerCase() === c.address);
    projection.contractAddress = c.address;
    const expected = {...input.identity, txHash: receipt.transactionHash, address: c.address,
      blockHash: receipt.blockHash, blockNumber: Number(BigInt(receipt.blockNumber)),
      requiredEvents: prepared.contracts[c.address].events.map(v => v.name)};
    const verified = collect(input.identity, projection, expected, input.artifacts[c.artifactId].abi);
    const wire = log => JSON.stringify({topics: log.topics.map(x => x.toLowerCase()), data: log.data.toLowerCase()});
    need(JSON.stringify(projection.logs.map(wire).sort()) === JSON.stringify(prepared.contracts[c.address].events.map(wire).sort()));
    emitters[c.address] = {...verified, projectionKind: 'EMITTER_ONLY_NOT_CREATE', operationKind: prepared.kind};
    getters[c.address] = {};
    for (let i = 0; i < c.getters.length; i++) {
      const g = c.getters[i], q = prepared.contracts[c.address].queries[i];
      const raw = input.observations[c.address].getters[g.name];
      const decoded = abi.decodeFunctionResult(g.function, raw);
      need(abi.encodeFunctionResult(g.function, decoded).toLowerCase() === raw && raw === q.expectedResult);
      getters[c.address][g.name] = {raw, value: plain(decoded.length === 1 ? decoded[0] : decoded), expected: q.expectedValue};
    }
  }
  return {emitters, getters};
}

if (require.main === module) {
  const raw = fs.readFileSync(0);
  if (raw.length > 4000000) process.exitCode = 1;
  else {
    try {
      dispatch(JSON.parse(raw)).then(x => process.stdout.write(JSON.stringify(x))).catch(() => {
        process.stderr.write('EVIDENCE_CODEC_REJECTED\n'); process.exitCode = 1;
      });
    } catch (_) { process.stderr.write('EVIDENCE_CODEC_REJECTED\n'); process.exitCode = 1; }
  }
}
module.exports = {dispatch};
