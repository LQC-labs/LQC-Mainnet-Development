'use strict';
// Historical fixture-only event projection, no constructor planner.
const fs = require('node:fs');
const {collect} = require('./receipt_events.cjs');
async function dispatch(input) {
  if (input?.scope !== 'FIXTURE_ONLY' || input.live !== false) throw Error('LiveDisabled');
  if (input.action === 'events') {
    // The prior deployment collector expects contractAddress. Calls use an explicitly
    // marked projection, never a claim that a new contract was deployed.
    const receipt = structuredClone(input.receipt);
    if (input.kind === 'CALL') {
      if (receipt?.contractAddress !== null) throw Error('CallCannotCreate');
      receipt.contractAddress = input.expected.address;
    } else if (input.kind !== 'CREATE') throw Error('OperationKind');
    const result = collect(input.identity, receipt, input.expected, input.abi);
    return {...result, operationKind: input.kind, fixtureOnly: true};
  }
  throw Error('UnsupportedAction');
}
if (require.main === module) {
  const raw = fs.readFileSync(0);
  if (raw.length > 4000000) { process.exitCode = 1; }
  else dispatch(JSON.parse(raw)).then(x => process.stdout.write(JSON.stringify(x))).catch(() => {
    // No request bodies, external error messages, signatures or keys in diagnostics.
    process.stderr.write('OFFLINE_CODEC_REJECTED\n'); process.exitCode = 1;
  });
}
module.exports = {dispatch};
