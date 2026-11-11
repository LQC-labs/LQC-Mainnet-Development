'use strict';
// Decode / recover only. No Wallet, key, signing, Provider or network instance.
const fs = require('node:fs');
const {Transaction, keccak256} = require('ethers');
const N = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');

function decode(raw) {
  if (typeof raw !== 'string' || !/^0x(?:[0-9a-f]{2})+$/.test(raw) || raw.length > 262146) throw Error('RawShape');
  const tx = Transaction.from(raw);
  if (tx.type !== 2 || !tx.isSigned() || !tx.signature) throw Error('SignedType2Required');
  const r = BigInt(tx.signature.r), s = BigInt(tx.signature.s);
  if (r <= 0n || r >= N || s <= 0n || s > N / 2n || ![0, 1].includes(tx.signature.yParity)) throw Error('NonCanonicalSignature');
  if (tx.accessList.length !== 0 || tx.blobVersionedHashes !== null || tx.authorizationList !== null) throw Error('UnapprovedExtensions');
  if (tx.serialized !== raw || tx.hash !== keccak256(raw)) throw Error('NonCanonicalTransaction');
  const sender = tx.from; // ethers secp256k1 recovery over the EIP-1559 signing hash
  if (!sender) throw Error('SignerRecoveryFailed');
  return {schema: 'LQC_EVM_RECOVERY_V1', type: 2, sender: sender.toLowerCase(),
    chainId: tx.chainId.toString(), nonce: tx.nonce.toString(), to: tx.to === null ? null : tx.to.toLowerCase(),
    value: tx.value.toString(), data: tx.data, gasLimit: tx.gasLimit.toString(),
    maxFee: tx.maxFeePerGas.toString(), maxPriority: tx.maxPriorityFeePerGas.toString(),
    accessList: [], txHash: tx.hash, evmSigningHash: tx.unsignedHash};
}

if (require.main === module) {
  try {
    const raw = fs.readFileSync(0);
    if (raw.length > 262144) throw Error('InputLimit');
    const input = JSON.parse(raw);
    if (!input || Object.keys(input).sort().join(',') !== 'rawTransactionHex') throw Error('InputFields');
    process.stdout.write(JSON.stringify(decode(input.rawTransactionHex)));
  } catch (_) {
    process.stderr.write('EVM_TRANSACTION_REJECTED\n');
    process.exitCode = 1;
  }
}
module.exports = {decode};
