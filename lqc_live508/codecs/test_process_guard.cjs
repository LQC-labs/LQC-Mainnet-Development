'use strict';
// Test preload only. No production entry point uses this file.
const fs = require('node:fs');
function deny(name) {
  if (process.env.LQC_TEST_GUARD_LOG) fs.appendFileSync(process.env.LQC_TEST_GUARD_LOG, name + '\n');
  throw Error('FORBIDDEN_TEST_OPERATION:' + name);
}
const net = require('node:net');
net.Socket.prototype.connect = function() { return deny('net.connect'); };
for (const name of ['connect', 'createConnection', 'createServer']) net[name] = () => deny('net.' + name);
for (const module of ['http', 'https']) {
  const api = require('node:' + module);
  for (const name of ['request', 'get', 'createServer']) api[name] = () => deny(module + '.' + name);
}
require('node:tls').connect = () => deny('tls.connect');
const dns = require('node:dns');
for (const name of ['lookup', 'resolve', 'resolve4', 'resolve6']) dns[name] = () => deny('dns.' + name);
const child = require('node:child_process');
for (const name of ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork']) child[name] = () => deny('child.' + name);
const crypto = require('node:crypto');
for (const name of ['sign', 'createSign', 'createPrivateKey', 'createECDH', 'generateKeyPair', 'generateKeyPairSync', 'generateKey', 'generateKeySync', 'randomBytes']) {
  crypto[name] = () => deny('crypto.' + name);
}
const ethers = require('ethers');
ethers.SigningKey.prototype.sign = function() { return deny('ethers.SigningKey.sign'); };
for (const type of [ethers.Wallet, ethers.HDNodeWallet]) {
  for (const name of ['signTransaction', 'signMessage', 'signTypedData']) type.prototype[name] = function() { return deny('ethers.' + name); };
  for (const name of ['createRandom', 'fromPhrase']) type[name] = () => deny('ethers.' + name);
}
