'use strict';
// Offline hashing ONLY. No Wallet, signer, provider, key or network API.
const fs = require('node:fs');
const {keccak256} = require('ethers');
const raw = fs.readFileSync(0);
if (!raw.length || raw.length > 131072) process.exitCode = 1;
else process.stdout.write(keccak256(raw));
