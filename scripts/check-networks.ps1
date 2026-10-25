# Copyright 2026 MMXlabs & LQC LLC
# SPDX-License-Identifier: Apache-2.0

$n = Get-Content "$PSScriptRoot\..\config\networks.example.json" -Raw | ConvertFrom-Json
if ($n.bscMainnet.chainId -ne 56) { throw "Invalid BSC Mainnet" }
if ($n.bscTestnet.chainId -ne 97) { throw "Invalid BSC Testnet" }
Write-Host "BSC settings PASS"
if ($n.lqcDevnet.chainId -in @(56,97)) { throw "LQC Devnet conflict" }
if ($n.lqcMainnet.chainId -in @(56,97)) { throw "LQC Mainnet conflict" }
if ($null -ne $n.lqcDevnet.chainId -and $n.lqcDevnet.chainId -eq $n.lqcMainnet.chainId) { throw "LQC ID conflict" }