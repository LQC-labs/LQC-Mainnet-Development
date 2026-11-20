# Copyright 2026 MMXlabs & LQC LLC
# SPDX-License-Identifier: Apache-2.0

$n = Get-Content "$PSScriptRoot\..\config\networks.example.json" -Raw | ConvertFrom-Json
if ($n.bscMainnet.chainId -ne 56) { throw "Invalid BSC Mainnet" }
if ($n.bscTestnet.chainId -ne 97) { throw "Invalid BSC Testnet" }
Write-Host "BSC settings PASS"
if ($n.lqcDevnet.chainId -in @(56,97,9001)) { throw "LQC Devnet conflict" }
if ($n.lqcMainnet.chainId -in @(56,97,9001)) { throw "LQC Mainnet conflict" }
if ($n.lqcMainnet.chainId -eq 917001) { throw "Devnet Chain ID cannot be used by LQC Mainnet" }
if ($null -ne $n.lqcDevnet.chainId -and $n.lqcDevnet.chainId -eq $n.lqcMainnet.chainId) { throw "LQC ID conflict" }
if ($n.lqcMainnet.chainId -ne 768167 -or $n.lqcMainnet.cosmosChainId -cne "lqc-1" -or
    $n.lqcMainnet.nativeDenom -cne "alqc" -or $n.lqcMainnet.displayDenom -cne "LQC" -or
    $n.lqcMainnet.decimals -ne 18 -or $n.lqcMainnet.bech32Prefix -cne "lqc") {
    throw "Invalid approved LQC Mainnet identity"
}
if ($n.lqcMainnet.rpcUrls -isnot [array] -or $n.lqcMainnet.rpcUrls.Count -ne 0) {
    throw "Mainnet RPC must remain unset"
}
Write-Host "LQC Mainnet identity PASS; Mainnet RPC unset"
