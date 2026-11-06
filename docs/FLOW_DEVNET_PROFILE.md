# LQC Devnet Flow profile — Core 3/3

Status: local configuration/preflight scaffolding. Actual Flow dApp, wallet,
liquidity, Oracle, governance wiring and LQC Flow deployment are NOT TESTED.
No transaction/deployment/signer capability is provided by this module.

## Separate profiles

`config/flow/lqc-devnet.json` is opt-in. It does not replace
`config/networks.example.json`, BSC 56/97, or the Flow repository's BSC UI config.
Core baseline: `957889bdb2e5709ce23e71f7c5536936ee187851`, plus preserved local
Core 3/2 changes. Flow interface source:
`LQC-labs/LQC-Liquidity-chain@8db16368b3e09a94bfd500a17e33e3e9ef62ed51`.

| Setting | Devnet value |
|---|---|
| Cosmos chain | lqc-devnet-test-1 |
| EVM chain | 917001 / 0xdfe09 |
| Bech32 | lqctest |
| Base/display | atest (exponent 0) / test (exponent 18) |
| Wallet native currency | LQC Devnet Test / TEST / 18 decimals |
| Local RPC | http://127.0.0.1:8545 |
| Explicit browser Origin | http://localhost:3000 |
| Mainnet EVM Chain ID | null / undecided |

The RPC URL is an intended local endpoint, not evidence that a node is listening
on 8545. Existing Core tests use ephemeral ports. Any endpoint change must pass
profile validation and be matched by the local node's listener.

Native `atest` has no ERC-20 address. Flow ERC-20 and wrapped native are separate
assets. Both addresses remain null. Flow token decimals are unconfirmed/null;
native and intended wrapped-native decimals are 18. This is not token issuance,
bridging, migration of BSC balances, or an adopted Mainnet monetary profile.
`displayToBase`/`baseToDisplay` convert exact decimal strings using BigInt;
Number, exponent notation and precision beyond 18 fractional places are refused.

## Interfaces and deployment records

- `abi-registry.json`: independent versioned, **partial** human-readable ABI
  fragments, their SHA-256 over UTF-8 JSON.stringify(abi), source commit/path
  and Git blob SHA. Functions were checked against the pinned Flow sources.
- `deployments.lqc-devnet.json`: 11 configured interface slots plus unimplemented
  Launchpad. Every address/transaction/runtime hash starts null. No deployed or
  verified status can be self-asserted in this file.
- The IERC20/IWBNB slots describe interfaces, not deployable implementations.
  Full compiled ABIs, events/errors and source-to-runtime compiler provenance
  remain future requirements. The Oracle entry is Lending `getPrices(address)`,
  not the different Futures `getPrice(address)` or `getPrice()` interface.

After a separately approved local deployment, a record can become a `candidate`
with chainId, nonzero contractAddress, transactionHash, ABI version and
`runtimeBytecodeSha256`. This hash is SHA-256 of decoded runtime bytecode bytes,
not of the textual hex and not Ethereum's Keccak code hash. Token/wrapper profile
addresses must match their manifest entries. BSC identities and recorded BSC
token/router/vault addresses are rejected. The denylist is an additional guard,
not an exhaustive inventory of all BSC addresses.

`verifyLocalDeployment` checks the validated local RPC's chain ID, nonempty
runtime/hash and successful deployment receipt/address/transaction/block fields.
It returns ephemeral evidence without changing the manifest. It does not prove
that a supplied ABI describes that runtime, perform a Solidity audit, validate
all module wiring, or authorize trading. All transaction gates stay disabled.
Mock tests of this verifier are not actual LQC deployments.

## Local browser and wallet access

Load the three JSON files explicitly and call `validateBundle`. No global
`window.LQC_FLOW_CONFIG` or existing BSC service is changed.
`quoteNetworksForDevnet(profile, existingNetworks)` creates a separate map for
the existing `getQuoteChainId` adapter while preserving BSC and null Mainnet.
`walletRequests(profile)` prepares add/switch payloads only; it does not invoke
the wallet, request accounts/signatures or send transactions.

Core's default StartEVMRPC still rejects browser Origins. For a future approved
new isolated Devnet, the matching API configuration is:

```go
address, err := n.StartEVMRPCWithOptions(ctx, "127.0.0.1:8545", node.RPCBrowserOptions{
    AllowedOrigins: []string{"http://localhost:3000"},
})
```

This snippet is configuration guidance, not a command to start an existing home.
The node must retain numeric loopback binding. CORS wildcard, external Host,
unlisted Origin, invalid preflight and Private Network Access preflight remain
rejected. Do not loosen these protections to support a remotely hosted/mobile
dApp. Browser local-network permissions and real wallet behavior need separate
verification; no public RPC or explorer URL is invented here.

`localRPCTransport(profile)` uses only the validated numeric HTTP loopback URL,
POST JSON-RPC, credentials omitted, redirects refused, and a 3-second abort
deadline. Its method allowlist is chainId/getCode/getTransactionReceipt only.
Browser Origin headers are browser-generated, not forged by JavaScript.
No transport reads local keys. `transactionGate()` always returns disabled in
this preparatory stage, including when an ABI/address is missing.

## Local checks

Use Node 22.16.0 and Go 1.25.9 in Linux:

```sh
node --test scripts/flow-devnet-profile.test.mjs
node --test scripts/flow-quote-adapter.test.mjs
go test -mod=readonly -p=2 -count=1 ./...
go build -mod=readonly -p=2 ./...
```

The first suite validates config, exact amounts, source/digest/version checks,
wallet payloads, fail-closed behavior and mocked read-only RPC responses. It
does not deploy Flow contracts. Ordinary Go tests preserve the explicit opt-in
requirement for live nodes; Core 3/2 runtime regression can be run separately
only with a new isolated Linux home. The existing CI workflow is unchanged;
the new profile suite is explicitly run locally and not yet added to CI.

Next gates: select/deploy an approved test ERC-20 and wrapped native, pin full
compiled artifacts/runtime hashes, verify receipts and decimals on 917001,
wire permissions and dependencies, then test a real local browser/wallet and
one bounded Flow route. Oracle/Lending/Futures/Intent settlement need their own
activation and economic/security checks. Launchpad remains unimplemented.
