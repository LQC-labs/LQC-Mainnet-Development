# Stage 7 isolated execution guard

This directory is a new local copy. Original Core, previous MVP work and the
verified Snapshot are inputs only. No existing node home is opened by the tests.
The Go package is internal/mvpsafety; the inactive sidecar policy is
config/flow/mvp/execution-policy.json. Existing profile/manifest/ABI/artifact
files are read, not rewritten. Draft Flow PR #447 remains a test candidate.

## Funding plan (no keys or Genesis generated)

Amounts are canonical unsigned uint256 decimal strings, in base units. The
gross Genesis allocation is exactly 100 TEST: deployer 30, test 20, reserve 50.
One TEST validator bond is taken from the deployer's 30; planned liquid funds
are therefore 29/20/50 plus 1 bonded, with no extra issuance. This interpretation
must be retained or explicitly reviewed before a future live Genesis path.
Token A (18 decimals) cumulative mint cap: 1000000000000000000000 units.
Token B (6 decimals) cumulative mint cap: 1000000000 units.
Wrapper cumulative deposit cap: 10000000000000000000 native units.
Reservations are cumulative and not refunded by retries, withdrawals or burns;
duplicate intent IDs permanently block that budget instance.

Overall deadline: 240 seconds, including a 50-second cleanup reserve. Per-stage:
20 seconds; close/proof: 5 seconds each, at most four owned resources; evidence:
2 seconds. Transaction gas cap: 5,000,000. Additional conservative proposals:
maxFeePerGas <= 2 gwei, at most 64 intents. Missing/excessive estimates fail
closed. Constructor encoding checks a mandatory gas lower bound, not a full
execution estimate. Actual deployment sufficiency remains NOT TESTED. No bound
is automatically increased. Existing profile gasCap=10M is preserved; this
guard applies the stricter 5M effective limit.

## Node and lifecycle adapter

CoreNodeFactory is compiled against existing node.Open, Start,
StartEVMRPCWithOptions, Close. Tests inject fake implementations; the real Open
method is never called. Explicit isolated-local authorization is required even
to enter the adapter. An incompatible funding plan is rejected before Open.
The current real factory ALWAYS rejects this 100 TEST / three-account policy:
the existing signed-gentx generator/validator is fixed to 3 TEST / one account.
No validator check is bypassed and no legacy Genesis code is changed.

Coordinator cancellation stops progression, closes resources in reverse order,
checks listener/DB/home locks and saves evidence. A failure, timeout, unjoined
callback, missing proof or evidence-write failure cannot produce PASS and the
coordinator cannot run again. Arbitrary in-process Go callbacks cannot be
forcibly killed: an unjoined real Core Close would remain BLOCKED. Child process
groups receive TERM then KILL and have exactly one cmd.Wait reaper. The child
unit test executes only /bin/sleep, not a blockchain node. Fake child termination
failure and lock retention are separate negative tests. No claim of real DB/RPC
cleanup testing is made by these offline results.

MVP constructors and unsigned calldata are ABI-encoded in dependency order.
Pair is created through Factory, never deployed as a top-level transaction.
Pair observation requires Factory PairCreated, both getPair directions, exact
runtime template with factory/token immutables and matching getters. Tests use
read-only fakes; no RPC connection, deployment, signing or mint is performed.
MVP namespace is separate from Router 2.0. Known BSC addresses and BSC chains
are rejected; arbitrary address provenance still requires a future fresh-run
receipt/account-generation proof, not an address string alone.

## Outstanding hard gates

1. A separately implemented and tested 100 TEST / three-account signed-gentx
   Genesis path compatible with node.Open validation. Do not alter/bypass the
   legacy 3 TEST path to make the new plan pass.
2. Future explicit approval for new ephemeral keys/Genesis/node/deployment and
   fresh account/contract provenance; offline fake observations are not live
   execution evidence.
3. Actual local gas estimates and live resource cleanup under the 240s bound;
   insufficient proposed bounds require BLOCKED, never automatic increases.

Final live-execution readiness is NO-GO until these gates are resolved.
