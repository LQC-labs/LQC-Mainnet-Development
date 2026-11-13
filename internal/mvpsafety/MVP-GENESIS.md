# Explicit MVP Genesis path

Core baseline b79394246a8819a7651275bd07c88b83bccdd8df. This is a separate
local copy of the stage7 guard, not a modification of the original or Snapshot.

The unchanged NewSingleValidator generator issues 3 TEST to one account.
Its validator requires ONE auth account and ONE balance, but does not require
exactly 3 TEST. This distinction corrects the prior broad wording of that gate.

## API and safety boundary

1. The inactive config/flow/mvp/genesis-profile.json has null addresses/public
   keys/home/runId, enabled=false, productionApproved=false. It is never
   activated by reading it. Explicit PrepareMVP(..., optIn=true, ...) is needed.
2. PrepareMVP validates the template, unchanged guard policy, sealed fresh plan,
   public keys/addresses, allocation and existing-account denylist. It passes
   MVPRequest to a fake immediately-before-Open boundary; it does not open a
   home, generate keys, build actual signed Genesis or call node.Open.
3. For a future separately authorized run, a newly generated deployer key signs
   a legacy seed with NewSingleValidator. NewMVP(app, options, signedSeed)
   validates that seed, reuses its exact gentx, and assembles three account
   funding in MEMORY. It never accepts a private key or writes a home.
4. ValidateMVP checks all three auth accounts and bank balances/supply first.
   A one-account memory projection then delegates the existing signed-gentx,
   envelope, chain/profile/module/no-prebonded-injection checks to unchanged
   singleValidatorInputs. Exact 1 TEST self-bond from deployer is required.
   The projection is validation only; it is never the actual node Genesis.
5. CoreMVPFactory{Options: request.Options} implements the existing NodeFactory
   interface. A future approved adapter run can inject it into GoAdapter;
   its Open selects node.OpenMVP. The default CoreNodeFactory stays legacy.
6. node.Open remains a wrapper selecting validateDevnetGenesis. OpenMVP requires
   explicit validated options and selects the MVP validator. Both reuse the
   SAME existing open/identity/key/signing-state/DB/height checks and lifecycle.
   Consensus public key must equal the signed gentx validator public key.

Total funding: 100 TEST gross, deployer/test/reserve 30/20/50, in canonical
18-decimal atest integers. The 1 TEST validator bond comes out of deployer's 30,
leaving 29/20/50 liquid plus 1 bonded. No additional issuance is allowed.
Accounts must match valid compressed eth_secp256k1 public keys and canonical
lqctest addresses; duplicate identities, old denylisted Bech32/EVM accounts,
wrong generation run, overflow/negative/over-cap funding are rejected.

GeneratedRunID is an input provenance claim, NOT cryptographic proof that the
key is fresh. Actual fresh-key generation/custody and complete old-account
inventory must be enforced by the future approved runner. Offline tests use
fixed PUBLIC curve points only, never private keys or a key generator.

Existing policy is byte-for-byte unchanged: 240s overall including cleanup,
20s stage timeout, gas <=5M, A18/B6 cumulative mint <=1000 each, wrapper <=10
TEST, finite fees/intents, localhost-only profile, evidence and fail-closed
cleanup. No existing timeout/cleanup tests were rerun; their existing results
are reused, and the new adapter test confirms the unchanged policy handoff.

## What was tested, and what was not

New tests verify public option validity, 3-account memory funding/conservation,
negative inputs, default rejection of MVP, and fake pre-Open configuration
handoff. A deliberately invalid dummy signature must reach and fail the real
legacy signature verifier; no signature bypass is injectable in production.
Only the key-free TestGenesisDraft existing regression is rerun. The original
signed-validator test is not run because it generates private keys.

A VALID signed 100 TEST gentx, actual InitChain, actual OpenMVP/DB/key consensus
matching, runtime bank conservation, 5M gas sufficiency and real node cleanup
are NOT TESTED under this request's prohibitions. Construction/wiring is
implemented, but end-to-end runtime compatibility is not declared PASS.
Live-execution readiness remains NO-GO until those checks are separately
authorized and pass. No filesystem home/Genesis/key is created by these tests.
