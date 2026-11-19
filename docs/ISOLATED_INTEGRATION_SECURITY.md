# Isolated integration candidate

Baseline: `b79394246a8819a7651275bd07c88b83bccdd8df` on `dev/lqc-core`.
This candidate is not deployed, published, or approved for mainnet.

## Dependency and source boundaries

The main module remains on Go 1.25.9 with unchanged go.mod and go.sum.
P0-A/P0-B custody remains a separate sibling module, tested with Go 1.26.11.
It is not imported by the main module and its existing evidence is preserved.
Adding it to main later requires a separate dependency/version review.

The three reviewed changes isolate genesis process globals, improve RPC height
observations/synchronization, and provide an explicit MVP validator dispatch.
Default node.Open still selects validateDevnetGenesis. OpenMVP is an exported
Linux opt-in API, not a cryptographic authorization boundary; review its callers
before any production integration. The inherited Stage 7 documents describe
their original stage and do not establish current operational readiness.

The selected JSON ABI/bytecode artifacts are inert text fixtures needed by
LoadConfig and provenance tests. They are not executed or deployed here.
No new runtime executable, DB, node_modules, key, backup archive, or private
credential is included. Historical tracked verification source.tar files remain
unchanged baseline material; no additional backup archives are introduced.

## Security and CI

The SDK AST scanner rejects direct etcd SDK imports in ordinary Go files,
including inactive build variants and nested modules. It excludes _test.go and
testdata and rejects production imports of testdata. Historical bypass samples
are parsed as text fixtures, never compiled or connected to etcd.
This does not prove dependency safety, process isolation, server RBAC, credential
ownership, or absence of arbitrary network/RPC access.

The new workflow is manual-only until reviewed. It pins Go and action revisions,
uses read-only repository permissions and disables persisted checkout credentials.
Its explicit test allowlist excludes validator signing and node startup. All
packages are also compiled with -run '^$'. The preexisting current-source workflow
still runs its original broader suite; this candidate does not change it. Its
existing unflagged synthetic validator-signing test needs separate review before
claiming all CI is non-signing. No GitHub workflow has been executed here.

P0 CI must run in a separate Go 1.26.11 job against an explicitly reviewed P0
module location, with mock-only full and Race tests and final errBoundaryDenied
checks. Do not wire the sibling module into main or enable real credentials just
to make CI run. Real custody, mTLS identity and least-privilege etcd RBAC require
independent evidence before any operational security PASS.

## Application order

1. Recheck the remote HEAD and review the supplied complete patch and hashes.
2. Review the three shared-file changes and the MVP dependency/fixture closure.
3. Apply the security checker and manual Linux preflight candidate separately.
4. Reproduce the recorded non-signing unit and Race checks on a clean Linux runner.
5. Resolve any resource-blocked checks; separately approve any node/signing tests.
6. Review a future P0 dependency and credentials/RBAC integration as its own change.

allow_signing=false; recovery_authorized=false; signing_history_complete=false.
Public mainnet remains NO-GO.

## MN-001 current-branch CI evidence reconciliation (2026-11-19)

This section applies specifically to `integration/mn001-v29-validation-20261117`
and supersedes the historical current-source workflow description above **for
this branch only**. The earlier section records the isolated candidate's state
at its creation; it is not a claim about today's workflow configuration.

- `.github/workflows/lqc-core-current-linux.yml` now invokes
  `bash scripts/security-preflight-linux.sh`. That script runs exact-name
  allowlists for securityaudit, mvpsafety, and selected chain/config, app,
  genesis, and node tests, repeats those selections with `-race`, and compiles
  all Go package test binaries without executing their test bodies.
- The allowlisted runs do not establish a full-suite or full operational
  security PASS. The current allowlist excludes newly introduced offline
  mainnet draft tests. In particular, `./cmd/lqcd` is compile-only in this
  workflow, not an executed allowlisted test package.
- The eight identified offline regression candidates are
  `TestRuntimeDevnetCompatibility`, `TestExplicitRuntimeValidation`,
  `TestMainnetProposalOfflineValidation`,
  `TestMainnetProfileRejectsDuplicateKeys`,
  `TestMainnetDraftOfflinePreflight`,
  `TestMainnetDraftRejectsDuplicateJSONKeys`,
  `TestOfflineMainnetDraftCLI`, and `TestReadBoundedOfflineFile`.
  These are **candidates**, not newly approved tests. Review package
  initialization, dependencies, and test call graphs before expanding any
  exact-name allowlist. Keep signing, validator startup, subprocess, and
  network-sensitive tests quarantined pending separate authorization.
- The GitHub Actions Core run 44046014343 reported success at commit
  `a809a852dd36c3ad18727f7cbc450d211f31be05`; this is evidence only
  for the jobs and checks actually executed at that commit. No new CI run
  or eight-test PASS is asserted by this documentation change.
- The sibling P0-A/P0-B Go 1.26.11 module is not integrated into the main
  module. Its source location, separate mock-only CI, full Race evidence,
  mTLS identity, RBAC, and real operational controls remain unverified here.

MN-001 remains IN PROGRESS. Do not advance to MN-002 or authorize public
mainnet activation without the separately required evidence. Public mainnet
remains NO-GO; `allow_signing=false`.
