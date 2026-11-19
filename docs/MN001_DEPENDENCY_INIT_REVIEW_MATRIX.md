# MN-001 dependency initialization and execution review matrix

Status: **SOURCE-LEVEL REVIEW / NOT TEST AUTHORIZATION**  
Review baseline: `c075f7c58b6bf2f8534b3592481f633abcdfa23a`  
Date: 2026-11-19

## Candidate scope (exact eight test names)

| Package | Exact selected test | Source-level observations | Unresolved boundary |
| --- | --- | --- | --- |
| `chain/config` | `TestRuntimeDevnetCompatibility` | Synthetic runtime configuration, validation and JSON round trip | Transitive package initialization |
| `chain/config` | `TestExplicitRuntimeValidation` | Synthetic mainnet config and invalid parameter cases | Transitive package initialization |
| `genesis` | `TestMainnetProposalOfflineValidation` | JSON profile validation and rejection cases | Package init; global state |
| `genesis` | `TestMainnetProfileRejectsDuplicateKeys` | JSON duplicate key rejection | Package init; global state |
| `genesis` | `TestMainnetDraftOfflinePreflight` | Synthetic unfunded Genesis structure, no validators | Package init; global state |
| `genesis` | `TestMainnetDraftRejectsDuplicateJSONKeys` | JSON duplicate key/trailing data rejection | Package init; global state |
| `cmd/lqcd` | `TestOfflineMainnetDraftCLI` | Temp JSON fixtures; in-process Cobra command; no direct app construction in selected command | Imports local `app` and Cosmos SDK/EVM; inspect transitive init and Cobra construction |
| `cmd/lqcd` | `TestReadBoundedOfflineFile` | Temp regular files, symlinks, directory, missing file and oversize rejection | Package init, kernel `openat2` behavior and sandbox file boundaries |

The Linux-only `TestReadBoundedOfflineFileFIFO` is **not** in the existing eight-test allowlist; it remains a proposed ninth test requiring a separate explicit scope decision.

## Verified repository facts

1. `scripts/mn001-offline-regression-candidate.sh` defaults to `LQC_MN001_OFFLINE_TEST_APPROVED=0` and exits without running tests. It rejects execution with `GITHUB_ACTIONS=true`, even when the approval flag is overridden.
2. `cmd/lqcd/main.go` imports local `app` and `genesis`. `app/app.go` imports Cosmos SDK and Cosmos EVM and exposes an application constructor with SDK process-global configuration; no inference about transitive package `init` safety follows from not invoking that constructor in a selected test.
3. `genesis/process_test.go` contains a subprocess helper using `exec.CommandContext` and inherited environment. The existence of this helper does not establish that any of the eight selected tests calls it.
4. `internal/securityaudit/guard.go` scans for etcd SDK access in production source. This is **not** a transitive Cosmos SDK/EVM initialization audit.
5. `go.mod` pins Go 1.25.9, Cosmos SDK 0.54.3, Cosmos EVM 0.7.3, CometBFT 0.39.3. A version pin is not proof of safe package initialization.
6. CI [44497781262](https://github.com/LQC-labs/LQC-Mainnet-Development/actions/runs/44497781262) passed on `c075f7c5`; this is existing preflight, candidate dry-run, and compile evidence, **not** candidate runtime PASS.

## Required evidence before execution approval

- Enumerate the full **resolved transitive import graph** of all three candidate packages for the exact pinned module versions, including test imports, build tags, CGo, and platform-specific files.
- Review all reachable `init()`, package-variable initializers, `TestMain`, side-effect imports, native library loading and filesystem/network/process effects. A test-name filter does not prevent package initialization.
- Trace the eight selected test bodies and helpers for subprocesses, environment inheritance, external network, disk writes, global state mutation, wallet/validator operations and node startup.
- Freeze immutable dependency artifacts and verify checksums before moving them into a disposable isolated Linux runner.
- Prove OS-level network denial, no secrets or production mounts, unprivileged execution, read-only source, writable scratch isolation, resource limits, independent wall-clock timeout, and complete logs.
- Obtain explicit user approval for the exact eight-test scope and runner. Separately decide whether to propose the FIFO fixture as a ninth test.
- Preserve exact commit SHA, runner image digest, dependency graph/hash, commands, normal/race exit codes, cleanup evidence and any failure logs.

## Gate

**Dependency initialization: NOT VERIFIED. Candidate execution: NOT AUTHORIZED.** Do not turn on the approval flag, execute the candidate tests, merge Draft PR #3, proceed to MN-002, or activate mainnet. Keep **MN-001 IN PROGRESS / MAINNET NO-GO**.
