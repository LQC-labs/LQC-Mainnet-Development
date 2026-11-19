# MN-001 offline regression execution boundary review

Status: **REVIEW IN PROGRESS — NO EXECUTION APPROVAL**  
Scope: `integration/mn001-offline-gate-hardening-20261119`, after Linux CI run 44461896243 succeeded.

## Confirmed evidence

- GitHub Actions run [44461896243](https://github.com/LQC-labs/LQC-Mainnet-Development/actions/runs/44461896243) completed successfully on 2026-11-19. It verified Bash syntax, the candidate script's default dry-run, and the existing reviewed security preflight. **It did not execute the eight candidate tests.**
- `scripts/mn001-offline-regression-candidate.sh` defaults to no execution unless `LQC_MN001_OFFLINE_TEST_APPROVED=1`. It selects exactly two `chain/config`, four `genesis`, and two `cmd/lqcd` test names, with regular and race modes.
- Reviewed the bodies of all eight selected tests: `chain/config/runtime_test.go`, `genesis/mainnet_test.go`, `genesis/mainnet_draft_test.go`, `genesis/mainnet_json_test.go`, `cmd/lqcd/mainnet_draft_test.go`, and `cmd/lqcd/mainnet_draft_limits_test.go`. Selected bodies operate on synthetic configuration, JSON, and temporary files.
- Reviewed direct production call paths: `chain/config/runtime.go`, `genesis/mainnet.go`, `genesis/mainnet_draft.go`, `genesis/mainnet_json.go`, `cmd/lqcd/mainnet_draft.go`, and `cmd/lqcd/main.go`. The selected CLI subcommand only reads bounded files and performs offline validation.
- A separate CLI subcommand `single-validator create` **can generate ephemeral keys and sign a gentx** (`cmd/lqcd/single_validator.go`). It is registered but is not selected by `TestOfflineMainnetDraftCLI`. `genesis/process_test.go` defines a subprocess helper; it is not called by the selected eight test bodies.
- No `func init()` or `func TestMain()` was identified in the inspected project source files, but this is **not** a full audit of imported packages or all transitive initialization.

## Outstanding approval blockers

1. Verify package-level initialization and `TestMain` across all relevant project packages and transitive dependencies; do not infer safety from test names alone.
2. Verify complete indirect call paths, including Cobra command construction and package initialization, to exclude key generation, signing, node startup, external RPC, and network side effects.
3. Establish an isolated Linux runner policy with explicit read-only repository permissions, no secrets, no credentials persistence, no external service deployment, and bounded runtime.
4. Only after recording evidence for 1–3 may the eight exact tests be approved for isolated execution. The current CI must retain `LQC_MN001_OFFLINE_TEST_APPROVED=0`.

## Non-goals / prohibitions

This review does **not** approve PR merge, mainnet Genesis adoption, validator signing, node startup, deployment, operational mTLS/RBAC, P0-A/P0-B closure, MN-002, or mainnet activation. Follow GitHub Terms of Service, Acceptable Use Policies, and Actions/Pages usage restrictions; GitHub Pages must not host commercial DEX trading operations.

**Gate: MN-001 IN PROGRESS; MAINNET NO-GO.**

## Additional exact-test call-path review (2026-11-19)

The eight selected test functions were re-read directly from the current branch:

| Package | Exact selected functions | Direct effects observed |
| --- | --- | --- |
| `chain/config` | `TestRuntimeDevnetCompatibility`, `TestExplicitRuntimeValidation` | Synthetic in-memory config, JSON serialization, table-driven validation; no file or CLI invocation. |
| `genesis` | `TestMainnetProposalOfflineValidation`, `TestMainnetProfileRejectsDuplicateKeys`, `TestMainnetDraftOfflinePreflight`, `TestMainnetDraftRejectsDuplicateJSONKeys` | Synthetic JSON fixtures and in-memory profile/draft validation. The tests do not invoke `runGenesisTestInSubprocess`, `NewSingleValidator`, or `withGenesisApp`. |
| `cmd/lqcd` | `TestOfflineMainnetDraftCLI`, `TestReadBoundedOfflineFile` | Temporary local JSON files and Cobra `genesis validate-mainnet-draft`; regular-file size/error checks. The tests do not select `single-validator create`. |

**Boundary limitation:** Go loads/initializes each package and its imports before `-run` selects a test. Therefore exact-name filtering prevents other test **bodies** from running but does not, by itself, rule out imported-package `init` side effects. The repository's `single-validator create` command has a signing implementation, although only command construction is reached in the selected CLI test. Dependency initialization remains an explicit approval blocker.

The latest preflight-only CI run [44463074190](https://github.com/LQC-labs/LQC-Mainnet-Development/actions/runs/44463074190) completed successfully for the prior commit `a2cd8bd4`; it **does not** certify the eight selected tests. This documentation update must receive its own CI status before being marked checked.

## Local project package initialization audit (2026-11-19)

The current commit's recursive Git tree lists 28 Go files in `chain/config`, `genesis`, and `cmd/lqcd`, plus 9 Go files in their directly imported local `app` package. All 37 files were fetched and searched for explicit `func init()` and `func TestMain()` declarations; none were found. This is a **source-text declaration audit**, not an exhaustive dynamic or transitive-dependency audit.

Some non-selected test bodies in `genesis` and `cmd/lqcd` use subprocess helpers or signing paths. `go test -run` excludes these non-selected test bodies, but still compiles the package and initializes imported dependencies. The `app` package imports Cosmos SDK / Cosmos EVM components; their dependency-level init and package variable side effects are **not cleared** by this audit.

**Decision:** Keep `LQC_MN001_OFFLINE_TEST_APPROVED=0` and the current workflow dry-run-only. No claim of 8-test PASS, no activation, no PR merge. Next evidence needed: dependency-init boundary review and an isolated, credential-free execution policy before any explicit approval.

## Linux offline input hardening evidence (2026-11-19)

- Commit `beefda4d583fb0b0e4eb3df37d4e93c38b9cebb0` adds Linux `openat2` with `RESOLVE_NO_SYMLINKS`, `O_CLOEXEC`, and `O_NONBLOCK`; the reader retains post-open regular-file and 8 MiB checks. Non-Linux platforms fail closed.
- A Linux-only `TestReadBoundedOfflineFileFIFO` fixture was added to check rejection of a named pipe with no writer. The existing `TestReadBoundedOfflineFile` also rejects a symlinked parent directory.
- GitHub Actions [run 44473726167](https://github.com/LQC-labs/LQC-Mainnet-Development/actions/runs/44473726167) concluded **success** on the exact commit `beefda4d`. It runs the previously reviewed security preflight, dry-run verification and package test-binary compilation; it **does not execute** either the new FIFO test or the eight candidate tests.
- `O_NONBLOCK` mitigates FIFO open blocking, but this is source-level reasoning until the FIFO fixture executes in an explicitly approved isolated Linux environment. Kernel support and actual behavior are not yet runtime-certified.
- `openat2` with `RESOLVE_NO_SYMLINKS` prevents symlink traversal during path resolution; no claim is made about all filesystem race classes, mounts, or hostile path mutation.

**Gate unchanged:** `LQC_MN001_OFFLINE_TEST_APPROVED=0`; dependency initialization and isolated-runner authorization remain outstanding. MN-001 IN PROGRESS / MAINNET NO-GO.
