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

## Confirmed upstream package initialization effect (2026-11-19)

Direct upstream source inspection at pinned `github.com/cosmos/evm v0.7.3`:

- `evmd/app.go` defines `func init()` that sets `sdk.DefaultPowerReduction = utils.AttoPowerReduction` and assigns `defaultNodeHome = evmconfig.MustGetDefaultNodeHome()`.
- `evmd/app.go` imports `github.com/ethereum/go-ethereum/eth/tracers/js` and `.../native` with blank imports, triggering their package initialization/registration paths. Their transitive side effects are **not yet fully reviewed**.
- `evmd/config/config.go` defines `MustGetDefaultNodeHome()`, which calls `clienthelpers.GetNodeHomeDirectory(".evmd")` and panics on error. This is an initialization-time dependency on host/environment state; the exact helper's behavior remains to be inspected.
- The LQC `app/app.go` imports `github.com/cosmos/evm/evmd`, and `cmd/lqcd/main.go` and `genesis/genesis.go` import local `app`. Therefore the `evmd` initializer is **reachable during package initialization** for the `cmd/lqcd` and `genesis` test binaries, independent of `-run` selection.
- This is **positive evidence of process-global mutation before selected test bodies run**. It is not evidence of node startup, network access, validator signing, or test runtime PASS.
- `chain/config` selected tests do not directly import local `app` through the inspected `chain/config` production files; their complete transitive import graph still requires independent verification.

**Gate decision:** Keep candidate execution NOT AUTHORIZED. Review the node-home helper and tracer imports; record immutable dependency closure and isolation proof before proposing explicit approval. Do not conflate passing preflight CI with these unexecuted tests.

CI [44501410374](https://github.com/LQC-labs/LQC-Mainnet-Development/actions/runs/44501410374) completed SUCCESS for baseline `a08ae151`; it did not execute the candidate tests.

## Pinned upstream initialization trace (2026-11-19, continued)

**Version resolution:** `go.mod` pins `github.com/cosmos/cosmos-sdk v0.54.3`, `github.com/cosmos/evm v0.7.3`, and separately `github.com/cosmos/evm/evmd v0.0.0-20260903174530-c3ae9067a7ea`. It replaces `github.com/ethereum/go-ethereum` with `github.com/cosmos/go-ethereum v1.17.2-cosmos-0`. Review must follow these resolved modules, not unmodified upstream go-ethereum.

**Home initialization:** `cosmos-sdk/client/v2/helpers/home.go` at `v0.54.3` defines `GetNodeHomeDirectory(name)`: checks `--home` / `--home=...` in process arguments, then `NODE_HOME` (or prefixed `_HOME`), then `os.UserHomeDir()`. The inspected helper contains no file write or network call. `evmd/config/config.go` wraps this in `MustGetDefaultNodeHome()` and panics on error. `evmd/app.go` initializes this before test bodies when its package is imported.

**Tracer registration:** `cosmos/go-ethereum` at `v1.17.2-cosmos-0` contains `init()` in `eth/tracers/js/goja.go`, `eth/tracers/native/4byte.go`, `eth/tracers/native/call.go`, and `eth/tracers/native/noop.go`. Native initializers register tracer constructors in `tracers.DefaultDirectory`. JS initializer calls `jsassets.Load()`, panics on error, and registers built-in tracer sources.

**Embedded JS assets:** `eth/tracers/js/internal/tracers/tracers.go` uses `//go:embed *.js` and `embed.FS`. Its `Load()` reads the embedded filesystem with `fs.WalkDir` / `fs.ReadFile`; no network or external file read appears in this function. This is **limited evidence for this loader only**, not a guarantee about all tracer dependency initializers.

**Security implications:** The `-run` allowlist does not suppress imported package initializers. Confirmed pre-test process-global changes and environment/argument reads require isolation. No evidence in these specific source paths establishes network access, validator signing, or node startup. Transitive dependency inventory, process isolation, approval enforcement, and execution evidence remain BLOCKED.

**CI distinction:** [44503116037](https://github.com/LQC-labs/LQC-Mainnet-Development/actions/runs/44503116037) SUCCESS for `f24c3608` covers the existing preflight/dry-run workflow, not the eight candidate tests.
