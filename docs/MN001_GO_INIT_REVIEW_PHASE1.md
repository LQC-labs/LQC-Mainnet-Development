# MN-001 Go candidate initialization risk review — phase 1 (read-only)

**Status: PARTIAL SOURCE REVIEW / NOT A FULL TRANSITIVE AUDIT / NO TEST AUTHORIZATION.**

Source inspected at review branch commit `2c9ddb7d5b8e4d1caffce3b5329a4840dc8ab289`. Inspection was performed
through GitHub file reads, without running `go test`, building packages,
loading LQC Go modules, starting nodes, or exercising a VM.

## Exact eight candidates and observed package paths

| Package | Candidate tests | Source reviewed | Initialization boundary |
|---|---|---|---|
| `chain/config` | `TestRuntimeDevnetCompatibility`, `TestExplicitRuntimeValidation` | `chain/config/runtime_test.go`, `chain/config/runtime.go` | `runtime.go` imports `github.com/cosmos/cosmos-sdk/types`; SDK and transitively imported packages not audited |
| `genesis` | `TestMainnetProposalOfflineValidation`, `TestMainnetProfileRejectsDuplicateKeys`, `TestMainnetDraftOfflinePreflight`, `TestMainnetDraftRejectsDuplicateJSONKeys` | `genesis/mainnet_test.go`, `genesis/mainnet_draft_test.go`, `genesis/mainnet_draft.go` | imports local `chain/config`; SDK dependency still present |
| `cmd/lqcd` | `TestOfflineMainnetDraftCLI`, `TestReadBoundedOfflineFile` | `cmd/lqcd/mainnet_draft_test.go`, `cmd/lqcd/mainnet_draft_limits_test.go`, `cmd/lqcd/mainnet_draft.go`, `cmd/lqcd/main.go` | package `main` imports local `app`, `genesis`, Cosmos DB and Cobra; package startup requires reviewing these imports even when the test uses only a limited CLI path |

The ninth `TestReadBoundedOfflineFileFIFO` remains explicitly excluded.

## Verified source observations (not execution evidence)

1. `chain/config/runtime_test.go`: candidate bodies use synthetic profiles,
   JSON marshaling and validation. However `runtime.go` calls
   `sdk.ParseDecCoin` and imports Cosmos SDK `types`. Do not infer that
   imported SDK packages have no initialization side effects.
2. `genesis/mainnet_draft.go`: structural JSON preflight checks empty
   validators, accounts, supply and genesis transactions. It intentionally
   does **not** perform full Cosmos SDK module genesis validation.
3. `cmd/lqcd/mainnet_draft_test.go`: writes temporary JSON fixtures,
   constructs `newRootCommand()` and calls `root.Execute()`. The CLI path
   reads local files. The source-visible command does not call `app.New`,
   but `cmd/lqcd/main.go` imports `app` at package load time.
4. `cmd/lqcd/main.go`: the different `withGenesisApp` command path invokes
   `app.New`, creates a temporary home and an in-memory DB; package-level
   import and command construction must be reviewed independently of whether
   the candidate calls this path.
5. `app/app.go`: `newWithOptions` may configure and seal SDK global
   address settings using `sync.Once`, instantiate `evmd.NewExampleApp`,
   and load latest stores. These are source-visible application-constructor
   effects, **not evidence that the candidate test executes them**.
6. `go.mod`: pins Go 1.25.9; direct dependencies include Cosmos SDK
   v0.54.3, Cosmos EVM v0.7.3, CometBFT v0.39.3, Cosmos DB v1.1.3
   and Cobra v1.10.2. The module list is **not** a resolved package import
   closure or an initializer review.

## Mandatory pending review: BLOCKED

- Enumerate the exact transitive package graph per candidate package at
  a frozen commit, using an approved nonexecuting dependency inspection
  workflow and offline verified module source. Review all `init()`,
  package variable initialization, `TestMain`, CGo/native imports,
  environment reads, file writes, shell/process spawns and network setup.
- Analyze the complete CLI command construction and any registered hooks.
- Bind reviewed source SHA, module digests, OS/architecture and Go version
  to a signed/tamper-evident evidence record.
- Independently verify guest network denial, credential isolation, read-only
  mounts, resource controls and cleanup on a **separately authorized**
  disposable VM; a valid JSON evidence manifest is insufficient.
- Obtain separate, explicit user authorization for the exact eight tests
  and regular/race execution commands. The current flag is never permission.

**Current decision:** `TRANSITIVE_INIT_REVIEW=BLOCKED`,
`NETWORK_ISOLATION=BLOCKED`, `MN001_GATE=NO_GO`,
`MAINNET=NO_GO`. No candidate tests, VM creation, node startup,
validator signing, merge, or mainnet activation were performed.
