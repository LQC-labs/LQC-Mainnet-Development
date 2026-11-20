# MN-001 source-level initializer inventory — GitHub read-only scan

**Status: PARTIAL LOCAL-SOURCE INVENTORY ONLY / TRANSITIVE_INIT_REVIEW=BLOCKED / MN001_GATE=NO_GO**

**Inspected commit:** `4dab244d5d2178a98dbc74e0ab35976c65a5c73e` on `fix/mn001-separate-ci-gate-review-20261119`.
**Method:** GitHub connector read of 40 `.go` files from these four local
package directories, followed by inspection of import declarations and
declaration-shaped text. No Go build/test, Go tool, package import, guest,
candidate test, node, validator, network probe, or CI workflow ran.

## Local package inventory

| Local package | Files inspected | Source-level observations |
| --- | ---: | --- |
| `app` | 9 | SDK/EVM application constructor and storage/runtime imports; Linux build-tag files; no literal declaration `func init()` or `func TestMain()` found |
| `chain/config` | 6 | Direct `github.com/cosmos/cosmos-sdk/types` import via `runtime.go`; no literal `init`/`TestMain` declaration found |
| `genesis` | 15 | Imports Cosmos SDK, Cosmos EVM and CometBFT in package files including test files; two package-level `regexp.MustCompile` initializers in `mvp.go` |
| `cmd/lqcd` | 10 | Imports local `app`, `genesis`, Cosmos DB and Cobra; Linux `golang.org/x/sys/unix` path; `main()` command entrypoint found, no literal `init`/`TestMain` declaration found |
| **Total** | **40** | **All findings are source-review observations, not execution safety proof** |

## Risk conclusions

1. Test-name filters cannot prevent initializers of package imports from
   running. `chain/config/runtime.go` directly imports Cosmos SDK types.
2. `genesis/genesis.go` brings in Cosmos SDK auth, bank, staking and genutil
   types and Cosmos EVM ERC20/EVM module types. Its package test files import
   further SDK, CometBFT and crypto packages.
3. `cmd/lqcd/main.go` imports local `app` even if a candidate only
   calls a narrow offline-draft command. `app/app.go` uses the
   Cosmos EVM `evmd` constructor in the `app.New` code path.
4. `app/persistent.go` has a Linux build tag and imports Cosmos SDK and
   Cosmos EVM server/runtime dependencies. It may be part of the
   Linux candidate package dependency closure; exact build-tag-aware
   resolution remains unverified.
5. In `genesis/mvp.go`, two `regexp.MustCompile` package-level
   initializers were observed at lines 41 and 42. These are source-level
   initialization expressions; their presence does not by itself establish
   unsafe behavior.
6. Source pattern scanning found no `func init()` or `func TestMain()`
   declarations among the **40 inspected local Go files**. This is not
   a guarantee about generated Go files, external packages, build tags,
   CGo/native startup, or all variable initializers.
7. Python static inventory and local synthetic fixture tests are distinct
   from real build-tag-aware package analysis and do not certify the SDK.

## Remaining blocking work, in priority order

- Identify an independently owned Linux VM host, with user approval before
  provisioning; validate OS/VM-enforced inbound/outbound isolation, guest
  credential absence, readonly source and resource/teardown controls.
- Resolve the exact Go 1.25.9 build-tag-aware transitive package graph from
  verified offline dependencies for a pinned commit. Audit `init`,
  package variable initialization, `TestMain`, native/CGo startup and
  indirect command effects in all reachable packages.
- Request independent Codex/security review of the exact source and the
  actual VM evidence; Codex has **not** been executed or claimed here.
- Perform separately authorized, narrowly scoped candidate execution only
  after the above reviews and **explicit user approval** of exact eight-test
  scope; exclude the ninth FIFO fixture.
- Require verified CI results and branch protection/review enforcement before
  any broader integration or release decisions. Branch protection is not
  currently established on the inspected branches.

**Final decision:** MN-001 IN PROGRESS; MN-002 BLOCKED; MAINNET NO-GO.
Do not interpret a green preflight or source scan as mainnet authorization.
