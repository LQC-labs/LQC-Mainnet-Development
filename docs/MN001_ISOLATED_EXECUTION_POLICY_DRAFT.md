# MN-001 isolated offline regression execution policy — DRAFT

Status: **PROPOSAL ONLY / NO EXECUTION AUTHORIZATION**
Date: 2026-11-19
Scope: eight existing candidate tests in `scripts/mn001-offline-regression-candidate.sh`; the separate Linux FIFO fixture is NOT in this scope.

## Evidence and boundaries

- CI [44495741137](https://github.com/LQC-labs/LQC-Mainnet-Development/actions/runs/44495741137) passed for `d26f6184`. This is reviewed preflight, script dry-run, and compilation evidence only. It does **not** run the eight candidate tests or FIFO fixture.
- Go `-run` filters test bodies, not dependency package initialization. `cmd/lqcd` imports local `app`, which imports Cosmos SDK and Cosmos EVM. Transitive package init and package-variable effects remain unapproved.
- `LQC_MN001_OFFLINE_TEST_APPROVED=0` remains mandatory in current GitHub Actions. `GITHUB_ACTIONS=true` explicitly blocks candidate execution even if approval flag is overridden.
- Linux `openat2` / `RESOLVE_NO_SYMLINKS` and `O_NONBLOCK` are implemented. The FIFO fixture has **not** been executed as part of the existing eight-test candidate.

## Mandatory conditions before proposing an execution authorization

1. **Dependency review:** enumerate the exact transitive Go package set and inspect `init`, package-level side effects, `TestMain`, indirect CLI command construction and any native/CGo startup. Record reviewed module versions and source commit.
2. **Isolation:** use a fresh disposable Linux environment with no production wallet, validator key, API token, cloud credential, GitHub write token, or mounted home directory; read-only repository source and a separate disposable writable work area.
3. **Network:** deny outbound and inbound network at the OS/container/VM boundary. An environment variable or test-name allowlist is not network isolation.
4. **Filesystem/process:** restrict writable paths, use unprivileged execution, deny privileged device/socket access, bound processes, memory, CPU, file descriptors and disk. Ensure all temporary files and child processes are cleaned up.
5. **Toolchain:** pin Go 1.25.9, Linux architecture/kernel support, module checksums, `GOTOOLCHAIN=local`, `GOWORK=off`, and immutable dependency artifacts. Avoid runtime dependency downloads in the isolated runner.
6. **Exact tests:** freeze and review the two `chain/config`, four `genesis`, and two `cmd/lqcd` test names; run regular and race modes only after an explicit approval record. The FIFO fixture is a **separate proposed ninth test** requiring a distinct scope decision.
7. **Timeout/fail-closed:** enforce an external wall-clock timeout for the complete test command and each package, not just Go `-timeout`; treat hangs, signals, missing logs, partial runs, unexpected network attempts, or isolation violations as FAIL/BLOCKED.
8. **Evidence:** capture exact commit SHA, Go version, OS/kernel, approved test names, normal/race command lines, exit codes, timestamped logs, hashes, and cleanup proof. A successful compile is not a runtime PASS.

## Explicit prohibitions

No validator signing, wallet generation, node startup, mainnet genesis adoption, production RPC calls, deployment, PR merge, MN-002 advancement, or mainnet activation. No test execution is authorized by this document.

## Decision gate

**BLOCKED** until all conditions above are independently verified and the user approves the exact isolated execution scope. Keep PR Draft, MN-001 IN PROGRESS, MAINNET NO-GO. GitHub Terms of Service, Acceptable Use Policies, and Pages restrictions remain mandatory.
