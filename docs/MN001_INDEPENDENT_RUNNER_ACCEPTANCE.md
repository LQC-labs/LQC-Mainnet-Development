# MN-001 independent isolated runner acceptance checklist

Status: **BLOCKED / DESIGN EVIDENCE ONLY / NO TEST AUTHORIZATION**
Date: 2026-11-19
Parent policy: [MN001_ISOLATED_EXECUTION_POLICY_DRAFT.md](MN001_ISOLATED_EXECUTION_POLICY_DRAFT.md)

## Confirmed CI evidence

- Run [44525777211](https://github.com/LQC-labs/LQC-Mainnet-Development/actions/runs/44525777211), commit `8e78e0e2`: reviewed existing security preflight **PASS**; network namespace enforcement **FAIL/BLOCKED**. The probe step uses `continue-on-error`, so its green UI is **not** isolation evidence.
- Run [44525141987](https://github.com/LQC-labs/LQC-Mainnet-Development/actions/runs/44525141987): `unshare: write failed /proc/self/uid_map: Operation not permitted`. The GitHub-hosted runner cannot provide the requested unprivileged namespace proof with the current configuration.
- Do not retry the same probe as if a retry could establish isolation. Do not elevate the GitHub-hosted runner, disable the network gate, or convert a failed isolation probe into PASS.

## Independent runner contract (not yet implemented)

Use a fresh **dedicated, disposable Linux VM or equivalently independently verified sandbox** outside the GitHub-hosted runner. A host-level firewall or container configuration alone is insufficient unless the actual isolation boundary is tested and evidenced.

1. **Provisioning:** fresh unprivileged identity; no production keys, GitHub credentials, cloud instance credentials, SSH agent, home-directory mounts, host Docker socket, privileged devices, or secrets in the environment. No access to production networks.
2. **Networking:** OS/VM-enforced inbound and outbound deny. Prove the guest has no permitted external network path, including DNS, IPv4, IPv6 and local metadata endpoints. Capture firewall or VM-network configuration plus independent negative connectivity checks; no test traffic to production systems.
3. **Filesystem:** immutable read-only source snapshot at a recorded commit and SHA-256 manifest; writable scratch volume only; no writable host mounts. Evidence of enforced read-only mounts and denied writes outside scratch.
4. **Resources:** externally enforced wall-clock timeout and CPU, memory, PID, file-descriptor and scratch-disk limits. Ensure all processes and scratch artifacts are destroyed after exit.
5. **Dependencies:** pin Go 1.25.9 and immutable offline module/cache artifacts before network isolation. `GOTOOLCHAIN=local`, `GOWORK=off`, and no runtime downloads. Verify checksums and record exact toolchain digest.
6. **Review:** freeze the eight candidate test names and exact transitive package init, `TestMain`, CGo/native and command-construction review. No Go test or package initialization during capability probing.
7. **Authorization:** require a separate, explicit user approval referencing the exact commit, eight-test scope, runner evidence and normal/race commands. The current `LQC_MN001_OFFLINE_TEST_APPROVED` flag **never** authorizes execution by itself.
8. **Evidence:** signed or tamper-evident run manifest with runner identity, source SHA, toolchain hash, timestamps, commands, exit codes, logs, resource and network denial evidence, and destruction confirmation.

## Non-executing acceptance matrix

| Gate | Evidence required | Current |
| --- | --- | --- |
| Network namespace/VM boundary | Independent deny proof | BLOCKED |
| Credential and secret isolation | Fresh VM inventory and mount/env proof | BLOCKED |
| Read-only source / scratch | Mount and denied-write evidence | BLOCKED |
| Resource limits and teardown | Host-enforced limits and cleanup logs | BLOCKED |
| Go dependencies / init review | Transitive reviewed manifest | BLOCKED |
| Exact eight tests and user authorization | Scope-specific explicit approval | BLOCKED |

**No candidate tests, FIFO fixture, validator, node, deployment, PR merge or mainnet activation are authorized.** MN-001 stays IN PROGRESS; MAINNET stays NO-GO.
