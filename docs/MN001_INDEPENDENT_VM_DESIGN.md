# MN-001 disposable isolated Linux VM — implementation decision record

**Status: DESIGN ONLY / NOT PROVISIONED / MN001 NO-GO.** This design is NOT
permission to run candidate tests or modify production infrastructure.

## Selected architecture and trust boundaries

A fresh dedicated QEMU/KVM Linux guest, running on an independently owned,
non-GitHub-hosted Linux machine, is the proposed boundary. KVM availability
must be checked on the actual host before selecting acceleration; no attempt
to bypass host security policies or privileged namespace restrictions.

* VM creation is a **separate, user-authorized infrastructure action**.
  This document does not contain a runnable provision/start command.
* Provision dependencies and Go 1.25.9 in a staging phase using verified
  immutable artifacts. After staging, disconnect the VM network at the
  hypervisor/host boundary; no NIC or host-port forwarding may remain.
* A private, dedicated, unprivileged guest identity runs with no credential
  injection; no cloud metadata, production network, SSH agent, API tokens,
  validator keys, home mounts, host Docker socket, or writable host share.
* Attach source as an immutable verified snapshot and allow only isolated
  guest scratch storage. Prove denial of writes outside approved paths.
* Limit guest vCPUs/RAM, disk, subprocesses and file descriptors. A trusted
  host supervisor enforces external deadlines and VM destruction.
* Separate **VM capability proof** from **transitive dependency init review**,
  **test execution approval** and **mainnet activation approval**.

## Acceptance sequence (no candidate execution until all completed)

1. Host identity/capabilities and ownership confirmed; a clean disposable
   guest image and immutable provenance documented.
2. Host/hypervisor configuration inspected and guest-side tests demonstrate
   denied outbound/inbound routes, IPv4, IPv6, DNS, metadata and host services
   using safe nonproduction endpoints. Document tests and counterexamples.
3. Guest environment and mounts audited for absence of credentials and
   non-scratch write access; capture independent denial evidence.
4. Host-enforced resource bounds and destruction tested on disposable
   **non-LQC** fixtures; no Go candidate package initialization.
5. Offline Go 1.25.9 binaries and module checksums reconciled against
   reviewed artifact hashes; prohibit runtime downloads.
6. Dependency `init`, `TestMain`, CLI construction and native/CGo call
   chains reviewed against an exact immutable source commit.
7. Evidence records collected privately, redacted and hashed. Run the
   format-only checker; `EVIDENCE_FORMAT=VALID` does not establish safety.
8. Independent security review and explicit user authorization tied to exact
   runner, commit SHA and eight test names. FIFO ninth excluded.
9. Only after a separate approval could a narrowly scoped execution workflow
   be designed and reviewed. None currently exists.

## Explicit blocks

GitHub-hosted runner `unshare` repeatedly failed with
`Operation not permitted`. Do not retry or elevate GitHub runners to evade
this restriction. No VM instance, isolation proof, Codex independent review,
user test approval, candidate test run, validator startup, PR merge or
mainnet activation is claimed here.

Related:
- [MN001_INDEPENDENT_RUNNER_ACCEPTANCE.md](MN001_INDEPENDENT_RUNNER_ACCEPTANCE.md)
- [MN001_EVIDENCE_BUNDLE_FORMAT.md](MN001_EVIDENCE_BUNDLE_FORMAT.md)
