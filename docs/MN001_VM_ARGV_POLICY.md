# MN-001 frozen QEMU command policy — DESIGN ONLY

**NOT RUNNABLE / NOT AN ISOLATION PROOF / NO-GO.**

The `scripts/mn001-vm-argv-policy.py` checker accepts a JSON proposal with
`schema_version: 1` and an `argv` list. The *only* accepted plan is the
exact `PLAN` list in the checker. It contains the deliberately invalid
`APPROVAL_REQUIRED_IMMUTABLE_GUEST_IMAGE` placeholder. It cannot be used to
boot a guest without a separate design change and explicit infrastructure approval.

The frozen profile has `-nodefaults`, `-no-user-config`, `-nic none`,
no graphical display, no QEMU monitor, and a read-only image placeholder.
Any additional network, port-forwarding, filesystem-sharing, QMP or device
option causes `VM_ARGV_POLICY=BLOCKED`. A matching proposal outputs
`VM_ARGV_POLICY=MATCHED_UNVERIFIED`; **both return exit code 2**, with
`MN001_GATE=NO_GO`. Do not treat plan matching as an operational PASS.

This profile is **not** a full VM launch design: boot functionality,
storage scratch, image provenance, KVM compatibility, host process limits,
VM teardown, host/hypervisor networking, guest IPv4/IPv6/DNS/metadata
denial and credential exclusion remain unverified. Do not execute it,
replace placeholders with a production image, add `sudo`, or treat the
literal QEMU flags as proof that a guest cannot reach the network.

Run only synthetic unit tests:
```sh
python3 scripts/test_mn001_vm_argv_policy.py
```
No VM, candidate tests, Go tooling or nodes are started.

QEMU reference: https://www.qemu.org/docs/master/system/invocation.html
(`-nic none` explicitly disables the default guest network configuration).
Parent acceptance: [MN001_INDEPENDENT_RUNNER_ACCEPTANCE.md](MN001_INDEPENDENT_RUNNER_ACCEPTANCE.md).

Before any real guest launch, require a user-approved, independently
reviewed host and image design, actual denial evidence, credential and
resource isolation, and a separate candidate-test approval decision.
MN-001 IN PROGRESS; MN-002 BLOCKED; MAINNET NO-GO.
