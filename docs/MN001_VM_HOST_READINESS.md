# MN-001 host readiness check — non-executing

**Status: HOST INVENTORY ONLY / MAINNET NO-GO / NO TEST APPROVAL.**

First determine if a user-controlled, non-GitHub-hosted Linux machine is a
plausible host for a disposable QEMU/KVM guest. A GitHub-hosted runner with
denied `unshare` is not an acceptable replacement.

```sh
bash scripts/mn001-vm-host-readiness.sh
```

The script does not create/start a VM, access a KVM device, execute Go,
use `sudo`, change the host or access the network. It checks non-root Linux
identity, installed tools, KVM device type and current-user access bits.
Exit 0 means only `HOST_PREREQUISITES=AVAILABLE_UNVERIFIED`, never proof of
guest isolation, hypervisor function, or candidate test authorization.

## Next technical gate — guest isolation (NOT IMPLEMENTED)

1. Confirm actual host ownership, Linux kernel and QEMU/KVM availability
   without privilege escalation or bypassing cloud restrictions.
2. Obtain user authorization before VM creation, disk provisioning, firewall
   changes, or any other infrastructure mutation.
3. Stage verified immutable guest image, Go 1.25.9 and module dependencies.
   Do not inject credentials, home mounts, signing keys or production assets.
4. Configure hypervisor-enforced no-NIC/no-forwarding network isolation.
   Independently prove denied IPv4, IPv6, DNS, metadata and host access with
   safe nonproduction checks.
5. Independently prove read-only source, disposable scratch, CPU/RAM/PID/FD/
   disk limits, external timeout and destruction using non-LQC fixtures.
6. Collect private evidence and review against
   [MN001_INDEPENDENT_RUNNER_ACCEPTANCE.md](MN001_INDEPENDENT_RUNNER_ACCEPTANCE.md).
   File digest agreement is not proof of effective isolation.
7. Review transitive `init`/`TestMain` and CLI/native behavior; require
   independent review and explicit user approval tied to exact source commit,
   runner identity and eight tests. The ninth FIFO test is excluded.

**Until separately approved:** MN-001 IN PROGRESS, MN-002 BLOCKED,
candidate tests NOT EXECUTED, MAINNET NO-GO. PR merge is a separate gate.
