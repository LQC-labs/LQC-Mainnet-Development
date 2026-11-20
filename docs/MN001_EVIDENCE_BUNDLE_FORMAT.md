# MN-001 independent VM evidence bundle — format-only verification

**State: DESIGN / NO TEST AUTHORIZATION / MAINNET NO-GO.**

The independent VM is **not provisioned** and no test execution is authorized.
This bundle is intended for evidence *captured later* by an independently
reviewed runner, not a substitute for that runner.

## Manifest and files

Create a private disposable evidence directory with a `manifest.json` and
eight separate evidence files. Do **not** commit evidence containing secrets,
tokens, usernames, private network topology, or credentials. Use the following
shape, replacing each placeholder with real values gathered from a verified VM:

```json
{
  "schema_version": 1,
  "source_sha": "0000000000000000000000000000000000000000",
  "evidence": {
    "vm_boundary": {"file": "vm-boundary.txt", "sha256": "<64 lowercase hex characters>"},
    "network_denial": {"file": "network-denial.txt", "sha256": "<64 lowercase hex characters>"},
    "credential_isolation": {"file": "credential-isolation.txt", "sha256": "<64 lowercase hex characters>"},
    "readonly_source": {"file": "readonly-source.txt", "sha256": "<64 lowercase hex characters>"},
    "resource_limits": {"file": "resource-limits.txt", "sha256": "<64 lowercase hex characters>"},
    "offline_toolchain": {"file": "offline-toolchain.txt", "sha256": "<64 lowercase hex characters>"},
    "dependency_init_review": {"file": "dependency-init-review.txt", "sha256": "<64 lowercase hex characters>"},
    "teardown": {"file": "teardown.txt", "sha256": "<64 lowercase hex characters>"}
  }
}
```

Run `python3 scripts/mn001-evidence-bundle-check.py /path/to/evidence`.
This reads local files only. Success means **schema and file digests match**,
nothing else: `EVIDENCE_FORMAT=VALID`, `MN001_GATE=NO_GO`. Failure means
`EVIDENCE_FORMAT=BLOCKED`, with a nonzero exit. File content is not interpreted
or certified; plausible or fabricated input can pass the format checker.

## Required independent decisions

1. Separately verify the guest OS, VM identity and isolated network boundary,
   including DNS, IPv4, IPv6 and metadata routes.
2. Independently inspect mounted credentials, immutable source and writable
   scratch, memory/process/disk limits, offline Go 1.25.9 dependencies,
   transitive `init`/`TestMain` review, and teardown proof.
3. Bind evidence to an exact source commit and approved eight-test scope.
4. Obtain **explicit user authorization** before building or running any
   execution workflow. The ninth FIFO test is excluded.
5. Keep GitHub branch protections, PR review and operational activation as
   distinct gates. Green preflight or evidence format checks are not approval.

Parent policy: [MN001_INDEPENDENT_RUNNER_ACCEPTANCE.md](MN001_INDEPENDENT_RUNNER_ACCEPTANCE.md).
