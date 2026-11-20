# MN-001 evidence producer attestation — review-only contract

**Status: DESIGN ONLY / NOT IMPLEMENTED / NO-GO.**
This proposal does not authorize candidate runs, issue credentials, provision a VM,
or establish an independent security review. It is deliberately separate from
the format-only `mn001-evidence-bundle-check.py` and directory metadata precheck.

## Trust anchors required before implementation

- An independently controlled host/supervisor identity and a review-approved
  public verification key. Keep signing keys outside guest storage and outside
  the source repository. Record key provenance, custody, revocation and rotation.
- A disposable VM instance identity bound to a verified image digest and an
  exact source commit SHA; the claimed guest identity alone is not an anchor.
- Host-observed network-device and forwarding configuration, denial probes on
  safe nonproduction destinations, immutable source mounts and resource limits.
  Guest self-reporting is insufficient.
- A reviewed, explicitly approved command allowlist. The eight candidate tests
  are **NOT APPROVED**; the ninth FIFO case is excluded.

## Proposed canonical signed record (schema proposal, not implemented)

Bind the following fields in one signed, canonical, versioned manifest:
`schema_version`, `run_id`, `source_sha`, `tree_digest`,
`host_identity`, `vm_instance_id`, `guest_image_sha256`,
`toolchain_sha256`, `dependency_manifest_sha256`,
`approved_scope_digest`, `command_argv`, `start_utc`, `end_utc`,
`monotonic_sequence`, `exit_status`, `evidence_digests`,
`teardown_digest`, `signing_key_id`, `signature`.

- Specify a deterministic byte encoding and reject duplicate fields, unknown
  critical schema keys, zero/placeholder values and unsupported algorithms.
- Verify signatures against a **pinned, independently approved** key registry,
  not a public key supplied inside the untrusted bundle.
- Bind the same immutable source/VM identity across manifest and host records.
  Use uniqueness and monotonic sequence checks to detect replay. Timestamps
  alone are not sufficient; protect the record against later replacement.
- Include a trusted host-side completion/teardown attestation. A guest-signed
  record by itself cannot prove the guest lacked network or host access.
- Do not copy secrets, identifying credentials or sensitive host topology into
  GitHub logs or committed fixtures.

## Mandatory negative tests for any future verifier

1. No signature, bad signature, altered evidence byte, altered command or SHA.
2. Self-supplied signing key, unapproved key, rotated/revoked key, wrong host.
3. Replayed run ID / monotonic sequence, mismatched VM instance, invalid clock.
4. Missing/contradictory host isolation evidence; guest-only success claim.
5. Unsupported algorithm/schema, duplicate keys, empty digest or malformed file.
6. Missing explicit user approval for the exact scope, commit and runner.

Every rejected case must exit nonzero with `MN001_GATE=NO_GO`. Even a valid
signature means **authentic record by a trusted signer**, not necessarily
effective VM isolation. Independent review and factual isolation evidence
remain separate gates.

## Current evidence and next decision

- PR #5 static [Actions run #44652862341](https://github.com/LQC-labs/LQC-Mainnet-Development/actions/runs/44652862341):
  Python syntax + 11 synthetic path-metadata tests PASS at commit
  `f9f997062f9013cb0d137873f59f315a0b47a2f4`.
- No independent PR review recorded when drafted; no trusted signer/VM
  attestation, actual isolated VM or candidate execution evidence.
- Do **not** implement a verifier that accepts unsigned data or self-declared
  trust roots as security proof. Resolve independent host ownership, key
  custody, evidence collection and reviewer sign-off before implementation.

**MN001 IN PROGRESS; MN002 BLOCKED; MAINNET NO-GO.**
