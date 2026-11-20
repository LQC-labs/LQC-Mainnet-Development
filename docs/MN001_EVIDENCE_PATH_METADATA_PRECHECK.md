# MN-001 evidence path metadata precheck (not provenance)

**Status: SYNTHETIC CI VERIFIED / PROVENANCE NOT VERIFIED / MN001 NO-GO / MAINNET NO-GO.**

The standalone `scripts/mn001-evidence-path-audit.py` performs a read-only,
Linux/POSIX directory metadata inventory. It does **not** execute the eight
candidate tests, start a VM, initialize Go modules, inspect production
credentials, modify GitHub Actions, or authorize anything.

```sh
python3 scripts/mn001-evidence-path-audit.py /trusted/private/evidence-dir
python3 -m unittest -v scripts/test_mn001_evidence_path_audit.py
```

Policy: require an **absolute evidence-directory path**; reject relative paths
(including `.`) because the current working directory's ancestors would otherwise
be unverified. Inspect all absolute path components from `/` using pinned
directory descriptors and `O_DIRECTORY|O_NOFOLLOW`; reject `..` traversal,
symlinks and components
whose owner is neither root nor the caller, and reject group/other writable
components, including sticky directories such as `/tmp`. This is deliberately
conservative and may reject legitimate scratch directories. It should not
be loosened merely to force a green result.

A zero exit prints `PATH_METADATA=CONSISTENT_UNVERIFIED`, never
`PROVENANCE=VERIFIED`. Successful metadata checks do not defend against
privileged or same-user modification, malicious provenance, namespace
remapping, forged SHA-256 manifests, non-atomic changes to evidence files,
or a deceptive VM supervisor. Separate attestation, immutable collection,
source SHA and runner identity binding, and review of signed evidence are
required before any candidate run is approved.

**Evidence:** PR #5 commit `d3d70561f519e3d08f80ea82a310360f0f5733ec` completed [Actions run #44654411746](https://github.com/LQC-labs/LQC-Mainnet-Development/actions/runs/44654411746): Python parse PASS and **15/15 synthetic tests PASS** (2026-11-20). Later changes add explicit absolute-path enforcement and two negative tests: these require an additional CI result for the resulting commit and MUST NOT inherit the earlier PASS. Independent review remains unverified. No signature, evidence-producer identity or VM isolation has been established; PR #4's CI is separately scoped.

**Next gate:** independent security review of this precheck and its
limitations, verify an independently controlled offline VM, establish
credible signed evidence capture, and obtain explicit user approval for a
pinned eight-test scope. Until then no VM provisioning, no candidate tests,
no validator, no PR merge or mainnet activation.
