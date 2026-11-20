# MN-001 evidence path metadata precheck (not provenance)

**Status: DESIGN/LOCAL SYNTHETIC TESTS ONLY; MN001 NO-GO; MAINNET NO-GO.**

The standalone `scripts/mn001-evidence-path-audit.py` performs a read-only,
Linux/POSIX directory metadata inventory. It does **not** execute the eight
candidate tests, start a VM, initialize Go modules, inspect production
credentials, modify GitHub Actions, or authorize anything.

```sh
python3 scripts/mn001-evidence-path-audit.py /trusted/private/evidence-dir
python3 -m unittest -v scripts/test_mn001_evidence_path_audit.py
```

Policy: inspect path components using pinned directory descriptors and
`O_DIRECTORY|O_NOFOLLOW`, reject `..` traversal, symlinks and components
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

**Evidence currently available:** 10 local synthetic unit cases passed;
Python syntax compilation passed. GitHub-hosted CI for this branch is
**not independently verified**. The existing PR #4 and its CI are separate
and may not be interpreted as validation of this change.

**Next gate:** independent security review of this precheck and its
limitations, verify an independently controlled offline VM, establish
credible signed evidence capture, and obtain explicit user approval for a
pinned eight-test scope. Until then no VM provisioning, no candidate tests,
no validator, no PR merge or mainnet activation.
