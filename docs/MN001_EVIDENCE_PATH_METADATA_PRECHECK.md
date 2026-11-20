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

**Evidence currently available:** PR #5 head `f9f997062f9013cb0d137873f59f315a0b47a2f4` completed [GitHub Actions run #44652862341](https://github.com/LQC-labs/LQC-Mainnet-Development/actions/runs/44652862341) with success. Job logs confirm Python parse PASS and **11/11 synthetic unit tests PASS** (2026-11-20). No independent PR review has been recorded at the time of this update. These checks prove neither evidence-producer identity nor VM isolation. PR #4's CI is separately scoped.

**Next gate:** independent security review of this precheck and its
limitations, verify an independently controlled offline VM, establish
credible signed evidence capture, and obtain explicit user approval for a
pinned eight-test scope. Until then no VM provisioning, no candidate tests,
no validator, no PR merge or mainnet activation.
