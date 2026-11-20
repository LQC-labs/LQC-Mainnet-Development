#!/usr/bin/env python3
# Copyright 2026 MMXlabs & LQC LLC
# SPDX-License-Identifier: Apache-2.0
"""Offline evidence bundle integrity check. NEVER authorizes MN-001 execution.

Input: manifest.json in a disposable evidence directory. This verifies only
schema, required evidence categories, path confinement, and SHA-256 hashes.
It does NOT independently establish that isolation controls actually worked.
No shell commands, candidate tests, VM processes, network, or Go are invoked.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import sys

REQUIRED = (
    "vm_boundary", "network_denial", "credential_isolation",
    "readonly_source", "resource_limits", "offline_toolchain",
    "dependency_init_review", "teardown",
)
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")

def blocked(message):
    print("EVIDENCE_FORMAT=BLOCKED")
    print("MN001_GATE=NO_GO")
    print("ERROR=" + message, file=sys.stderr)
    return 1

def unique_object_pairs(pairs):
    """Reject duplicate JSON keys rather than silently accepting last-wins."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key: " + key)
        result[key] = value
    return result


def check(directory):
    root = Path(directory).resolve(strict=True)
    if not root.is_dir():
        return blocked("evidence path must be a directory")
    manifest = root / "manifest.json"
    if manifest.is_symlink() or not manifest.is_file():
        return blocked("manifest.json missing or symlink")
    if manifest.stat().st_size > 65536:
        return blocked("manifest too large")
    try:
        payload = json.loads(manifest.read_text(encoding="utf-8"), object_pairs_hook=unique_object_pairs)
    except (ValueError, UnicodeError, OSError):
        return blocked("invalid JSON manifest")
    if (not isinstance(payload, dict) or type(payload.get("schema_version")) is not int
            or payload["schema_version"] != 1):
        return blocked("unsupported evidence schema")
    if (not isinstance(payload.get("source_sha"), str)
            or not GIT_SHA.fullmatch(payload["source_sha"])
            or payload["source_sha"] == "0" * 40):
        return blocked("full source commit SHA required")
    records = payload.get("evidence")
    if not isinstance(records, dict) or set(records) != set(REQUIRED):
        return blocked("required evidence categories must match exactly")
    seen = set()
    for category in REQUIRED:
        record = records[category]
        if not isinstance(record, dict) or set(record) != {"file", "sha256"}:
            return blocked("invalid record for " + category)
        relative, expected_hash = record["file"], record["sha256"]
        if not isinstance(relative, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", relative):
            return blocked("unsafe evidence filename for " + category)
        if relative in seen:
            return blocked("evidence filenames must be distinct")
        seen.add(relative)
        if not isinstance(expected_hash, str) or not SHA256.fullmatch(expected_hash):
            return blocked("invalid sha256 for " + category)
        path = root / relative
        if path.is_symlink() or not path.is_file():
            return blocked("missing or symlinked evidence for " + category)
        size = path.stat().st_size
        if size == 0:
            return blocked("empty evidence file for " + category)
        if size > 8 * 1024 * 1024:
            return blocked("evidence file too large for " + category)
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(65536), b""):
                digest.update(chunk)
        if digest.hexdigest() != expected_hash:
            return blocked("SHA-256 mismatch for " + category)
    print("EVIDENCE_FORMAT=VALID")
    print("EVIDENCE_CATEGORIES=8")
    print("MN001_GATE=NO_GO")
    print("REVIEW_REQUIRED=YES")
    print("This is file-integrity evidence only; no isolation proof or execution authorization.")
    return 0

if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(blocked("usage: mn001-evidence-bundle-check.py EVIDENCE_DIRECTORY"))
    try:
        sys.exit(check(sys.argv[1]))
    except (OSError, RuntimeError) as exc:
        sys.exit(blocked("failed to read evidence bundle: " + str(exc)))
