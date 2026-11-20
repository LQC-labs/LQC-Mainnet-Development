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
import stat
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


def read_regular_at(root_fd, name, maximum):
    """Read via dirfd; always release the owned raw FD exactly once."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    fd = os.open(name, flags, dir_fd=root_fd)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("not a regular evidence file: " + name)
        if info.st_size == 0 or info.st_size > maximum:
            raise ValueError("invalid evidence file size: " + name)
        # The wrapper never owns the original descriptor, even on error.
        with os.fdopen(fd, "rb", closefd=False) as stream:
            payload = stream.read(maximum + 1)
        if not payload or len(payload) > maximum:
            raise ValueError("evidence read exceeds size limit: " + name)
    except BaseException as processing_error:
        # Cleanup even for MemoryError, KeyboardInterrupt, SystemExit.
        try:
            os.close(fd)
        except OSError as cleanup_error:
            if isinstance(processing_error, (KeyboardInterrupt, SystemExit)):
                processing_error.add_note(
                    "evidence file cleanup failed: " + str(cleanup_error))
            else:
                raise OSError("evidence file processing failed: " +
                              str(processing_error) + "; close failed: " +
                              str(cleanup_error)) from processing_error
        # This raise is in the outer except, NOT the cleanup except.
        raise
    else:
        # A Linux close error is fatal, and the FD must not be retried.
        os.close(fd)
        return payload


def open_evidence_directory(directory):
    """Walk each path component from / or cwd without following symlinks.

    The resulting fd pins the selected directory even if its path is renamed.
    This does not establish trusted ownership of writable parent directories.
    """
    requested = Path(directory)
    if not requested.parts:
        raise ValueError("empty evidence path")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open("/" if requested.is_absolute() else ".", flags)
    try:
        for component in requested.parts:
            if component in ("/", "."):
                continue
            if component == "..":
                raise ValueError("parent traversal not permitted in evidence path")
            next_fd = os.open(component, flags, dir_fd=fd)
            parent_fd = fd
            fd = next_fd  # Own the child before releasing the parent.
            try:
                os.close(parent_fd)
            except OSError as exc:
                # Linux close may already have released parent_fd; never retry.
                raise OSError("failed to close parent evidence directory: " + str(exc)) from exc
        return fd
    except BaseException as original_error:
        try:
            os.close(fd)  # Close the currently owned child exactly once.
        except OSError as cleanup_error:
            if isinstance(original_error, (KeyboardInterrupt, SystemExit)):
                original_error.add_note(
                    "evidence traversal cleanup failed: " + str(cleanup_error))
            else:
                raise OSError("evidence traversal failed: " +
                              str(original_error) + "; cleanup failed: " +
                              str(cleanup_error)) from original_error
        raise


def inspect_bundle(root_fd):
    """Inspect content with no verdict output; caller owns directory cleanup."""
    manifest_data = read_regular_at(root_fd, "manifest.json", 65536)
    try:
        payload = json.loads(manifest_data.decode("utf-8"), object_pairs_hook=unique_object_pairs)
    except (ValueError, UnicodeError):
        return False, "invalid JSON manifest"
    if (not isinstance(payload, dict) or type(payload.get("schema_version")) is not int
            or payload["schema_version"] != 1):
        return False, "unsupported evidence schema"
    if (not isinstance(payload.get("source_sha"), str)
            or not GIT_SHA.fullmatch(payload["source_sha"])
            or payload["source_sha"] == "0" * 40):
        return False, "full source commit SHA required"
    records = payload.get("evidence")
    if not isinstance(records, dict) or set(records) != set(REQUIRED):
        return False, "required evidence categories must match exactly"
    seen = set()
    for category in REQUIRED:
        record = records[category]
        if not isinstance(record, dict) or set(record) != {"file", "sha256"}:
            return False, "invalid record for " + category
        relative, expected_hash = record["file"], record["sha256"]
        if not isinstance(relative, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", relative):
            return False, "unsafe evidence filename for " + category
        if relative in seen or relative == "manifest.json":
            return False, "evidence filenames must be distinct from each other and manifest"
        seen.add(relative)
        if not isinstance(expected_hash, str) or not SHA256.fullmatch(expected_hash):
            return False, "invalid sha256 for " + category
        try:
            data = read_regular_at(root_fd, relative, 8 * 1024 * 1024)
        except (OSError, ValueError) as exc:
            return False, "unsafe evidence for " + category + ": " + str(exc)
        if hashlib.sha256(data).hexdigest() != expected_hash:
            return False, "SHA-256 mismatch for " + category
    return True, None

def check(directory):
    # Final verdict must be emitted only after the root descriptor is closed.
    try:
        root_fd = open_evidence_directory(directory)
    except (OSError, ValueError) as exc:
        return blocked("unsafe evidence directory: " + str(exc))

    valid, error = False, None
    cleanup_error = None
    try:
        valid, error = inspect_bundle(root_fd)
    except (KeyboardInterrupt, SystemExit) as interruption:
        # Preserve the exit request even when root descriptor cleanup fails.
        try:
            os.close(root_fd)
        except OSError as exc:
            interruption.add_note("evidence root cleanup failed: " + str(exc))
        raise
    except (OSError, ValueError) as exc:
        error = "cannot safely read evidence: " + str(exc)
    try:
        os.close(root_fd)
    except OSError as exc:
        cleanup_error = str(exc)

    if cleanup_error is not None:
        return blocked((error + "; " if error else "") +
                       "evidence directory close failed: " + cleanup_error)
    if not valid:
        return blocked(error or "evidence validation failed")
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
