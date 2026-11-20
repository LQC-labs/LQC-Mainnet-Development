#!/usr/bin/env python3
# Copyright 2026 MMXlabs & LQC LLC
# SPDX-License-Identifier: Apache-2.0
"""Read-only evidence path metadata audit. Never establishes provenance or GO."""
import os
from pathlib import Path
import stat
import sys


def acceptable_directory(info, expected_uid):
    """Conservative policy: only root/current user, no group/other writes."""
    return (stat.S_ISDIR(info.st_mode)
            and info.st_uid in (0, expected_uid)
            and (info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)) == 0)


def check_path(path, expected_uid=None):
    """Pin and inspect every directory component without following links."""
    if expected_uid is None:
        expected_uid = os.getuid()
    requested = Path(path)
    if not str(path):
        return False, 'EMPTY_PATH'
    if '\x00' in str(path):
        return False, 'INVALID_PATH'
    # Relative input trusts CWD without validating its ancestor chain.
    # Require absolute paths to inspect every component from the root.
    if not requested.is_absolute():
        return False, 'RELATIVE_PATH_NOT_ALLOWED'
    if not requested.parts:
        return False, 'EMPTY_PATH'
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open('/' if requested.is_absolute() else '.', flags)
    except OSError:
        return False, 'START_DIRECTORY_UNAVAILABLE'
    try:
        if not acceptable_directory(os.fstat(fd), expected_uid):
            return False, 'UNTRUSTED_START_DIRECTORY'
        for part in requested.parts:
            if part in ('/', '.'):
                continue
            if part == '..':
                return False, 'PARENT_TRAVERSAL'
            try:
                child = os.open(part, flags, dir_fd=fd)
            except OSError:
                return False, 'UNSAFE_COMPONENT'
            os.close(fd)
            fd = child
            if not acceptable_directory(os.fstat(fd), expected_uid):
                return False, 'UNTRUSTED_DIRECTORY_METADATA'
        return True, 'DIRECTORY_METADATA_CONSISTENT'
    except OSError:
        return False, 'METADATA_INSPECTION_FAILED'
    finally:
        os.close(fd)


def main(argv):
    print('MN001_EVIDENCE_PATH_AUDIT=READ_ONLY')
    print('MN001_GATE=NO_GO')
    print('MAINNET=NO_GO')
    if len(argv) != 2:
        print('PATH_METADATA=BLOCKED REASON=USAGE')
        return 1
    allowed, reason = check_path(argv[1])
    print('PATH_METADATA=' + ('CONSISTENT_UNVERIFIED' if allowed else 'BLOCKED'))
    print('REASON=' + reason)
    print('PROVENANCE=NOT_ESTABLISHED')
    print('VM_ISOLATION=NOT_ESTABLISHED')
    print('This metadata-only check cannot authenticate evidence producers or files.')
    return 0 if allowed else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv))
