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


def close_checked(fd):
    """Never retry close on Linux: an error may still mean FD was released."""
    try:
        os.close(fd)
        return True
    except OSError:
        return False


def check_path(path, expected_uid=None):
    """Audit each absolute directory component; errors always fail closed.

    Directory descriptors pin objects during this metadata-only check, but do
    not authenticate later evidence reads, mounts, or producer identity.
    """
    if expected_uid is None:
        expected_uid = os.getuid()
    if not isinstance(path, (str, os.PathLike)):
        return False, 'INVALID_PATH'
    raw_path = os.fspath(path)
    if not isinstance(raw_path, str):
        return False, 'INVALID_PATH'
    if not raw_path:
        return False, 'EMPTY_PATH'
    if '\\x00' in raw_path or raw_path.startswith('//'):
        return False, 'INVALID_PATH'
    requested = Path(raw_path)
    if not requested.is_absolute():
        return False, 'RELATIVE_PATH_NOT_ALLOWED'
    if not requested.parts:
        return False, 'EMPTY_PATH'

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open('/', flags)
    except OSError:
        return False, 'START_DIRECTORY_UNAVAILABLE'

    outcome = (False, 'METADATA_INSPECTION_FAILED')
    try:
        if not acceptable_directory(os.fstat(fd), expected_uid):
            outcome = (False, 'UNTRUSTED_START_DIRECTORY')
        else:
            for part in requested.parts:
                if part == '/':
                    continue
                if part == '..':
                    outcome = (False, 'PARENT_TRAVERSAL')
                    break
                # openat must receive only a relative single component.
                if part in ('.', '') or '/' in part:
                    outcome = (False, 'INVALID_COMPONENT')
                    break
                try:
                    child = os.open(part, flags, dir_fd=fd)
                except OSError:
                    outcome = (False, 'UNSAFE_COMPONENT')
                    break
                previous_fd = fd
                fd = child  # Transfer ownership before closing the parent.
                if not close_checked(previous_fd):
                    outcome = (False, 'FD_CLOSE_FAILED')
                    break
                if not acceptable_directory(os.fstat(fd), expected_uid):
                    outcome = (False, 'UNTRUSTED_DIRECTORY_METADATA')
                    break
            else:
                outcome = (True, 'DIRECTORY_METADATA_CONSISTENT')
    except (OSError, ValueError):
        outcome = (False, 'METADATA_INSPECTION_FAILED')
    finally:
        if not close_checked(fd):
            outcome = (False, 'FD_CLOSE_FAILED')
    return outcome


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
