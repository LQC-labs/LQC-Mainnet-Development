#!/usr/bin/env python3
# Copyright 2026 MMXlabs & LQC LLC
# SPDX-License-Identifier: Apache-2.0
"""MN-001 nonexecuting QEMU argv policy check.

Verifies *only* an exact minimal argument profile, not effective isolation.
Never executes QEMU, loads a guest image, builds Go, or runs tests.
"""
import json
from pathlib import Path
import sys

# No free-form device/network/share/monitor options permitted. The disk
# placeholder is NOT an executable path or an approved image.
PLAN = [
    "qemu-system-x86_64",
    "-nodefaults",
    "-no-user-config",
    "-machine", "q35,accel=kvm",
    "-cpu", "host",
    "-smp", "2",
    "-m", "2048",
    "-nic", "none",
    "-display", "none",
    "-monitor", "none",
    "-serial", "none",
    "-drive", "file=APPROVAL_REQUIRED_IMMUTABLE_GUEST_IMAGE,format=qcow2,if=virtio,readonly=on",
]

def validate(raw):
    if not isinstance(raw, dict) or set(raw) != {"schema_version", "argv"}:
        return False, "expected exact versioned argv plan"
    if type(raw["schema_version"]) is not int or raw["schema_version"] != 1:
        return False, "unsupported plan version"
    if not isinstance(raw["argv"], list) or any(type(x) is not str for x in raw["argv"]):
        return False, "argv must be a list of strings"
    if raw["argv"] != PLAN:
        return False, "VM plan differs from frozen no-network/no-host-share profile"
    return True, "frozen profile matched; security still unverified"

def main(args):
    if len(args) != 2:
        print("usage: mn001-vm-argv-policy.py PLAN.json", file=sys.stderr)
        return 2
    try:
        path = Path(args[1])
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
            raise ValueError("plan file missing, symlinked or oversized")
        plan = json.loads(path.read_text(encoding="utf-8"))
        good, reason = validate(plan)
    except (OSError, ValueError, UnicodeError) as exc:
        good, reason = False, "invalid plan: " + str(exc)
    print("VM_ARGV_POLICY=" + ("MATCHED_UNVERIFIED" if good else "BLOCKED"))
    print("MN001_GATE=NO_GO")
    print("MAINNET=NO_GO")
    print(reason)
    # Deliberately no 0 exit code: successful plan matching is NOT approval.
    return 2

if __name__ == "__main__":
    sys.exit(main(sys.argv))
