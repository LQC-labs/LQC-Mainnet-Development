#!/usr/bin/env python3
# Copyright 2026 MMXlabs & LQC LLC
# SPDX-License-Identifier: Apache-2.0
"""Synthetic-only VM argv policy test. Never invokes QEMU."""
import importlib.util
from pathlib import Path
import unittest

path = Path(__file__).with_name("mn001-vm-argv-policy.py")
spec = importlib.util.spec_from_file_location("mn001_vm_argv_policy", path)
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)

class VmArgvPolicyTests(unittest.TestCase):
    def setUp(self):
        self.good = {"schema_version": 1, "argv": list(policy.PLAN)}

    def test_only_frozen_plan_matches_but_is_unverified(self):
        self.assertTrue(policy.validate(self.good)[0])

    def test_boolean_version_rejected(self):
        self.good["schema_version"] = True
        self.assertFalse(policy.validate(self.good)[0])

    def test_unapproved_network_device_rejected(self):
        self.good["argv"] += ["-nic", "user"]
        self.assertFalse(policy.validate(self.good)[0])

    def test_host_share_rejected(self):
        self.good["argv"] += ["-virtfs", "local,path=/home,mount_tag=host,security_model=none"]
        self.assertFalse(policy.validate(self.good)[0])

    def test_monitor_port_rejected(self):
        self.good["argv"] += ["-qmp", "tcp:127.0.0.1:4444,server=on"]
        self.assertFalse(policy.validate(self.good)[0])

    def test_override_disk_path_rejected(self):
        self.good["argv"][-1] = "file=/home/user/disk.qcow2,format=qcow2,if=virtio"
        self.assertFalse(policy.validate(self.good)[0])

    def test_missing_no_nic_rejected(self):
        i = self.good["argv"].index("-nic")
        del self.good["argv"][i:i+2]
        self.assertFalse(policy.validate(self.good)[0])

    def test_extra_args_rejected(self):
        self.good["argv"].append("-enable-kvm")
        self.assertFalse(policy.validate(self.good)[0])

    def test_missing_argument_rejected(self):
        self.good["argv"].pop()
        self.assertFalse(policy.validate(self.good)[0])

    def test_unknown_schema_rejected(self):
        self.good["extra"] = "network=off"
        self.assertFalse(policy.validate(self.good)[0])

if __name__ == "__main__":
    unittest.main()
