#!/usr/bin/env python3
# Copyright 2026 MMXlabs & LQC LLC
# SPDX-License-Identifier: Apache-2.0
"""Synthetic noncandidate path-audit tests; no VM or network."""
import importlib.util
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import Mock

source = Path(__file__).with_name('mn001-evidence-path-audit.py')
spec = importlib.util.spec_from_file_location('mn001_path_audit', source)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class AuditTests(unittest.TestCase):
    def info(self, mode, uid=1001):
        return Mock(st_mode=mode, st_uid=uid)

    def test_private_user_directory_acceptable(self):
        self.assertTrue(module.acceptable_directory(self.info(stat.S_IFDIR | 0o700), 1001))

    def test_root_owned_nonwritable_directory_acceptable(self):
        self.assertTrue(module.acceptable_directory(self.info(stat.S_IFDIR | 0o755, 0), 1001))

    def test_group_writable_rejected(self):
        self.assertFalse(module.acceptable_directory(self.info(stat.S_IFDIR | 0o770), 1001))

    def test_world_writable_sticky_directory_rejected(self):
        self.assertFalse(module.acceptable_directory(self.info(stat.S_IFDIR | 0o1777, 0), 1001))

    def test_foreign_owner_rejected(self):
        self.assertFalse(module.acceptable_directory(self.info(stat.S_IFDIR | 0o700, 1002), 1001))

    def test_nondirectory_rejected(self):
        self.assertFalse(module.acceptable_directory(self.info(stat.S_IFREG | 0o600), 1001))

    def test_parent_traversal_rejected(self):
        self.assertEqual(module.check_path('/../tmp')[1], 'PARENT_TRAVERSAL')

    def test_world_writable_tmp_path_rejected(self):
        with tempfile.TemporaryDirectory() as scratch:
            self.assertFalse(module.check_path(scratch)[0])

    def test_symlink_component_rejected(self):
        with tempfile.TemporaryDirectory() as scratch:
            target = Path(scratch) / 'real'
            target.mkdir()
            alias = Path(scratch) / 'alias'
            alias.symlink_to(target, target_is_directory=True)
            self.assertFalse(module.check_path(alias)[0])

    def test_missing_path_rejected(self):
        self.assertFalse(module.check_path('/some-nonexistent-mn001-directory/part')[0])


if __name__ == '__main__':
    unittest.main()
