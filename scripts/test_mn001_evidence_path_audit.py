#!/usr/bin/env python3
# Copyright 2026 MMXlabs & LQC LLC
# SPDX-License-Identifier: Apache-2.0
"""Synthetic noncandidate path-audit tests; no VM or network."""
import importlib.util
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import Mock, patch

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
            # Bypass only owner/mode policy so the symlink defense is reached.
            with patch.object(module, 'acceptable_directory', return_value=True):
                allowed, reason = module.check_path(alias)
            self.assertFalse(allowed)
            self.assertEqual(reason, 'UNSAFE_COMPONENT')

    def test_normal_directory_components_traverse(self):
        with tempfile.TemporaryDirectory() as scratch:
            child = Path(scratch) / 'real'
            child.mkdir()
            # Prove traversal succeeds when metadata policy alone is bypassed.
            with patch.object(module, 'acceptable_directory', return_value=True):
                self.assertEqual(module.check_path(child),
                                 (True, 'DIRECTORY_METADATA_CONSISTENT'))

    def test_empty_path_rejected(self):
        self.assertEqual(module.check_path(''), (False, 'EMPTY_PATH'))

    def test_relative_parent_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as scratch:
            parent = Path(scratch) / 'parent'
            parent.mkdir()
            # The prefix must exist so the audit actually encounters '..'.
            with patch.object(module, 'acceptable_directory', return_value=True):
                self.assertEqual(module.check_path(parent / '..' / 'child')[1],
                                 'PARENT_TRAVERSAL')

    def test_middle_symlink_component_rejected(self):
        with tempfile.TemporaryDirectory() as scratch:
            target = Path(scratch) / 'trusted'
            (target / 'bundle').mkdir(parents=True)
            alias = Path(scratch) / 'alias'
            alias.symlink_to(target, target_is_directory=True)
            # Reach the OS directory traversal, not the /tmp policy gate.
            with patch.object(module, 'acceptable_directory', return_value=True):
                self.assertEqual(module.check_path(alias / 'bundle')[1],
                                 'UNSAFE_COMPONENT')

    def test_group_writable_final_directory_rejected(self):
        with tempfile.TemporaryDirectory() as scratch:
            target = Path(scratch) / 'bundle'
            target.mkdir(mode=0o700)
            target.chmod(0o770)
            original = module.acceptable_directory
            # Accept the temporary-directory ancestors solely so the final
            # directory's real mode is directly checked.
            def check_final(info, uid):
                if info.st_ino == target.stat().st_ino:
                    return original(info, uid)
                return True
            with patch.object(module, 'acceptable_directory', side_effect=check_final):
                allowed, reason = module.check_path(target)
            self.assertFalse(allowed)
            self.assertEqual(reason, 'UNTRUSTED_DIRECTORY_METADATA')

    def test_missing_path_rejected(self):
        self.assertFalse(module.check_path('/some-nonexistent-mn001-directory/part')[0])


if __name__ == '__main__':
    unittest.main()
