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

    def test_embedded_nul_absolute_path_rejected(self):
        self.assertEqual(module.check_path('/tmp/bundle\x00suffix'),
                         (False, 'INVALID_PATH'))

    def test_embedded_nul_rejected_before_os_open(self):
        with patch.object(module.os, 'open', side_effect=AssertionError('opened')):
            self.assertEqual(module.check_path('/bundle\x00malicious'),
                             (False, 'INVALID_PATH'))

    def test_double_slash_root_rejected_before_os_open(self):
        with patch.object(module.os, 'open', side_effect=AssertionError('opened')):
            self.assertEqual(module.check_path('//tmp/evidence'),
                             (False, 'INVALID_PATH'))

    def test_initial_open_failure_returns_blocked(self):
        with patch.object(module.os, 'open', side_effect=OSError('denied')):
            self.assertEqual(module.check_path('/trusted/evidence'),
                             (False, 'START_DIRECTORY_UNAVAILABLE'))

    def test_parent_close_failure_closes_child_and_blocks(self):
        real_close = module.os.close
        closed = []
        def close_then_fail_once(fd):
            closed.append(fd)
            real_close(fd)
            if len(closed) == 1:
                raise OSError('injected close error')
        with patch.object(module, 'acceptable_directory', return_value=True):
            with patch.object(module.os, 'close', side_effect=close_then_fail_once):
                self.assertEqual(module.check_path('/tmp'),
                                 (False, 'FD_CLOSE_FAILED'))
        self.assertEqual(len(closed), 2)
        self.assertNotEqual(closed[0], closed[1])

    def test_final_close_failure_cannot_return_consistent(self):
        real_close = module.os.close
        def close_and_fail(fd):
            real_close(fd)
            raise OSError('injected close error')
        with patch.object(module.os, 'close', side_effect=close_and_fail):
            self.assertEqual(module.check_path('/'),
                             (False, 'FD_CLOSE_FAILED'))

    def test_fstat_failure_returns_blocked_with_cleanup(self):
        with patch.object(module.os, 'fstat', side_effect=OSError('injected')):
            self.assertEqual(module.check_path('/'),
                             (False, 'METADATA_INSPECTION_FAILED'))

    def test_empty_path_rejected(self):
        self.assertEqual(module.check_path(''), (False, 'EMPTY_PATH'))

    def test_relative_directory_rejected_before_open(self):
        with patch.object(module.os, 'open', side_effect=AssertionError('opened')):
            self.assertEqual(module.check_path('private/bundle'),
                             (False, 'RELATIVE_PATH_NOT_ALLOWED'))

    def test_current_directory_alias_rejected(self):
        self.assertEqual(module.check_path('.'),
                         (False, 'RELATIVE_PATH_NOT_ALLOWED'))

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
