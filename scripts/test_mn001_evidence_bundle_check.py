#!/usr/bin/env python3
# Copyright 2026 MMXlabs & LQC LLC
# SPDX-License-Identifier: Apache-2.0
"""Offline format-verifier unit tests only. No VM or MN-001 candidate execution."""
import hashlib
from contextlib import redirect_stderr, redirect_stdout
import io
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

CHECKER = Path(__file__).resolve().with_name("mn001-evidence-bundle-check.py")
spec = importlib.util.spec_from_file_location("mn001_evidence", CHECKER)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class EvidenceCheckerTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.payload = {
            "schema_version": 1,
            "source_sha": "a" * 40,
            "evidence": {},
        }
        for key in module.REQUIRED:
            name = key + ".txt"
            body = ("synthetic-only:" + key).encode("utf-8")
            (self.root / name).write_bytes(body)
            self.payload["evidence"][key] = {
                "file": name,
                "sha256": hashlib.sha256(body).hexdigest(),
            }
        self.save_manifest()

    def save_manifest(self):
        (self.root / "manifest.json").write_text(
            json.dumps(self.payload), encoding="utf-8"
        )

    def test_parent_close_error_closes_child_without_retry(self):
        real_close = os.close
        seen = []

        def close_then_error(fd):
            seen.append(fd)
            real_close(fd)
            if len(seen) == 1:
                raise OSError("injected parent close failure")

        nested = self.root / "parent" / "evidence"
        nested.mkdir(parents=True)
        with patch.object(module.os, "close", side_effect=close_then_error):
            with self.assertRaises(OSError):
                module.open_evidence_directory(nested)
        self.assertEqual(len(seen), 2)
        self.assertNotEqual(seen[0], seen[1])

    def test_child_open_error_closes_parent_once(self):
        real_open, real_close = os.open, os.close
        opened, closed = [], []

        def fail_component(name, flags, *args, **kwargs):
            if name == "missing":
                raise OSError("injected child open failure")
            fd = real_open(name, flags, *args, **kwargs)
            opened.append(fd)
            return fd

        def record_close(fd):
            closed.append(fd)
            return real_close(fd)

        with patch.object(module.os, "open", side_effect=fail_component):
            with patch.object(module.os, "close", side_effect=record_close):
                with self.assertRaises(OSError):
                    module.open_evidence_directory(self.root / "missing")
        # Linux is free to reuse descriptor numbers once a prior FD closes.
        # Verify every successfully opened descriptor was closed once.
        self.assertGreaterEqual(len(opened), 1)
        self.assertEqual(closed, opened)

    def test_wrapper_creation_failure_closes_raw_file_fd(self):
        real_open = os.open
        opened = []
        dir_fd = real_open(str(self.root), os.O_RDONLY | os.O_DIRECTORY)
        try:
            def track_open(name, flags, *args, **kwargs):
                fd = real_open(name, flags, *args, **kwargs)
                opened.append(fd)
                return fd
            with patch.object(module.os, "open", side_effect=track_open):
                with patch.object(module.os, "fdopen", side_effect=OSError("injected wrapper failure")):
                    with self.assertRaises(OSError):
                        module.read_regular_at(dir_fd, "manifest.json", 65536)
            self.assertEqual(len(opened), 1)
            with self.assertRaises(OSError):
                os.fstat(opened[0])  # The raw file descriptor was closed.
        finally:
            os.close(dir_fd)

    def test_directory_input_closes_raw_fd(self):
        real_open = os.open
        opened = []
        dir_fd = real_open(str(self.root), os.O_RDONLY | os.O_DIRECTORY)
        try:
            def track_open(name, flags, *args, **kwargs):
                fd = real_open(name, flags, *args, **kwargs)
                opened.append(fd)
                return fd
            with patch.object(module.os, "open", side_effect=track_open):
                with self.assertRaises(ValueError):
                    module.read_regular_at(dir_fd, ".", 65536)
        finally:
            os.close(dir_fd)
        self.assertEqual(len(opened), 1)
        with self.assertRaises(OSError):
            os.fstat(opened[0])  # Rejected directory descriptor was released.

    def test_root_close_failure_never_prints_valid(self):
        root_fd = os.open(str(self.root), os.O_RDONLY | os.O_DIRECTORY)
        real_close = os.close
        out, err = io.StringIO(), io.StringIO()
        def final_close_error(fd):
            real_close(fd)
            if fd == root_fd:
                raise OSError("injected root cleanup failure")
        with patch.object(module, "open_evidence_directory", return_value=root_fd):
            with patch.object(module.os, "close", side_effect=final_close_error):
                with redirect_stdout(out), redirect_stderr(err):
                    result = module.check(self.root)
        self.assertEqual(result, 1)
        self.assertEqual(out.getvalue().count("EVIDENCE_FORMAT=BLOCKED"), 1)
        self.assertNotIn("EVIDENCE_FORMAT=VALID", out.getvalue())
        self.assertIn("root cleanup failure", err.getvalue())

    def test_validation_and_root_cleanup_errors_both_reported(self):
        self.payload["schema_version"] = 2
        self.save_manifest()
        root_fd = os.open(str(self.root), os.O_RDONLY | os.O_DIRECTORY)
        real_close = os.close
        out, err = io.StringIO(), io.StringIO()
        def final_close_error(fd):
            real_close(fd)
            if fd == root_fd:
                raise OSError("injected cleanup failure")
        with patch.object(module, "open_evidence_directory", return_value=root_fd):
            with patch.object(module.os, "close", side_effect=final_close_error):
                with redirect_stdout(out), redirect_stderr(err):
                    result = module.check(self.root)
        self.assertEqual(result, 1)
        self.assertEqual(out.getvalue().count("EVIDENCE_FORMAT=BLOCKED"), 1)
        self.assertNotIn("EVIDENCE_FORMAT=VALID", out.getvalue())
        self.assertIn("unsupported evidence schema", err.getvalue())
        self.assertIn("injected cleanup failure", err.getvalue())

    def test_file_fstat_and_close_double_failure_preserves_both(self):
        real_open, real_close, real_fstat = os.open, os.close, os.fstat
        directory = real_open(str(self.root), os.O_RDONLY | os.O_DIRECTORY)
        opened = []
        try:
            def tracked_open(name, flags, *args, **kwargs):
                fd = real_open(name, flags, *args, **kwargs)
                opened.append(fd)
                return fd
            def fail_fstat(fd):
                if fd in opened:
                    raise OSError("injected file fstat failure")
                return real_fstat(fd)
            def fail_after_close(fd):
                real_close(fd)
                if fd in opened:
                    raise OSError("injected file close failure")
            with patch.object(module.os, "open", side_effect=tracked_open):
                with patch.object(module.os, "fstat", side_effect=fail_fstat):
                    with patch.object(module.os, "close", side_effect=fail_after_close):
                        with self.assertRaises(OSError) as context:
                            module.read_regular_at(directory, "manifest.json", 65536)
            self.assertIn("file fstat failure", str(context.exception))
            self.assertIn("file close failure", str(context.exception))
            self.assertEqual(len(opened), 1)
            with self.assertRaises(OSError):
                real_fstat(opened[0])
        finally:
            real_close(directory)

    def test_file_read_and_close_double_failure_preserves_both(self):
        real_close = os.close
        directory = os.open(str(self.root), os.O_RDONLY | os.O_DIRECTORY)
        try:
            from unittest.mock import Mock
            wrapper = Mock()
            wrapper.__enter__ = Mock(return_value=wrapper)
            wrapper.__exit__ = Mock(return_value=False)
            wrapper.read.side_effect = OSError("injected read failure")
            def fail_after_close(fd):
                real_close(fd)
                if fd != directory:
                    raise OSError("injected read fd close failure")
            with patch.object(module.os, "fdopen", return_value=wrapper):
                with patch.object(module.os, "close", side_effect=fail_after_close):
                    with self.assertRaises(OSError) as context:
                        module.read_regular_at(directory, "manifest.json", 65536)
            self.assertIn("read failure", str(context.exception))
            self.assertIn("read fd close failure", str(context.exception))
        finally:
            real_close(directory)

    def test_traversal_and_cleanup_double_failure_preserves_both(self):
        real_open, real_close = os.open, os.close
        tracked = []
        def fail_component(name, flags, *args, **kwargs):
            if name == "missing":
                raise OSError("injected traversal failure")
            fd = real_open(name, flags, *args, **kwargs)
            tracked.append(fd)
            return fd
        def close_then_error(fd):
            real_close(fd)
            raise OSError("injected traversal cleanup failure")
        with patch.object(module.os, "open", side_effect=fail_component):
            with patch.object(module.os, "close", side_effect=close_then_error):
                with self.assertRaises(OSError) as context:
                    module.open_evidence_directory("missing")
        self.assertIn("traversal failure", str(context.exception))
        self.assertIn("cleanup failure", str(context.exception))
        self.assertEqual(len(tracked), 1)

    def test_unexpected_memory_error_releases_raw_fd(self):
        real_open, real_close = os.open, os.close
        directory = real_open(str(self.root), os.O_RDONLY | os.O_DIRECTORY)
        raw_fds, closed = [], []
        try:
            def tracked_open(name, flags, *args, **kwargs):
                fd = real_open(name, flags, *args, **kwargs)
                raw_fds.append(fd)
                return fd
            def tracked_close(fd):
                closed.append(fd)
                real_close(fd)
            with patch.object(module.os, "open", side_effect=tracked_open):
                with patch.object(module.os, "fstat", side_effect=MemoryError("injected memory failure")):
                    with patch.object(module.os, "close", side_effect=tracked_close):
                        with self.assertRaisesRegex(MemoryError, "memory failure"):
                            module.read_regular_at(directory, "manifest.json", 65536)
            self.assertEqual(raw_fds, closed)
            with self.assertRaises(OSError):
                os.fstat(raw_fds[0])
        finally:
            real_close(directory)

    def test_fdopen_and_close_double_failure_preserves_both(self):
        real_open, real_close = os.open, os.close
        directory = real_open(str(self.root), os.O_RDONLY | os.O_DIRECTORY)
        raw_fds, closed = [], []
        try:
            def tracked_open(name, flags, *args, **kwargs):
                fd = real_open(name, flags, *args, **kwargs)
                raw_fds.append(fd)
                return fd
            def close_with_error(fd):
                closed.append(fd)
                real_close(fd)
                raise OSError("injected cleanup error")
            with patch.object(module.os, "open", side_effect=tracked_open):
                with patch.object(module.os, "fdopen", side_effect=OSError("injected fdopen error")):
                    with patch.object(module.os, "close", side_effect=close_with_error):
                        with self.assertRaises(OSError) as context:
                            module.read_regular_at(directory, "manifest.json", 65536)
            self.assertIn("fdopen error", str(context.exception))
            self.assertIn("cleanup error", str(context.exception))
            self.assertEqual(raw_fds, closed)
        finally:
            real_close(directory)

    def test_interrupt_releases_raw_fd_before_propagation(self):
        real_open, real_close = os.open, os.close
        directory = real_open(str(self.root), os.O_RDONLY | os.O_DIRECTORY)
        raw_fds, closed = [], []
        try:
            def tracked_open(name, flags, *args, **kwargs):
                fd = real_open(name, flags, *args, **kwargs)
                raw_fds.append(fd)
                return fd
            def tracked_close(fd):
                closed.append(fd)
                real_close(fd)
            with patch.object(module.os, "open", side_effect=tracked_open):
                with patch.object(module.os, "fstat", side_effect=KeyboardInterrupt()):
                    with patch.object(module.os, "close", side_effect=tracked_close):
                        with self.assertRaises(KeyboardInterrupt):
                            module.read_regular_at(directory, "manifest.json", 65536)
            self.assertEqual(raw_fds, closed)
        finally:
            real_close(directory)

    def test_parent_and_child_close_failures_preserve_both(self):
        real_open, real_close = os.open, os.close
        opens, closes = [], []
        def tracked_open(name, flags, *args, **kwargs):
            fd = real_open(name, flags, *args, **kwargs)
            opens.append(fd)
            return fd
        def close_with_error(fd):
            closes.append(fd)
            real_close(fd)
            if len(closes) == 1:
                raise OSError("injected parent close detail")
            raise OSError("injected child close detail")
        with patch.object(module.os, "open", side_effect=tracked_open):
            with patch.object(module.os, "close", side_effect=close_with_error):
                with self.assertRaises(OSError) as context:
                    module.open_evidence_directory(self.root)
        self.assertIn("parent close detail", str(context.exception))
        self.assertIn("child close detail", str(context.exception))
        self.assertEqual(len(closes), 2)
        self.assertEqual(opens[:2], closes)

    def test_interrupt_and_file_close_failure_preserve_interrupt(self):
        real_open, real_close = os.open, os.close
        directory = real_open(str(self.root), os.O_RDONLY | os.O_DIRECTORY)
        opened, closed = [], []
        try:
            def track_open(name, flags, *args, **kwargs):
                fd = real_open(name, flags, *args, **kwargs)
                opened.append(fd)
                return fd
            def close_then_fail(fd):
                closed.append(fd)
                real_close(fd)
                raise OSError("file close diagnostic")
            with patch.object(module.os, "open", side_effect=track_open):
                with patch.object(module.os, "fstat", side_effect=KeyboardInterrupt("stop")):
                    with patch.object(module.os, "close", side_effect=close_then_fail):
                        with self.assertRaises(KeyboardInterrupt) as context:
                            module.read_regular_at(directory, "manifest.json", 65536)
            self.assertEqual(opened, closed)
            self.assertIn("file close diagnostic", " ".join(context.exception.__notes__))
        finally:
            real_close(directory)

    def test_system_exit_and_traversal_cleanup_preserve_exit_code(self):
        real_open, real_close = os.open, os.close
        opened, closed = [], []
        def track_open(name, flags, *args, **kwargs):
            fd = real_open(name, flags, *args, **kwargs)
            opened.append(fd)
            return fd
        def inject_exit(name, flags, *args, **kwargs):
            if name == "halt":
                raise SystemExit(37)
            return track_open(name, flags, *args, **kwargs)
        def close_then_fail(fd):
            closed.append(fd)
            real_close(fd)
            raise OSError("traversal close diagnostic")
        with patch.object(module.os, "open", side_effect=inject_exit):
            with patch.object(module.os, "close", side_effect=close_then_fail):
                with self.assertRaises(SystemExit) as context:
                    module.open_evidence_directory("halt")
        self.assertEqual(context.exception.code, 37)
        self.assertEqual(opened, closed)
        self.assertIn("traversal close diagnostic", " ".join(context.exception.__notes__))

    def test_interrupt_and_root_close_failure_preserve_interrupt(self):
        real_open, real_close = os.open, os.close
        root_fd = real_open(str(self.root), os.O_RDONLY | os.O_DIRECTORY)
        closed = []
        def close_then_fail(fd):
            closed.append(fd)
            real_close(fd)
            raise OSError("root close diagnostic")
        out = io.StringIO()
        with patch.object(module, "open_evidence_directory", return_value=root_fd):
            with patch.object(module, "inspect_bundle", side_effect=KeyboardInterrupt("stop")):
                with patch.object(module.os, "close", side_effect=close_then_fail):
                    with redirect_stdout(out):
                        with self.assertRaises(KeyboardInterrupt) as context:
                            module.check(self.root)
        self.assertEqual(closed, [root_fd])
        self.assertIn("root close diagnostic", " ".join(context.exception.__notes__))
        self.assertNotIn("EVIDENCE_FORMAT=VALID", out.getvalue())

    def test_memory_error_during_inspection_closes_root_once(self):
        self._assert_root_exception_closes_once(MemoryError("memory exhausted"))

    def test_recursion_error_during_inspection_closes_root_once(self):
        self._assert_root_exception_closes_once(RecursionError("recursion limit"))

    def test_memory_error_and_root_cleanup_failure_preserve_both(self):
        self._assert_root_exception_closes_once(
            MemoryError("memory exhausted"), cleanup_failure=True)

    def _assert_root_exception_closes_once(self, fault, cleanup_failure=False):
        real_open, real_close, real_fstat = os.open, os.close, os.fstat
        fd = real_open(str(self.root), os.O_RDONLY | os.O_DIRECTORY)
        close_calls = []
        out = io.StringIO()

        def instrument_close(target):
            close_calls.append(target)
            real_close(target)
            if cleanup_failure:
                raise OSError("injected root cleanup failure")

        with patch.object(module, "open_evidence_directory", return_value=fd):
            with patch.object(module, "inspect_bundle", side_effect=fault):
                with patch.object(module.os, "close", side_effect=instrument_close):
                    with redirect_stdout(out):
                        with self.assertRaises(type(fault)) as observed:
                            module.check(self.root)
        self.assertIs(observed.exception, fault)
        self.assertEqual(close_calls, [fd])
        with self.assertRaises(OSError):
            real_fstat(fd)
        self.assertNotIn("EVIDENCE_FORMAT=VALID", out.getvalue())
        if cleanup_failure:
            self.assertIn("injected root cleanup failure",
                          " ".join(observed.exception.__notes__))

    def test_synthetic_format_is_valid_but_never_authorized(self):
        self.assertEqual(module.check(self.root), 0)

    def test_boolean_schema_version_blocks(self):
        self.payload["schema_version"] = True
        self.save_manifest()
        self.assertEqual(module.check(self.root), 1)

    def test_unknown_schema_version_blocks(self):
        self.payload["schema_version"] = 2
        self.save_manifest()
        self.assertEqual(module.check(self.root), 1)

    def test_missing_required_category_blocks(self):
        del self.payload["evidence"]["network_denial"]
        self.save_manifest()
        self.assertEqual(module.check(self.root), 1)

    def test_sha256_mismatch_blocks(self):
        (self.root / "network_denial.txt").write_text("tampered")
        self.assertEqual(module.check(self.root), 1)

    def test_empty_evidence_blocks(self):
        self.payload["evidence"]["network_denial"]["sha256"] = hashlib.sha256(b"").hexdigest()
        (self.root / "network_denial.txt").write_bytes(b"")
        self.save_manifest()
        self.assertEqual(module.check(self.root), 1)

    def test_placeholder_source_sha_blocks(self):
        self.payload["source_sha"] = "0" * 40
        self.save_manifest()
        self.assertEqual(module.check(self.root), 1)

    def test_duplicate_json_key_blocks(self):
        raw = (self.root / "manifest.json").read_text(encoding="utf-8")
        raw = raw.replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1', 1)
        (self.root / "manifest.json").write_text(raw, encoding="utf-8")
        self.assertEqual(module.check(self.root), 1)

    def test_symlink_parent_directory_blocks(self):
        parent = self.root / "trusted"
        parent.mkdir()
        child = parent / "bundle"
        child.mkdir()
        alias = self.root / "alias"
        alias.symlink_to(parent, target_is_directory=True)
        self.assertEqual(module.check(alias / "bundle"), 1)

    def test_parent_traversal_rejected(self):
        self.assertEqual(module.check(self.root / ".." / self.root.name), 1)

    def test_nested_real_directory_remains_accepted(self):
        import shutil
        nested = self.root / "nested" / "bundle"
        nested.mkdir(parents=True)
        for file in self.root.iterdir():
            if file.is_file():
                shutil.copyfile(file, nested / file.name)
        self.assertEqual(module.check(nested), 0)

    def test_symlink_root_directory_blocks(self):
        link = self.root.parent / (self.root.name + "-symlink")
        link.symlink_to(self.root, target_is_directory=True)
        self.addCleanup(link.unlink)
        self.assertEqual(module.check(link), 1)

    def test_manifest_symlink_blocks(self):
        manifest = self.root / "manifest.json"
        manifest.unlink()
        manifest.symlink_to(self.root / "vm_boundary.txt")
        self.assertEqual(module.check(self.root), 1)

    def test_manifest_named_as_evidence_blocks(self):
        self.payload["evidence"]["network_denial"]["file"] = "manifest.json"
        self.save_manifest()
        self.assertEqual(module.check(self.root), 1)

    def test_fifo_evidence_blocks_without_waiting(self):
        import os
        target = self.root / "network_denial.txt"
        target.unlink()
        os.mkfifo(target)
        self.assertEqual(module.check(self.root), 1)

    def test_directory_in_place_of_evidence_blocks(self):
        target = self.root / "network_denial.txt"
        target.unlink()
        target.mkdir()
        self.assertEqual(module.check(self.root), 1)

    def test_symlink_evidence_blocks(self):
        target = self.root / "network_denial.txt"
        target.unlink()
        target.symlink_to(self.root / "vm_boundary.txt")
        self.assertEqual(module.check(self.root), 1)

    def test_path_escape_blocks(self):
        self.payload["evidence"]["network_denial"]["file"] = "../outside.txt"
        self.save_manifest()
        self.assertEqual(module.check(self.root), 1)

    def test_extra_category_blocks(self):
        self.payload["evidence"]["fake_proof"] = self.payload["evidence"]["network_denial"]
        self.save_manifest()
        self.assertEqual(module.check(self.root), 1)


if __name__ == "__main__":
    unittest.main()
