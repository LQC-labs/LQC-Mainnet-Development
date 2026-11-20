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
        with os.scandir(self.root):
            pass  # Only synthetic local temporary files are used.
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
                    module.read_regular_at(dir_fd, "network_denial.txt", 65536)
        finally:
            os.close(dir_fd)
        # The ordinary directory case is exercised separately by the
        # existing test_directory_in_place_of_evidence_blocks test.

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
