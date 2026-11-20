#!/usr/bin/env python3
# Copyright 2026 MMXlabs & LQC LLC
# SPDX-License-Identifier: Apache-2.0
"""Offline format-verifier unit tests only. No VM or MN-001 candidate execution."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

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
