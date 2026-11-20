#!/usr/bin/env python3
# Copyright 2026 MMXlabs & LQC LLC
# SPDX-License-Identifier: Apache-2.0
"""Synthetic-only checks of the local Go source-text inventory.

This does not load Go modules, run Go, execute candidate tests, or certify init safety.
"""
import importlib.util
from pathlib import Path
import tempfile
import unittest

checker = Path(__file__).resolve().with_name("mn001-go-local-init-inventory.py")
spec = importlib.util.spec_from_file_location("mn001_go_inventory", checker)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class GoLocalInventoryTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        for package in module.ROOTS:
            folder = self.root / package
            folder.mkdir(parents=True)
            (folder / "sample.go").write_text(
                'package x\nimport "fmt"\n', encoding="utf-8"
            )

    def test_baseline_reports_no_go(self):
        result = module.inventory(self.root)
        self.assertEqual(len(result["local_packages"]), 3)
        self.assertEqual(result["mn001_gate"], "NO_GO")
        self.assertEqual(result["transitive_init_review"], "BLOCKED")

    def test_local_alias_import_recurses(self):
        (self.root / "cmd/lqcd/sample.go").write_text(
            'package x\nimport (\n alias "github.com/LQC-labs/LQC-Mainnet-Development/app"\n _ "os"\n)\n',
            encoding="utf-8",
        )
        folder = self.root / "app"
        folder.mkdir()
        (folder / "app.go").write_text(
            "package app\nfunc init() {}\nfunc TestMain(m *testing.M) {}\n",
            encoding="utf-8",
        )
        result = module.inventory(self.root)
        self.assertIn("app", result["local_packages"])
        self.assertEqual(len(result["observed_source_signals"]), 2)

    def test_cgo_signal(self):
        (self.root / "genesis/sample.go").write_text(
            'package x\nimport "C"\n', encoding="utf-8"
        )
        result = module.inventory(self.root)
        self.assertTrue(any(
            entry["signal"] == "cgo_import"
            for entry in result["observed_source_signals"]
        ))

    def test_symlink_is_rejected(self):
        file = self.root / "genesis/sample.go"
        file.unlink()
        file.symlink_to(self.root / "chain/config/sample.go")
        with self.assertRaises(ValueError):
            module.inventory(self.root)

    def test_missing_go_files_is_rejected(self):
        (self.root / "chain/config/sample.go").unlink()
        with self.assertRaises(ValueError):
            module.inventory(self.root)

    def test_comments_are_unverified_source_text_signals(self):
        (self.root / "genesis/sample.go").write_text(
            "package x\n// func init() { }\n", encoding="utf-8"
        )
        result = module.inventory(self.root)
        self.assertTrue(any(
            entry["signal"] == "init_decl"
            for entry in result["observed_source_signals"]
        ))
        self.assertEqual(result["transitive_init_review"], "BLOCKED")

    def test_external_import_remains_unaudited(self):
        (self.root / "genesis/sample.go").write_text(
            'package x\nimport "github.com/cosmos/cosmos-sdk/types"\n',
            encoding="utf-8",
        )
        self.assertIn(
            "github.com/cosmos/cosmos-sdk/types",
            module.inventory(self.root)["external_imports_not_audited"],
        )

    def test_local_path_traversal_is_rejected(self):
        (self.root / "cmd/lqcd/sample.go").write_text(
            'package x\nimport "github.com/LQC-labs/LQC-Mainnet-Development/../escape"\n',
            encoding="utf-8",
        )
        with self.assertRaises(ValueError):
            module.inventory(self.root)


if __name__ == "__main__":
    unittest.main()
