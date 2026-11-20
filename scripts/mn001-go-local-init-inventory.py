#!/usr/bin/env python3
# Copyright 2026 MMXlabs & LQC LLC
# SPDX-License-Identifier: Apache-2.0
"""Read-only local Go import/initializer inventory for MN-001.

No Go tools, imports, binaries, tests, VM, or network calls. Deliberately
incomplete for external transitive modules; always returns BLOCKED (exit 2).
"""
import json
from pathlib import Path
import re
import sys

MODULE = "github.com/LQC-labs/LQC-Mainnet-Development"
ROOTS = ("chain/config", "genesis", "cmd/lqcd")
IMPORT = re.compile(r'^\s*(?:[\w.]+\s+)?"([^"\n]+)"\s*(?://.*)?$')
FUNC_INIT = re.compile(r'\bfunc\s+init\s*\(')
FUNC_TESTMAIN = re.compile(r'\bfunc\s+TestMain\s*\(')
BLOCK_IMPORT = re.compile(r'(?m)^\s*import\s*\((.*?)\)', re.S)
SINGLE_IMPORT = re.compile(r'(?m)^\s*import\s+(?:[\w.]+\s+)?"([^"\n]+)"')

def imports_of(source):
    found = set(SINGLE_IMPORT.findall(source))
    for block in BLOCK_IMPORT.findall(source):
        for line in block.splitlines():
            m = IMPORT.fullmatch(line.strip())
            if m:
                found.add(m.group(1))
    return found

def inventory(root):
    packages = set(ROOTS)
    queue = list(ROOTS)
    findings = []
    external = set()
    scanned = []
    while queue:
        package = queue.pop(0)
        folder = root / package
        if folder.is_symlink() or not folder.is_dir():
            raise ValueError("missing or symlinked local package: " + package)
        files = sorted(folder.glob("*.go"))
        if not files:
            raise ValueError("empty Go package: " + package)
        for path in files:
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
                raise ValueError("unsafe Go file: " + str(path))
            source = path.read_text(encoding="utf-8")
            relative = path.relative_to(root).as_posix()
            scanned.append(relative)
            for label, pattern in (("init_decl", FUNC_INIT), ("testmain_decl", FUNC_TESTMAIN)):
                for match in pattern.finditer(source):
                    findings.append({"file": relative, "signal": label,
                                     "line": source.count("\n", 0, match.start()) + 1})
            for imported in imports_of(source):
                if imported == "C":
                    findings.append({"file": relative, "signal": "cgo_import"})
                elif imported.startswith(MODULE + "/"):
                    local = imported[len(MODULE) + 1:]
                    if not re.fullmatch(r"[a-zA-Z0-9_/-]+", local) or ".." in local.split("/"):
                        raise ValueError("unsafe local import: " + imported)
                    if local not in packages:
                        packages.add(local)
                        queue.append(local)
                else:
                    external.add(imported)
    return {"source_scope": "LOCAL_PACKAGE_FILES_ONLY", "candidate_roots": list(ROOTS),
            "local_packages": sorted(packages), "go_files": sorted(scanned),
            "observed_source_signals": findings, "external_imports_not_audited": sorted(external),
            "transitive_init_review": "BLOCKED", "mn001_gate": "NO_GO",
            "mainnet": "NO_GO"}

def main():
    if len(sys.argv) != 2:
        print("usage: mn001-go-local-init-inventory.py REPOSITORY_ROOT", file=sys.stderr)
        return 2
    try:
        root = Path(sys.argv[1]).resolve(strict=True)
        result = inventory(root)
        print(json.dumps(result, indent=2, sort_keys=True))
    except (OSError, UnicodeError, ValueError) as error:
        print("TRANSITIVE_INIT_REVIEW=BLOCKED; MN001_GATE=NO_GO", file=sys.stderr)
        print("INVENTORY_ERROR=" + str(error), file=sys.stderr)
    # Even a successful local inventory cannot prove transitive module safety.
    return 2

if __name__ == "__main__":
    sys.exit(main())
