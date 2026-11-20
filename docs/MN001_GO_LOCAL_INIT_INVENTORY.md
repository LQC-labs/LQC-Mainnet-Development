# MN-001 Go import initialization inventory — local source only

**IN PROGRESS / TRANSITIVE_INIT_REVIEW=BLOCKED / MAINNET NO-GO.**

This nonexecuting tool maps local Go source files and imports reachable from
`chain/config`, `genesis`, and `cmd/lqcd`, including test files.
It lists external module imports requiring independent investigation and
source-text matches for `init`, `TestMain`, and `import "C"`.

```sh
python3 scripts/mn001-go-local-init-inventory.py .
```

* JSON output is a **source-text inventory**, not a full Go parser. It may
  include build-tag-disabled files, comments and string-literal false
  positives; it may miss syntactically unusual imports or generated sources.
* A candidate test `-run` filter cannot prevent the initialization of a
  transitively imported Go package. This tool **does not execute Go**, compile,
  load dependencies or certify their side effects.
* It always returns exit code 2 / `TRANSITIVE_INIT_REVIEW=BLOCKED`.
  NEVER interpret inventory completion as a PASS gate.
* For authoritative review, pin source, toolchain and immutable offline
  dependencies, resolve exact build-tag-aware package graph, audit upstream
  `init`/`TestMain`/CGo effects, and independently review results.
* No candidate tests, ninth FIFO fixture, VM creation, validator signing,
  node launch, PR merge or mainnet activation is authorized.

Read the source-specific observations in
[MN001_GO_INIT_REVIEW_PHASE1.md](MN001_GO_INIT_REVIEW_PHASE1.md).

## Static-only regression tests

Run `python3 scripts/test_mn001_go_local_init_inventory.py` using Python
standard-library-only synthetic fixtures. These tests cover local package
traversal, alias imports, CGo text signals, missing files, symlink rejection,
external-import classification, unsafe import paths, and documented comment
false positives. They DO NOT run Go, candidate tests, SDK initialization,
or prove the real repository's full dependency closure.

**Important:** `observed_source_signals` values are raw regular-expression
text matches. A commented-out `func init()` can produce `init_decl`; no
found signal and a found signal are **both insufficient** to certify initialization
safety. A build-tag-aware Go AST plus independent upstream code review is
still required.
