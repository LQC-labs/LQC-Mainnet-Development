#!/usr/bin/env bash
# Copyright 2026 MMXlabs & LQC LLC
# SPDX-License-Identifier: Apache-2.0
#
# Static MN-001 test-scope contract. Does not invoke Go or test packages.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
candidate=scripts/mn001-offline-regression-candidate.sh
status=scripts/mn001-approval-status.sh
test -f "$candidate" && test -f "$status"
expected_chain='chain_tests='"'"'^(TestRuntimeDevnetCompatibility|TestExplicitRuntimeValidation)$'"'"''
expected_genesis='genesis_tests='"'"'^(TestMainnetProposalOfflineValidation|TestMainnetProfileRejectsDuplicateKeys|TestMainnetDraftOfflinePreflight|TestMainnetDraftRejectsDuplicateJSONKeys)$'"'"''
expected_cli='cli_tests='"'"'^(TestOfflineMainnetDraftCLI|TestReadBoundedOfflineFile)$'"'"''
# All three assignments must appear exactly once. Merely finding an
# expected line is insufficient if a later assignment overrides it.
for variable in chain_tests genesis_tests cli_tests; do
  count="$(grep -Ec "^[[:space:]]*${variable}=" "$candidate" || true)"
  if [[ "$count" != 1 ]]; then
    printf 'BLOCKED: expected one %s assignment, found %s.\n' "$variable" "$count" >&2
    exit 1
  fi
done
for expected in "$expected_chain" "$expected_genesis" "$expected_cli"; do
  if ! grep -Fxq -- "$expected" "$candidate"; then
    printf '%s\n' 'BLOCKED: frozen MN-001 eight-test scope changed.' >&2
    exit 1
  fi
done
# A separate FIFO fixture is not part of the eight-test candidate.
if grep -Fq 'TestReadBoundedOfflineFileFIFO' "$candidate"; then
  printf '%s\n' 'BLOCKED: separate FIFO fixture entered candidate scope.' >&2
  exit 1
fi
# This is a narrowly-scoped review assertion, not proof that arbitrary shell
# commands could never execute Go. The script must remain fail-closed.
if grep -Eq '^[[:space:]]*(go[[:space:]]+test|exec[[:space:]]+go[[:space:]])' "$candidate"; then
  printf '%s\n' 'BLOCKED: direct Go test invocation found in candidate wrapper.' >&2
  exit 1
fi
if ! grep -Fq 'candidate execution remains BLOCKED' "$candidate"; then
  printf '%s\n' 'BLOCKED: candidate execution rejection missing.' >&2
  exit 1
fi
if ! grep -Fxq "printf '%s\\n' 'MN001_GATE=NO_GO'" "$status"; then
  printf '%s\n' 'BLOCKED: NO-GO status marker missing.' >&2
  exit 1
fi
printf '%s\n' 'RESULT=STATIC_SCOPE_INVENTORY_ONLY'
printf '%s\n' 'CANDIDATE_TEST_COUNT=8'
printf '%s\n' 'MN001_GATE=NO_GO'
printf '%s\n' 'BLOCKED: static inventory is not execution permission or isolation evidence.'
