#!/usr/bin/env bash
# Copyright 2026 MMXlabs & LQC LLC
# SPDX-License-Identifier: Apache-2.0
#
# Offline mutation checks of the MN-001 static scope inventory.
# Runs only shell text checks in a disposable copy: never Go, nodes, or candidates.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
scratch="$(mktemp -d)"
trap 'rm -rf -- "$scratch"' EXIT
mkdir -p "$scratch/scripts"
candidate="$scratch/scripts/mn001-offline-regression-candidate.sh"
status="$scratch/scripts/mn001-approval-status.sh"
contract="$scratch/scripts/mn001-offline-scope-contract.sh"
cp scripts/mn001-offline-scope-contract.sh "$contract"

restore() {
  cp scripts/mn001-offline-regression-candidate.sh "$candidate"
  cp scripts/mn001-approval-status.sh "$status"
}
expect_blocked() {
  local description="$1" expected="$2" rc=0
  local report="$scratch/report"
  bash "$contract" >"$report" 2>&1 || rc=$?
  if [[ "$rc" -eq 0 ]] || ! grep -Fq "$expected" "$report"; then
    printf 'ERROR: expected scope mutation to block: %s (exit=%s)\n' "$description" "$rc" >&2
    cat "$report" >&2
    exit 1
  fi
  printf 'BLOCKED_AS_EXPECTED=%s\n' "$description"
}
restore
bash "$contract" >"$scratch/baseline"
grep -Fxq 'RESULT=STATIC_SCOPE_INVENTORY_ONLY' "$scratch/baseline"
grep -Fxq 'CANDIDATE_TEST_COUNT=8' "$scratch/baseline"
grep -Fxq 'MN001_GATE=NO_GO' "$scratch/baseline"
printf '%s\n' 'BASELINE=STATIC_SCOPE_ONLY'

restore
printf '%s\n' "chain_tests='^(TestInjected)$'" >> "$candidate"
expect_blocked duplicate_assignment 'expected one chain_tests assignment'
restore
sed -i 's/TestExplicitRuntimeValidation/TestInjectedRuntimeValidation/' "$candidate"
expect_blocked changed_test_name 'frozen MN-001 eight-test scope changed'
restore
printf '%s\n' '# TestReadBoundedOfflineFileFIFO' >> "$candidate"
expect_blocked forbidden_fifo 'separate FIFO fixture entered candidate scope'
restore
printf '%s\n' 'go test ./genesis' >> "$candidate"
expect_blocked direct_go_invocation 'direct Go test invocation found'
restore
sed -i '/candidate execution remains BLOCKED/d' "$candidate"
expect_blocked missing_execution_guard 'candidate execution rejection missing'
restore
sed -i '/MN001_GATE=NO_GO/d' "$status"
expect_blocked missing_no_go_marker 'NO-GO status marker missing'

printf '%s\n' 'RESULT=STATIC_CONTRACT_MUTATION_CHECKS_PASSED'
printf '%s\n' 'MN001_GATE=NO_GO'
printf '%s\n' 'BLOCKED: this verifies only the static contract against known mutations.'
