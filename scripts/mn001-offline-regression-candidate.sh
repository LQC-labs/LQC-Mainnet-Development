#!/usr/bin/env bash
# Copyright 2026 MMXlabs & LQC LLC
# SPDX-License-Identifier: Apache-2.0
#
# MN-001 candidate ONLY. Default is a dry-run. Do not treat this script
# as authorization for validator signing, node startup, or mainnet activation.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."

chain_tests='^(TestRuntimeDevnetCompatibility|TestExplicitRuntimeValidation)$'
genesis_tests='^(TestMainnetProposalOfflineValidation|TestMainnetProfileRejectsDuplicateKeys|TestMainnetDraftOfflinePreflight|TestMainnetDraftRejectsDuplicateJSONKeys)$'
cli_tests='^(TestOfflineMainnetDraftCLI|TestReadBoundedOfflineFile)$'

if [[ "${LQC_MN001_OFFLINE_TEST_APPROVED:-0}" != '1' ]]; then
  printf '%s\n' 'MN-001 candidate only: no tests executed.'
  printf '%s\n' 'Approval requires reviewing dependency init, TestMain, and all test call graphs.'
  printf '%s\n' 'BLOCKED: approval flag alone never permits execution; isolated executor and separate authorization do not exist.'
  printf 'chain/config: %s\ngenesis: %s\ncmd/lqcd: %s\n' "$chain_tests" "$genesis_tests" "$cli_tests"
  exit 0
fi

# Defense in depth: a CI environment-variable override is not execution approval.
# A separate reviewed workflow and explicit authorization are required before CI execution.
if [[ "${GITHUB_ACTIONS:-false}" == 'true' ]]; then
  printf '%s\n' 'ERROR: MN-001 candidate execution is prohibited in GitHub Actions pending dependency-init approval.' >&2
  exit 1
fi

# Fail closed until an independently reviewed isolated executor exists.
# This guard is intentionally unconditional: an environment variable, local
# approval flag, or CI override is NOT proof of user authorization or isolation.
# Do not remove this block without a separate approved execution-gate change.
printf '%s\n' 'ERROR: MN-001 candidate execution remains BLOCKED: isolated executor and approval evidence are not implemented.' >&2
exit 1

# Candidate commands are intentionally absent until a separately reviewed,
# explicitly authorized isolated executor is implemented. The exact eight
# candidate test names above remain an inventory, not a runnable test suite.
