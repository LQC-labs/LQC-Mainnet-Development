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
  printf '%s\n' 'After approval, run on isolated Linux with LQC_MN001_OFFLINE_TEST_APPROVED=1.'
  printf 'chain/config: %s\ngenesis: %s\ncmd/lqcd: %s\n' "$chain_tests" "$genesis_tests" "$cli_tests"
  exit 0
fi

test "$(go env GOOS)" = linux
test "$(go env GOVERSION)" = go1.25.9
export GOTOOLCHAIN=local GOWORK=off
export LQC_RUN_NATIVE_EVM=0 LQC_RUN_EVM_CONTRACT=0
export LQC_RUN_EVMRPC_INTEGRATION=0 LQC_RUN_RESTART_REGRESSION=0
export LQC_RUN_ADMISSION_REGRESSION=0 LQC_RUN_FLOW_MINIMAL=0
export LQC_RUN_CLUSTER=0 LQC_REQUIRE_FLOW_ASSETS=0
export LQC_FLOW_ASSET_ROOT=''

for race in 0 1; do
  args=(-mod=readonly -p=2 -count=1 -timeout=3m)
  if [[ "$race" == '1' ]]; then args+=(-race); fi
  go test "${args[@]}" -run "$chain_tests" ./chain/config
  go test "${args[@]}" -run "$genesis_tests" ./genesis
  go test "${args[@]}" -run "$cli_tests" ./cmd/lqcd
done
printf '%s\n' 'MN-001 candidate offline tests completed; operational security and P0 remain unverified.'
