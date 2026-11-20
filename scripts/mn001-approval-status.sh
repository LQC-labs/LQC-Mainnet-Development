#!/usr/bin/env bash
# Copyright 2026 MMXlabs & LQC LLC
# SPDX-License-Identifier: Apache-2.0
#
# MN-001 offline approval status only. Never launches candidate tests,
# validators, nodes, networking, or GitHub Actions.
set -euo pipefail
printf '%s\n' 'MN001_GATE=NO_GO'
printf '%s\n' 'NETWORK_ISOLATION=BLOCKED'
printf '%s\n' 'FILESYSTEM_ISOLATION=BLOCKED'
printf '%s\n' 'CREDENTIAL_ISOLATION=BLOCKED'
printf '%s\n' 'RESOURCE_LIMITS=BLOCKED'
printf '%s\n' 'TRANSITIVE_INIT_REVIEW=BLOCKED'
printf '%s\n' 'USER_TEST_AUTHORIZATION=NOT_GRANTED'
printf '%s\n' 'MN001_CANDIDATE_TESTS=NOT_EXECUTED'
printf '%s\n' 'MAINNET=NO_GO'
printf '%s\n' 'This status is not an approval mechanism; missing evidence cannot be overridden by flags.'
exit 1
