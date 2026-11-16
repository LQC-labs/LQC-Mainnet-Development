#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
test "$(go env GOVERSION)" = go1.25.9
test "$(go env GOOS)" = linux
export GOTOOLCHAIN=local GOWORK=off
export LQC_RUN_NATIVE_EVM=0 LQC_RUN_EVM_CONTRACT=0
export LQC_RUN_EVMRPC_INTEGRATION=0 LQC_RUN_RESTART_REGRESSION=0
export LQC_RUN_ADMISSION_REGRESSION=0 LQC_RUN_FLOW_MINIMAL=0
# Exact allowlist: no node startup, key generation or validator signing tests.
tests='^(TestChainConfigValidate|TestValidateNetworkPair|TestTestOnlyDevnetConfig|TestTestOnlyDevnetConfigRejectsBSCAndExampleIDs|TestDevnetConfigRejectsProductionLikeOverrides|TestApplicationWiringWithoutGenesis|TestPersistentDBReconnect|TestPersistentRejectsUntrustedPaths|TestPersistentQueueCapacities|TestGenesisDraft|TestMVPOptionsOffline|TestMVPFundingProjectionOffline|TestMVPOptInBeforeHomeAccess|TestMVPDefaultDispatchUnchanged|TestFlowMinimalArtifacts)$'
go test -mod=readonly -p=2 -count=1 -timeout=3m ./internal/securityaudit ./internal/mvpsafety
go test -mod=readonly -p=2 -count=1 -timeout=3m -run "$tests" ./chain/config ./app ./genesis ./node
go test -mod=readonly -p=2 -race -count=1 -timeout=3m ./internal/securityaudit ./internal/mvpsafety
go test -mod=readonly -p=2 -race -count=1 -timeout=3m -run "$tests" ./chain/config ./app ./genesis ./node
# Compile all test packages without invoking their test bodies.
go test -mod=readonly -p=2 -run '^$' ./...
