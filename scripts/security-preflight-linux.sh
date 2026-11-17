#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
test "$(go env GOVERSION)" = go1.25.9
test "$(go env GOOS)" = linux
export GOTOOLCHAIN=local GOWORK=off
export LQC_RUN_NATIVE_EVM=0 LQC_RUN_EVM_CONTRACT=0
export LQC_RUN_EVMRPC_INTEGRATION=0 LQC_RUN_RESTART_REGRESSION=0
export LQC_RUN_ADMISSION_REGRESSION=0 LQC_RUN_FLOW_MINIMAL=0
# PROPOSAL ONLY: subprocess/skip tests quarantined pending explicit safety review.
# Exact test-name allowlists: new internal tests are not automatically executed.
# TestChildCancellationReaps quarantined: invokes external /bin/sleep.
# Names alone do not certify safety: review TestMain/init and test call graphs before execution.
tests='^(TestChainConfigValidate|TestValidateNetworkPair|TestTestOnlyDevnetConfig|TestTestOnlyDevnetConfigRejectsBSCAndExampleIDs|TestDevnetConfigRejectsProductionLikeOverrides|TestApplicationWiringWithoutGenesis|TestPersistentRejectsUntrustedPaths|TestGenesisDraft|TestMVPOptionsOffline|TestMVPFundingProjectionOffline|TestMVPOptInBeforeHomeAccess|TestMVPDefaultDispatchUnchanged)$'
go test -mod=readonly -p=2 -count=1 -timeout=3m -run '^(TestDirectoryScanFailsClosedAndCoversNestedModules|TestHistoricalFixturesDetectedWithoutExecutingSDK|TestMainModuleSDKBoundary|TestMemoryAdaptersAreTestOnly|TestNoNameOnlyFalsePositives|TestSDKPatternsAndReadOnlyClassification)$' ./internal/securityaudit
go test -mod=readonly -p=2 -count=1 -timeout=3m -run '^(TestActualCoreFundingGate|TestBudgetGuards|TestCancellationDuringStep|TestCleanupAndCancellation|TestConfigAndEndpointGuards|TestConstructorAndOrder|TestConstructorGasAndBindingRejection|TestEntryCleanupExternalAddressRejected|TestEntryCleanupObservationOffline|TestEntryCoordinatorConnectionOffline|TestEntryDefaultRealBackendBlocked|TestEntryRuntimeBoundaryOffline|TestEvidenceExclusiveAndHashed|TestFreshPlanGuards|TestGoHarnessAdapterFakeLifecycle|TestIntegerAndFundingGuards|TestMVPAdapterOffline|TestMVPDefaultFactoryRemainsLegacy|TestPairObservationProofs|TestStrictJSON|TestTransactionCountCap|TestUnjoinedCleanupBlocksContinuation)$' ./internal/mvpsafety
go test -mod=readonly -p=2 -count=1 -timeout=3m -run "$tests" ./chain/config ./app ./genesis ./node
go test -mod=readonly -p=2 -race -count=1 -timeout=3m -run '^(TestDirectoryScanFailsClosedAndCoversNestedModules|TestHistoricalFixturesDetectedWithoutExecutingSDK|TestMainModuleSDKBoundary|TestMemoryAdaptersAreTestOnly|TestNoNameOnlyFalsePositives|TestSDKPatternsAndReadOnlyClassification)$' ./internal/securityaudit
go test -mod=readonly -p=2 -race -count=1 -timeout=3m -run '^(TestActualCoreFundingGate|TestBudgetGuards|TestCancellationDuringStep|TestCleanupAndCancellation|TestConfigAndEndpointGuards|TestConstructorAndOrder|TestConstructorGasAndBindingRejection|TestEntryCleanupExternalAddressRejected|TestEntryCleanupObservationOffline|TestEntryCoordinatorConnectionOffline|TestEntryDefaultRealBackendBlocked|TestEntryRuntimeBoundaryOffline|TestEvidenceExclusiveAndHashed|TestFreshPlanGuards|TestGoHarnessAdapterFakeLifecycle|TestIntegerAndFundingGuards|TestMVPAdapterOffline|TestMVPDefaultFactoryRemainsLegacy|TestPairObservationProofs|TestStrictJSON|TestTransactionCountCap|TestUnjoinedCleanupBlocksContinuation)$' ./internal/mvpsafety
go test -mod=readonly -p=2 -race -count=1 -timeout=3m -run "$tests" ./chain/config ./app ./genesis ./node
# Compile all test packages without invoking their test bodies.
# Build each package test binary without executing package init, TestMain or tests.
# Use a disposable directory; no binaries are written to the source tree.
compile_dir="$(mktemp -d)"
trap 'rm -rf -- "$compile_dir"' EXIT
# Capture the exit status of go list; process substitution would hide failures.
package_list="$compile_dir/packages.txt"
go list -mod=readonly ./... > "$package_list"
if [[ ! -s "$package_list" ]]; then
  echo "ERROR: no Go packages found; compilation cannot be certified" >&2
  exit 1
fi
index=0
while IFS= read -r package; do
  [[ -n "$package" ]] || { echo "ERROR: empty package name" >&2; exit 1; }
  index=$((index + 1))
  go test -mod=readonly -p=2 -c -o "$compile_dir/package-${index}.test" "$package"
done < "$package_list"
echo "Compiled test binaries for ${index} Go packages without running them"
