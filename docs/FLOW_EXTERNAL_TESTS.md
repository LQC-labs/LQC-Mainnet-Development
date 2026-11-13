# 별도 FLOW 팀 자료를 이용하는 메인넷 통합 테스트

이 저장소는 FLOW 소스나 계약 아티팩트를 배포하지 않습니다. 테스트 코드와 기존 해시·ABI·수수료·롤백·재시작 검증은 유지합니다. 외부 자료가 없으면 해당 데이터 의존 테스트는 명시적으로 SKIP하며, 이는 FLOW 검증 PASS가 아닙니다. 일부 internal/mvpsafety 오프라인 어댑터 시험도 같은 입력에 의존하므로 기본 실행에서 SKIP될 수 있습니다.

메인넷 자체 기본 검증:

    go test -mod=readonly -p=2 ./... -count=1
    go build -mod=readonly -p=2 ./...
    node --test scripts/flow-quote-adapter.test.mjs

별도로 적법하게 제공받은 자료는 저장소 밖의 절대 경로에 두세요. 자동 다운로드나 외부 스크립트 실행은 하지 않습니다. bundle root 아래에 다음 경로를 유지합니다: node/testdata/flow-minimal/SOURCE.json 및 원래 contracts/upstream/artifacts, config/flow의 원래 ABI와 테스트 설정, tools/flow-mvp의 기존 build-manifest와 artifacts. 사용자가 지정한 경로가 잘못됐거나 일부 파일만 있거나 해시/ABI가 다르면 실패합니다. 다른 자료로 자동 대체하지 않습니다.

외부 자료 포함 오프라인 검증(노드·실제 FLOW 통합 실행은 활성화하지 않음):

    LQC_FLOW_ASSET_ROOT=/absolute/external/bundle LQC_REQUIRE_FLOW_ASSETS=1 go test -mod=readonly -p=2 ./... -count=1

자료 누락을 반드시 오류로 검사하려면 LQC_REQUIRE_FLOW_ASSETS=1을 사용하세요. LQC_RUN_FLOW_MINIMAL=1로 실제 통합 시험을 요청해도 자료가 없으면 키·HOME·노드를 만들기 전에 FAIL입니다. 실제 통합 실행은 별도 승인이 필요합니다. 단순 자료 검증과 실제 통합 시험을 구분해 보고하세요.

직접 의존: node/flow_minimal_integration_test.go는 원문·아티팩트의 핀과 해시 및 기존 런타임 검증을 수행합니다. node/flow_minimal_helpers_test.go는 ABI/bytecode를 읽고, 메인넷 소유 scripts/flow-minimal-preflight.mjs가 외부 자료의 ABI·배포 영수증을 사용합니다. internal/mvpsafety/adapter_linux.go는 config/flow/mvp와 tools/flow-mvp/build-manifest 및 artifacts를 읽으며 pair.go는 Factory/Pair ABI를 사용합니다. internal/mvpsafety/mvp.go는 테스트 funding 설정을 읽습니다. 이 어댑터는 메인넷 기본 start 경로에 포함된 자동 계약 배포기가 아닙니다.

별도 도구 scripts/compile-flow-mvp.py, scripts/verify-flow-minimal-build.py, scripts/flow-devnet-profile.test.mjs 및 tools/flow-mvp의 로컬 도구도 원래 FLOW 입력 없이는 실행할 수 없습니다. 이 도구들의 기본 경로를 임의 데이터나 새 구현으로 대체하지 않았습니다. 기본 메인넷 CI는 이 선택형 도구를 호출하지 않습니다.
