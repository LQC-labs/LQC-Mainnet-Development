<!--
Copyright 2026 MMXlabs & LQC LLC
SPDX-License-Identifier: Apache-2.0
-->

# LQC Mainnet Development

LQC 메인넷 자체 개발 소스입니다. FLOW 개발팀은 별도 팀이며 FLOW 원본 코드·계약·빌드 아티팩트는 이 저장소의 업로드 후보에서 제외합니다. 메인넷 소스의 기존 라이선스는 Apache-2.0입니다. 자세한 범위는 [라이선스 안내](docs/LICENSE_SCOPE.md)와 [NOTICE](NOTICE)를 확인하세요.

이 준비본은 개발 1~4단계의 RuntimeConfig, Genesis 검증, 명시적 start 설정 및 격리 다중 검증자/P2P 소스와 외부 테스트 자료 분리를 포함합니다. 공식 메인넷 Chain ID·경제 정책·검증자·운영 준비 완료를 확정하지 않습니다. 원본 5단계 소스와 증거는 별도로 보존하며 이 후보에 합치지 않았습니다.

## 빌드와 테스트

    go test -mod=readonly -p=2 ./... -count=1
    go build -mod=readonly -p=2 ./...

FLOW 관련 통합 테스트와 어댑터 검증은 유지하지만 자료는 별도로 공급합니다. 자료 없는 실행의 SKIP은 해당 검증을 수행하지 않았다는 뜻입니다. 명시적 요구·불완전한 자료·해시 불일치는 FAIL입니다. [외부 자료와 검증 방법](docs/FLOW_EXTERNAL_TESTS.md)을 확인하세요. 기본 start/코어 빌드는 FLOW 소스를 필요로 하지 않습니다.

검증자 1명 장애의 가용성, 운영 서명키 관리·복제 키 방지, 동적 검증자 변경과 장기 안정성 등 출시 차단 요소는 별도 개발·검증 대상입니다. 공개 메인넷 실행이나 실제 운영용 키·자산 사용을 승인하는 저장소가 아닙니다.

## 보관 자료

verification/core12 및 core21은 별도 source.tar에 종속된 과거 보관 자료입니다. 대응 workflow는 .github/workflow-archive에 있으며 현재 CI로 취급하지 않습니다. 현재 소스로 tar를 대신하거나 과거 체크섬을 갱신하지 마세요.
