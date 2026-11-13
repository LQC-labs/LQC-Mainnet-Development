# 과거 보관용 검증 자료

core12/core21의 스크립트, 체크섬과 기록은 당시의 별도 source.tar에 종속된 보관용입니다. source.tar는 본 공개 후보에 포함하지 않았습니다. core12 워크플로의 tar 추출 및 core21/verify-linux.sh:source.tar 참조를 확인했습니다. 대응 워크플로는 .github/workflow-archive로 이동해 현재 CI에서 제외했습니다.

체크섬 파일은 과거 입력의 기록이며 현재 개발 소스와 비교하는 manifest가 아닙니다. 누락된 tar 대신 현재 소스를 넣거나 과거 해시를 새 해시로 바꾸지 않았습니다. 기존 검증 스크립트 본문은 그대로 보존했습니다. 현재 소스 CI는 .github/workflows/lqc-core-current-linux.yml을 참조하되, 메인넷 기본 테스트는 별도 FLOW 자료가 없으면 해당 항목을 명시적으로 SKIP합니다. 외부 자료를 제공한 검증과 자료 없는 검증을 구분하며, FLOW 런타임 통합 완료를 주장하지 않습니다.
