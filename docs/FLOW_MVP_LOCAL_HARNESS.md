> 현재 메인넷 공개 후보 안내: 아래는 과거 로컬 검증 및 통합 설계 기록입니다. FLOW 팀의 계약·ABI·아티팩트는 이 저장소에 포함하지 않습니다. 기존 경로 설명은 별도 자료 묶음 기준이며, 자료 없는 SKIP은 FLOW 검증 성공이 아닙니다. 현재 분리 정책과 실행 방법은 [FLOW_EXTERNAL_TESTS.md](FLOW_EXTERNAL_TESTS.md)를 확인하세요.

# Offline LQC Devnet MVP harness

Core base b79394246a8819a7651275bd07c88b83bccdd8df plus the verified 27-file overlay.
Flow candidate 013d159f05ed6a924ee965ec41ef193a069da122 is Draft/unmerged and NOT operationally approved.

config/flow/mvp/ is independent of the existing Router2 subset registry/manifest.
All addresses and transaction/code fields start null. Deployment and transactions stay disabled.
MockWBNB is a test wrapper with actual symbol WBNB, not canonical LQC/BSC wrapped native.
Native atest/test has 18 decimals; ERC20 A18/B6 use separate raw units.

Commands from the isolated Core source directory:

    python3 scripts/compile-flow-mvp.py --solc /path/to/already-verified/solc-0.8.30
    node tools/flow-mvp/cli.mjs check
    node tools/flow-mvp/cli.mjs plan
    node --test tools/flow-mvp/mvp.test.mjs

Only ethers6.17.0 and its locked dependency closure are needed by this offline tool.
The current workspace reuses a local installed cache; no npm install/download is run.
The compiler input has the 11 pinned Solidity dependencies. No external Solidity library linking.
Artifacts include immutable variable mappings so runtime comparison checks constructor-bound values.

The symbolic order is test A/B, wrapper, Factory, Factory-created AB/native Pairs, then Router.
Constructor values are encoded offline only after explicit local address bindings are provided.
No transport/signer/wallet/send/deploy/mint/node-start function exists in this tool.
CLI accepts only check and plan. A deploy command fails without executing anything.
The gas/time limits are validated planning constraints; no simulation or node is executed here.

verifyPairObservations consumes an injected read-only provider. It checks chain917001,
successful Factory-target receipt, one matching PairCreated event, bidirectional getPair,
exact Factory/Pair runtime (including immutables), and Pair factory/token0/token1 getters.
It never assumes receipt.contractAddress is the internally-created Pair.
Unit tests supply synthetic observations. Passing them does NOT prove an actual deployment.
Existing Router2, BSC56/97 profiles, go.mod/go.sum and existing fixtures are preserved.
Actual local deployment/transactions/restart and full dApp integration remain NOT TESTED.
