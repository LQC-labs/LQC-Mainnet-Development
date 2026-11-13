> 현재 메인넷 공개 후보 안내: 아래는 과거 로컬 검증 및 통합 설계 기록입니다. FLOW 팀의 계약·ABI·아티팩트는 이 저장소에 포함하지 않습니다. 기존 경로 설명은 별도 자료 묶음 기준이며, 자료 없는 SKIP은 FLOW 검증 성공이 아닙니다. 현재 분리 정책과 실행 방법은 [FLOW_EXTERNAL_TESTS.md](FLOW_EXTERNAL_TESTS.md)를 확인하세요.

# Core 3/4 — original Flow minimal local integration

This is a bounded opt-in Devnet integration test, not a production deployment,
wallet UI integration, bridge or Mainnet activation. No GitHub operation is
performed by these files.

## Source and compiler

Flow source is pinned to LQC-labs/LQC-Liquidity-chain commit
8db16368b3e09a94bfd500a17e33e3e9ef62ed51. The Factory, Pair,
LQCTestToken, MockWBNB and dependency sources remain unchanged. The Router has
one local minimum-guard patch, with its exact original saved under upstream/.
The complete pinned closure (11 files) is accounted for under node/testdata/flow-minimal/contracts. SPDX MIT notices remain.
SOURCE.json records upstream paths, Git blob SHA-1, SHA-256, compiler provenance,
settings and artifact hashes. Full solc JSON ABIs are retained with bytecode.

Compiler: official ethereum/solc-bin Solidity 0.8.30+commit.73712a01 Linux binary,
SHA-256 f3e987dc6ecebd4bd350c48edcbc320b46cf9e3109bd3fc3d88f1acaf4c428f7.
It is not vendored or installed globally. User-approved download was confined
to the isolated validation toolchain directory. Settings match Flow:
optimizer enabled/runs200, viaIR, evmVersion shanghai.

Given the separately provisioned compiler, verify all seven artifacts offline:

    python3 scripts/verify-flow-minimal-build.py --solc /absolute/path/to/solc-0.8.30

The script downloads nothing and overwrites nothing. It checks compiler/source
hashes and requires byte-for-byte reproducible artifacts.

## What is used and what is new

- Factory/Pair and both normal tokens are original Flow contracts. Router
  retains the original implementation plus one explicit minimum guard; it is
  not a replacement AMM or hand-built EVM bytecode.
- LQCTestToken is owner-minted only for testing. Separate instances use 18 and
  6 decimals. These are not issued production LQC assets.
- Flow's MockWBNB is deployed at a NEW LQC address and backed by Devnet native
  value. The upstream name/symbol still says BNB/WBNB. It is a test-only
  IWBNB-compatible wrapper, not BSC WBNB and not an approved production wrapped
  LQC asset. No BSC address is reused.
- FlowCallbackToken and FlowWithdrawalProbe are NEW adversarial test fixtures.
  They exercise the original Pair lock and wrapper accounting. They are never
  used as substitutes for the main 18/6-decimal swap pool.
- Node, app, fixed chain settings, go.mod/go.sum, BSC profiles and prior tests
  are unchanged.

## Explicit local execution

Ordinary go test runs provenance/ABI checks and skips node execution.
Use Linux, Go1.25.9 and Node22.16.0. Build and run the opt-in test:

    go test -mod=readonly -p=2 -c -o /new/private/test-area/node.test ./node
    LQC_RUN_FLOW_MINIMAL=1 LQC_FLOW_TEST_PARENT=/new/private/evidence /new/private/test-area/node.test -test.run='^TestFlowMinimalIntegration$' -test.v -test.timeout=240s

All homes are NEW Linux directories named lqc-flow-minimal.*. A new funded
account key, consensus key and node key are prepared using existing Core
fixtures, with existing permissions. Nothing opens or resets an old home.
RPC/P2P are loopback-only and RPC allows only http://localhost:3000 as the
explicit browser Origin. No peers, external chain endpoints or deployments.
Account private keys and mnemonics are never printed.

The test retains its home/evidence. Do not copy its keys, DB, WAL or signing
state into a repository. Compiler binaries and generated runtime homes belong
outside source control.

## Runtime checks

The test deploys real compiled contracts, mints test assets, checks transfers,
allowance/approve, wrapper deposit/withdraw and backing, creates a real Pair,
adds liquidity, verifies reserves/LP shares, compares getAmountsOut with the
0.30%-fee constant-product formula and sends a signed swapExactTokensForTokens.
Balances, exact allowance consumption, reserves and token conservation are
checked against actual state. Receipts/events/log queries are compared using
the compiled ABI and actual block/transaction identities.

Negative signed transactions cover zero recipient, insufficient token balance,
insufficient approval, expired deadline, excessive minOut, invalid path and
invalid swap recipient. Reverts may consume native gas and a nonce; ERC20
balances/allowance, reserves and logs must roll back. A chain97 signature is
rejected before inclusion on chain917001.

An adversarial output token calls sync during Pair.swap; the nested call must
return the actual Locked selector while the bounded swap succeeds. A receiver
tries to withdraw the same wrapper credit twice; backing/supply and recipient
balances must remain conserved. This is a targeted test, not a complete
reentrancy or economic audit.

The node closes, then a NEW process opens the same new home and extends the
chain. Block1/block11, Genesis/keys/validator/signing continuity, runtime code,
ERC20 balances, main Pair reserves and all prior receipts are compared. The
swap event is queried again after restart. Listeners and home locks are closed.

## Core 3/3 integration and evidence

flow-minimal-preflight.mjs derives runtime profiles/manifests from the original
Core3/3 templates without changing them. Core3/3's real read-only deployment
verifier checks deployed token18/wrapper bytecode hashes and successful
deployment receipts at the current local RPC. Factory/Router are checked too.
The Pair is correctly recorded as an internal factory CREATE: its outer
transaction receipt has no top-level contractAddress, so its PairCreated event
and code are the relevant creation evidence.

The flowMinimal manifest extension and full JSON ABI sidecar record the
Factory/Pair/Router/token6 path. Unsupported modules remain null. The existing
configuration transaction gate remains disabled; no wallet UI is activated.
All generated addresses and RPC ports live only in the isolated evidence.

## Boundaries and upstream limitations

- No real browser/wallet or full Flow dApp integration is claimed.
- Lending/Futures/Oracle/Intent/Settlement/Staking/Launchpad and economic
  activation are outside this minimum route.
- Fee-on-transfer/rebasing tokens are outside the original Router's supported
  route. No cross-chain asset migration or price Oracle is introduced.
- The local Router now rejects amountAMin/amountBMin greater than desired
  before the initial empty-pool return. Its original version is retained under
  upstream/LQCFlowRouter.sol with the original Git blob/hash; SOURCE.json
  separates patched_sources from unmodified original_sources. ABI/error names
  are unchanged. This is a LOCAL patch, not an upstream/BSC deployment change.
- Real signed negative liquidity transactions cover no Pair, empty existing
  Pair and an already funded Pair, with A-only/B-only/both minima violations.
  Factory mappings/count/nonce/predicted code, token balances/allowances/supply,
  LP shares/reserves/timestamp and logs must all remain unchanged on revert.
- Compiler immutables are compared only at compiler-declared slots; constructor
  getters and persistent runtime hashes provide the value/continuity checks.
- Pending-pool durability and synthetic pending state remain unsupported as
  documented by Core3/2. The test uses committed receipts.
- Existing CI is unchanged. It can run provenance/unit checks but must not
  operate this node as a persistent service. Live execution remains local opt-in.
