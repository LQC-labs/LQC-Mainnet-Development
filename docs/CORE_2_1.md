# Core 2/2-1: application and CLI

This stage constructs an SDK application and exposes `lqcd --help` and
`lqcd version`. It does not initialize a chain, create keys, start CometBFT,
open RPC listeners, or implement a Genesis command.

## Reference and dependency boundary

The application composes the official Cosmos EVM `evmd` constructor from the
same commit as tag v0.7.3:

- Commit: `c3ae9067a7eadcdea55a5192226916deb44c71c4`
- Separate reference module:
  `github.com/cosmos/evm/evmd v0.0.0-20260903174530-c3ae9067a7ea`
- Cosmos EVM: v0.7.3; Cosmos SDK: v0.54.3; CometBFT: v0.39.3
- Go: 1.25.9

The separate `evmd` module is pinned to the tag commit, not a floating latest
version. Its upstream local `replace github.com/cosmos/evm => ../` is not
copied. LQC retains its existing application-level replacements and explicit
Cosmos EVM v0.7.3 requirement.

`app.New` delegates store keys, keeper construction, module services, block
ordering, ante/post handlers and the EVM mempool wiring to the reference
constructor. This includes SDK support modules, ERC20 and IBC keeper
dependencies required by its static precompiles. Removing these dependencies
is not part of this stage.

LQC injects its application name, version, Cosmos chain ID, EVM chain ID,
address prefixes, an isolated caller-supplied home, and minimum gas price.
The database is opened by the caller. The reference constructor is invoked
without loading/hydrating Genesis defaults; the wrapper then loads the empty
stores. `InitChain` is never called by this stage.

The upstream EVM chain configuration is process-global and permits a single
non-default chain configuration. Run independent application instances in
separate processes; do not create several differently configured chains in
one process.

## Fixed test profile and decimals

The unchanged `chain/config` profile is:

- Cosmos chain ID: `lqc-devnet-test-1`
- EVM chain ID: `917001`
- Bech32 account prefix: `lqctest`
- Base denom: `atest`
- Minimum gas price: `0atest`

Eighteen decimals is the design target, not an adopted production token
setting. The reference module initializes SDK power reduction to 10^18 and
contains upstream default EVM configuration. This stage does not write
LQC coin metadata, initialize module Genesis, configure an EVM coin-info
record, mint tokens, or adopt the upstream example token pairs/preinstalls.
The profile denomination is carried for the next stage; on-chain denomination
and decimal consistency remain a required Genesis-stage validation.

Do not use the upstream `DefaultGenesis` or testnet commands to create an LQC
network: they contain example-chain assets and policies. No such command is
registered by `cmd/lqcd`.

## Verification

The full reference application requires CGO: Cosmos EVM's EIP-712 ante
handler calls the CGO-only `crypto/secp256k1` API. Use `CGO_ENABLED=1` with a
compatible C compiler. A CGO-disabled build is not a supported validation of
this application, even though the earlier standalone configuration package
compiled without CGO. Do not change upstream signing code to bypass this.

Run `go test -mod=readonly ./...`, the existing JavaScript adapter tests, and
`go build -mod=readonly -o <external-output>/lqcd ./cmd/lqcd`.
Execute the resulting binary with `--help` and `version`.

The application test must construct the real reference application using an
in-memory database and temporary home, check keepers/modules/chain identity,
and close it without producing Genesis, validator keys or blocks. CLI tests
also reject `init`, `start`, `keys` and `genesis` in this stage.

Core 1/2's committed snapshot and workflow remain historical evidence. They
do not validate this new application code. No GitHub Actions run is requested
or performed as part of this stage.

## Local validation on 2026-11-01

The Windows/amd64 Go 1.25.9 build was validated with CGO enabled and a portable
Zig 0.15.2 C compiler in an external temporary directory. The compiler archive
was checked against the official Zig SHA-256. No system compiler installation
or persistent environment change was made.

- Full Go tests, including real application construction: PASS.
- Existing JavaScript tests: 25 PASS, 0 FAIL.
- Existing network configuration check: PASS.
- Actual Windows `lqcd.exe` build: PASS.
- Actual `--help` and `version` invocation: PASS.
- Version output: `lqcd 0.0.0-core2.1-dev`.

The initial CGO-disabled attempt failed with missing secp256k1 symbols. That
failure was resolved by enabling CGO, without editing upstream signing code.
A subsequent test run passed all packages but returned a Windows temporary
executable cleanup/locking error. Final tests and build used `-work` to retain
their temporary build directories and returned exit code 0. This does not
skip or relax any test.

The newly added application has not been validated on Linux or via Actions.
Genesis, token metadata, validator signing, block production and EVM RPC
remain outside this stage.
