# LQC Live 5.08 execution boundary

Official 5.08 BLOCKED / mainnet NO-GO. This package is a local implementation,
not authorization to activate a signer, node, RPC connection or deployment.

## Capabilities and threat model

The supported execution entry is LivePath. SubmissionTransport is bound once to
that path. Arbitrary callback-based authorize_once is retained only as a rejecting
compatibility stub; direct exchange rejects writes. Even invoking the inherited
exchange method still runs the capability validator. A capability is an opaque
identity registered only after the attached path validates the actual Authority,
Run/Genesis, nonce/balance/budget and the durable SUBMIT_INTENT. Constructor-created,
object.__new__-created, copied, foreign and reused lookalikes have no registry entry.

The registry binds transaction hash/raw digest, approval/trust digests, Run identity
and launch-spec digest, contract, journal path, generation and snapshot digest.
It validates them again at the wire boundary and consumes permission BEFORE send.
Issuance/dispatch share the coordinator journal lock. A consumed intent cannot
receive a fresh capability even after replacing its transport; issuance history
remains on the bound RPC. Any failure halts the receiver and its attached coordinator; unrelated unbound
receivers cannot mutate another path's journal. No automatic retries or re-signing.

This is API misuse protection inside TRUSTED Python execution, not a sandbox.
Malicious code in the same process can inspect name-mangled fields, replace
methods/modules, mutate registries, access raw bytes or create a socket directly.
Private attributes/opaque objects are NOT cryptographic or OS capabilities.
Do not load untrusted plugins or expose these Python objects to untrusted callers.

Before any untrusted-caller integration, use a separate execution broker process
and OS principal: broker exclusively owns journal, approval/trust, checkpoint and
signer connection; authenticated narrow IPC accepts an approved operation ID,
never arbitrary raw bytes/callbacks/paths. Enforce peer authorization and separate
filesystem/socket permissions; signer independently enforces scope. The client
must not have broker memory, journal or keys access. No such production broker or
signer is provided or activated here. A loopback endpoint alone is not user isolation.

## Restore and rollback

During an open journal lifetime, only locally committed (generation,snapshot hash)
pairs are accepted. A different valid snapshot, even at the same generation, poisons
the journal and prevents progress. Atomic fsync/replace primitives are reused.

Every existing journal opened with create=False is a restoration without an
independent freshness proof. recover reports blocked even if empty or all records
were CONFIRMED; Coordinator durably HALTs it. The transport also refuses restored
journals. Manual reconciliation can account for a known transaction but cannot
restart submission. create=True refuses existing journals. No journal is migrated,
deleted or overwritten by the integration tooling.

For future safe resume, an external service in a separate restore/failure domain
must atomically CAS (journal identity, approved Run, fencing epoch, monotonically
increasing generation, snapshot digest). Reserve a single-writer fencing epoch;
prepare an intent at the service; fsync the local snapshot; acknowledge completion
at the service before permitting wire dispatch. Missing records, old generation,
same-generation hash conflicts, pending CAS or service loss must HALT. Remote
acceptance of a transaction still cannot be atomically committed with a local file.
Any uncertainty requires independent chain observation and a separately approved
reconciliation. A caller-supplied boolean/local copy of a checkpoint is not trusted.

This protocol is a DESIGN, not an implemented external checkpoint adapter. Without
it the conservative HALT-on-reopen behavior is mandatory. It cannot detect malicious
replacement of the entire application and creation of a new journal by the same OS
user; that requires the broker/external trust boundary above.

## Public fixtures versus operations

Only tests/live508/fixtures contains PUBLIC SYNTHETIC fixtures: RFC public signatures,
public r=s=1 serialized transactions, UNKNOWN approval templates and compiler artifact.
None is an operational approval, funded account or signer key. Positive structured
JSON approval tests explicitly mock the Ed25519 verification seam; RFC verification
and EVM recovery/ABI/runtime checks run locally with real validators.

Place operations under var/live508 or runtime/live508, including live508-approvals,
live508-run-evidence, live508-signed-transactions, live508-checkpoints and journal/.
.gitignore excludes these, including journal.json.new, owner.json and lock. Raw signed
transactions remain broadcastable and MUST NOT be published even though they are not
private keys. Permissions 0700/0600 are not encryption. Do not upload operational
journal/approval data as workflow artifacts, diagnostics or backups with source.

## Endpoint identity

canonical_endpoint accepts only literal http://127.0.0.1:PORT with an empty path or '/'.
It adds only the trailing slash; host, numeric port and scheme are never defaulted or
rewritten. Userinfo, DNS names, alternate IPs, leading-zero ports, query, fragment,
encoded/dot paths and extra slashes are rejected. Normalize BEFORE computing the
approved Run digest. An already signed specification is never silently rewritten;
changing even its slash invalidates its pin. Chain IDs remain 917001 and
lqc-devnet-test-1. Actual Flow E2E and live EIP-1898 semantics remain UNVERIFIED.
