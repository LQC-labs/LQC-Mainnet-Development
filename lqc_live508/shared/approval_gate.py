"""Offline fixture authority only. This module cannot authorize real signatures or RPC."""
import copy
import threading
from lqc_live508.shared.mock_backend import MockBackend, MemoryIO, Denied, need, canonical, digest, uint


def transaction_scope(backend):
    """Bind complete ordered calldata/constructor packet and execution ceilings."""
    p = backend.p
    entries = []
    for op, t in backend.plan.items():
        e = backend.entries[op]
        entries.append({"operation": op, "role": t["senderRole"], "from": p["roles"][t["senderRole"]],
                        "to": e["transaction"].get("to"), "value": 0,
                        "dataSHA256": digest(bytes.fromhex(e["transaction"]["data"][2:])),
                        "nonce": uint(t["nonce"]), "gasLimit": uint(t["gasLimit"]),
                        "maxFee": uint(t["maxFeePerGasAtest"]),
                        "maxPriority": uint(t["maxPriorityFeePerGasAtest"])})
    return {"chainId": p["chainId"], "genesisSHA256": p["genesisSHA256"], "runId": p["runId"],
            "profileSHA256": digest(canonical(p)), "ABIPlanSHA256": digest(canonical(backend.packet)),
            "roles": copy.deepcopy(p["roles"]), "roleBudgets": backend.budgets.copy(),
            "totalBudget": backend.total, "transactions": entries}


class FixtureClock:
    def __init__(self, now=100):
        self.time = now

    def now(self):
        return self.time


class FixtureAuthority:
    """Pinned fixture document digests, NOT a legal authority or real approval verifier."""
    def __init__(self, records):
        self.pins = {record["approvalId"]: digest(canonical(record)) for record in records}
        self.used = set()
        self.inflight = {}
        self.revoked = set()
        self.lock = threading.RLock()

    def verify(self, record):
        need(record.get("approvalId") not in self.revoked, "approval-revoked")
        need(self.pins.get(record.get("approvalId")) == digest(canonical(record)), "approval-untrusted-or-modified")


class ApprovalGate:
    def __init__(self, *, enabled=False, authority=None, record=None, clock=None):
        self.enabled = enabled
        self.authority = authority
        self.record = record
        self.clock = clock
        self.used = authority.used if type(authority) is FixtureAuthority else set()
        self.inflight = authority.inflight if type(authority) is FixtureAuthority else {}
        self.last_time = None
        self.audit = []
        self.lock = authority.lock if type(authority) is FixtureAuthority else threading.RLock()
        self.anchor = digest(canonical(record)) if record is not None else None

    def require_enabled(self):
        need(self.enabled is True and type(self.authority) is FixtureAuthority and
             type(self.clock) is FixtureClock and type(self.record) is dict,
             "default-disabled-no-verified-approval")

    def validate(self, backend, tx, phase):
        self.require_enabled()
        record = self.record
        need(digest(canonical(record)) == self.anchor, "approval-changed-during-session")
        self.authority.verify(record)
        need(record.get("scope") == "OFFLINE_GATE_TEST_ONLY" and
             record.get("issuer") == "FIXTURE_NOT_REAL_APPROVER" and
             record.get("realExecutionEnabled") is False, "real-approval-not-supported")
        need(type(record.get("approvalId")) is str and len(record["approvalId"]) == 64 and
             all(c in "0123456789abcdef" for c in record["approvalId"]), "approval-id")
        times = [record.get(k) for k in ("issuedAt", "notBefore", "expiresAt")]
        need(all(type(t) is int for t in times), "approval-time-UNKNOWN")
        issued, not_before, expires = times
        now = self.clock.now()
        need(type(now) is int and issued <= not_before <= now < expires and
             0 < expires - issued <= 240, "approval-expired-or-not-yet-valid")
        need(self.last_time is None or now >= self.last_time, "clock-rollback")
        self.last_time = now
        current = transaction_scope(backend)
        need(current == record.get("manifest"), "approval-transaction-scope-mismatch")
        need(all(tx[k] == current[k] for k in ("chainId", "genesisSHA256", "runId")), "transaction-run-binding")
        expected = next((e for e in current["transactions"] if e["operation"] == tx["operation"]), None)
        actual = {k: tx[k] for k in ("operation", "role", "from", "to", "value", "nonce", "gasLimit", "maxFee", "maxPriority")}
        actual["dataSHA256"] = digest(bytes.fromhex(tx["data"][2:]))
        need(actual == expected, "approval-role-or-envelope-mismatch")
        need(backend.io.read_context() == {k: tx[k] for k in ("chainId", "genesisSHA256", "runId")}, "context-changed")
        need(backend.io.read_nonce(tx["role"]) == (tx["nonce"], tx["nonce"]), "nonce-changed")
        need(backend.spent[tx["role"]] + backend.reserved[tx["role"]] <= backend.budgets[tx["role"]] and
             sum(backend.spent.values()) + sum(backend.reserved.values()) <= backend.total, "approval-budget-overrun")
        fingerprint = digest(canonical(tx))
        key = (record["approvalId"], tx["role"], tx["nonce"])
        need(key not in self.used, "duplicate-submission")
        if phase == "before-sign":
            need(key not in self.inflight, "duplicate-sign-request")
            self.inflight[key] = fingerprint
        else:
            need(phase == "before-submit" and self.inflight.get(key) == fingerprint, "signature-to-submit-input-changed")
            # Consume before attempting submission. Unknown outcomes can never be retried automatically.
            self.used.add(key)
        self.audit.append({"phase": phase, "approvalSHA256": self.anchor, "txSHA256": fingerprint,
                           "operation": tx["operation"], "role": tx["role"], "time": now})


class GuardedMockBackend(MockBackend):
    def __init__(self, *args, gate=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.gate = gate if gate is not None else ApprovalGate()

    def authorize(self, tx, phase):
        self.gate.validate(self, tx, phase)

    def execute_mock(self, operation, role):
        try:
            self.gate.require_enabled()
            with self.gate.lock:
                return super().execute_mock(operation, role)
        except Exception as exc:
            self.failure = self.failure or str(exc)
            raise


class RealAdapter:
    """No live implementation, authority verifier, key adapter, network or activation switch."""
    def __init__(self, *args, **kwargs):
        raise Denied("real-adapter-disabled-separate-approval-and-implementation-required")
