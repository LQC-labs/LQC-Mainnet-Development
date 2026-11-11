"""Durable offline gate integration; no live RPC or signing adapters."""
from lqc_live508.shared.approval_gate import GuardedMockBackend, transaction_scope
from lqc_live508.shared.mock_backend import need, digest, canonical, uint
from lqc_live508.shared.durable_journal import Journal


def context_for(backend, gate):
    need(type(gate.record) is dict and gate.anchor is not None, "journal-approval-required")
    return {"scope": "OFFLINE_FIXTURE_JOURNAL_ONLY", "runId": backend.p["runId"], "chainId": 917001,
            "genesisSHA256": backend.p["genesisSHA256"], "approvalId": gate.record["approvalId"],
            "approvalSHA256": gate.anchor, "manifestSHA256": digest(canonical(transaction_scope(backend)))}


class JournaledMockBackend(GuardedMockBackend):
    def __init__(self, *args, journal, **kwargs):
        super().__init__(*args, **kwargs)
        need(type(journal) is Journal and journal.context == context_for(self, self.gate), "journal-adapter-binding")
        self.journal = journal
        recovered = journal.recover()
        self.recovery_blocked = recovered["blocked"]
        for role in self.reserved:
            self.reserved[role] += recovered["reserved"][role]
            self.spent[role] = recovered["spent"][role]
            need(self.reserved[role] + self.spent[role] <= min(self.budgets[role], self.balances[role]), "restored-role-budget")
        need(sum(self.spent.values()) + sum(self.reserved.values()) <= self.total, "restored-total-budget")
        for record in recovered["records"].values():
            op, role = record["operation"], record["role"]
            need(op in self.plan and self.plan[op]["senderRole"] == role, "restored-operation-role")
            tx = self.expected_envelope(op)
            need(record["txSHA256"] == digest(canonical(tx)) and record["maxReserveAtest"] == tx["gasLimit"] * tx["maxFee"], "restored-envelope-mismatch")
            self.leases.add((role, record["nonce"]))
            if record["state"] == "CONFIRMED":
                self.done.add(op)
                self.gate.used.add((journal.context["approvalId"], role, record["nonce"]))

    def expected_envelope(self, op):
        t, e = self.plan[op], self.entries[op]
        role = t["senderRole"]
        return {"runId": self.p["runId"], "chainId": 917001, "genesisSHA256": self.p["genesisSHA256"],
                "scope": "OFFLINE_SIMULATION", "operation": op, "role": role, "from": self.p["roles"][role],
                "to": e["transaction"].get("to"), "data": e["transaction"]["data"], "nonce": uint(t["nonce"]),
                "gasLimit": uint(t["gasLimit"]), "maxFee": uint(t["maxFeePerGasAtest"]),
                "maxPriority": uint(t["maxPriorityFeePerGasAtest"]), "value": 0}

    def journal_event(self, tx, stage, evidence=None):
        need(tx == self.expected_envelope(tx["operation"]), "journal-envelope-binding")
        if stage == "reserve":
            self.journal.reserve(tx)
            return
        target = {"sign-requested": "SIGN_REQUESTED", "submit-intent": "SUBMIT_INTENT",
                  "submitted": "SUBMITTED", "confirm": "CONFIRMED"}[stage]
        if stage == "submitted":
            need(evidence == "MOCK_TX:" + digest(canonical(tx)), "journal-submission-hash")
        self.journal.transition(tx["role"], tx["nonce"], target, receipt=evidence if stage == "confirm" else None)

    def execute_mock(self, operation, role):
        if self.recovery_blocked:
            self.failure = self.failure or "recovered-unresolved-submission-no-retry"
            need(False, self.failure)
        try:
            return super().execute_mock(operation, role)
        except Exception:
            # Never release a nonce or reserve automatically after an ambiguous submission.
            if not self.journal.poisoned and not self.journal.closed:
                try:
                    records = self.journal.recover()["records"]
                    found = next((r for r in records.values() if r["operation"] == operation), None)
                    if found and found["state"] not in ("CONFIRMED", "FAILED", "UNCERTAIN"):
                        state = "UNCERTAIN" if found["state"] == "SUBMIT_INTENT" else "FAILED"
                        self.journal.transition(found["role"], found["nonce"], state)
                except Exception:
                    self.failure = self.failure or "journal-failure"
            raise


class RealRPCAdapter:
    def __init__(self, *args, **kwargs):
        need(False, "real-RPC-disabled-not-implemented")

    def read_context(self):
        need(False, "real-RPC-disabled-not-implemented")

    def read_nonce(self, role):
        need(False, "real-RPC-disabled-not-implemented")

    def submit(self, tx, token):
        need(False, "real-submission-disabled-not-implemented")

    def receipt(self, tx, txid, expected):
        need(False, "real-RPC-disabled-not-implemented")


class RealSignerAdapter:
    def __init__(self, *args, **kwargs):
        need(False, "real-signer-disabled-not-implemented")

    def request_signature(self, tx):
        need(False, "real-signature-disabled-not-implemented")


class RealApprovalVerifier:
    """Approver identity and legal signing authority are NOT implemented or verified."""
    def verify(self, document):
        need(False, "real-approver-identity-authority-UNVERIFIED")
