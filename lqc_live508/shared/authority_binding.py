"""Cryptographic approval checks around a MOCK backend. Live adapters remain disabled."""
from lqc_live508.shared.approval_gate import transaction_scope
from lqc_live508.shared.journal_backend import JournaledMockBackend
from lqc_live508.shared.offline_authority import OfflineApprovalVerifier
from lqc_live508.shared.mock_backend import need, canonical, digest


class ApprovalBinding:
    def __init__(self, verifier, signed_document, clock):
        need(type(verifier) is OfflineApprovalVerifier, "offline-verifier-required")
        self.verifier = verifier
        self.document = signed_document
        self.document_pin = digest(canonical(signed_document))
        self.trust_pin = verifier.trust.pin
        self.clock = clock

    def validate(self, backend):
        return self.validate_scope(transaction_scope(backend), backend.journal.path,
                                   backend.journal.context["approvalId"], backend.gate.record)

    def validate_scope(self, manifest, journal_path, journal_approval_id, anchors):
        """Shared verification for mock and live callers; no execution permission."""
        need(digest(canonical(self.document)) == self.document_pin and self.verifier.trust.pin == self.trust_pin, "authority-binding-changed")
        verified = self.verifier.verify(self.document, manifest, self.clock.now())
        registration = self.verifier.trust.document.get("journalBindings", {}).get(manifest["runId"])
        need(type(registration) is dict and registration == {
            "genesisSHA256": manifest["genesisSHA256"], "approvalId": verified["approvalId"],
            "pathSHA256": digest(str(journal_path).encode())}, "unregistered-or-rebound-journal-HALTED")
        record = anchors
        need(record.get("externalApprovalSHA256") == self.document_pin and record.get("externalTrustSHA256") == self.trust_pin,
             "journal-external-approval-anchor")
        need(verified["approvalId"] == journal_approval_id, "journal-approval-id")
        return verified


class AuthorityBoundMockBackend(JournaledMockBackend):
    def __init__(self, *args, binding, **kwargs):
        super().__init__(*args, **kwargs)
        self.binding = binding
        # Journal is read/replayed before this point; no signatures or submissions can occur.
        self.binding.validate(self)
        self.halted = self.recovery_blocked

    def authorize(self, tx, phase):
        self.binding.validate(self)
        super().authorize(tx, phase)

    def execute_mock(self, operation, role):
        try:
            self.binding.validate(self)
            need(not self.halted, "HALTED-no-automatic-resubmission")
            return super().execute_mock(operation, role)
        except Exception as exc:
            self.halted = True
            self.failure = self.failure or str(exc)
            raise

    def result(self):
        result = super().result()
        result["operationalState"] = "HALTED" if self.halted or self.failure else "OFFLINE_MOCK_ONLY"
        result["realExecutionEnabled"] = False
        return result


class RealChainEvidenceVerifier:
    """No RPC/light-client/real-chain proof source is supplied in this offline task."""
    def verify(self, evidence, journal_context):
        need(False, "REAL_CHAIN_EVIDENCE_UNVERIFIED-HALTED")


def review_manual_recovery(verifier, signed_recovery, manifest, now, journal, chain_evidence=None):
    """A separate recovery approval and independently verified chain evidence are mandatory.

    No method resets leases/budgets, edits journal history, or resubmits a transaction.
    """
    verifier.verify(signed_recovery, manifest, now, purpose="MANUAL_RECOVERY")
    recovery = signed_recovery["body"]["recovery"]
    journal.recover()
    need(recovery["journalSHA256"] == digest(canonical(journal.payload)), "recovery-journal-snapshot-mismatch")
    need(chain_evidence is not None and digest(canonical(chain_evidence)) == recovery["chainEvidenceSHA256"], "recovery-chain-evidence-missing-or-mismatched")
    RealChainEvidenceVerifier().verify(chain_evidence, journal.context)
    need(False, "HALTED-manual-state-change-not-implemented")
