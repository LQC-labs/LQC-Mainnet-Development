"""Reuse Ed25519 approval verification and ApprovalBinding for the live contract.

This module owns no private keys and performs no EVM signing or RPC calls.
RunBinding is rechecked locally; RPCBoundVerification adds actual/synthetic RPC
preflight separately. Recovery/receipt chain verification remains unavailable.
"""
import copy
from lqc_live508.authority_reuse import (need, canonical, digest, validate_contract, parse_signed_document,
                             OfflineApprovalVerifier, ApprovalBinding, LiveJournal)
from lqc_live508.live_signer import EVMTransactionVerifier


def approval_scope(contract):
    """Extend signed manifest without a self-reference to approvalSHA256.

    Legacy verifier accepts this exact expected manifest and signs all its bytes.
    The old LiveJournal manifest schema and its transaction projection stay intact.
    """
    c = validate_contract(contract)
    m = copy.deepcopy(c['manifest'])
    b = c['binding']
    m['liveBinding'] = {'schema': 'LQC_LIVE_AUTHORITY_V1', 'runEvidenceSHA256': b['runEvidenceSHA256'],
                        'journalPathSHA256': b['journalPathSHA256'], 'trustSHA256': b['trustSHA256'],
                        'envelopesSHA256': digest(canonical(c['envelopes'])), 'transactionType': 2, 'accessList': []}
    if 'evidencePolicySHA256' in b:
        m['liveBinding']['evidencePolicySHA256'] = b['evidencePolicySHA256']
    return m


class BindingClock:
    def __init__(self, owner): self.owner = owner
    def now(self): return self.owner.verification_time


class LiveAuthorityBinding:
    def __init__(self, contract, journal, run_binding, verifier, signed_document, *, evm_verifier=None):
        self.contract = validate_contract(contract)
        need(type(journal) is LiveJournal and type(verifier) is OfflineApprovalVerifier, 'exact-live-journal-and-approval-verifier-required')
        self.journal, self.run_binding, self.verifier = journal, run_binding, verifier
        self.pin = digest(canonical(self.contract))
        need(digest(canonical(journal.contract)) == self.pin == run_binding.contract_pin, 'authority-contract-binding')
        document = parse_signed_document(signed_document)
        self.verification_time = None
        self.binding = ApprovalBinding(verifier, copy.deepcopy(document), BindingClock(self))
        self.evm = evm_verifier if evm_verifier is not None else EVMTransactionVerifier()
        need(type(self.evm) is EVMTransactionVerifier, 'exact-EVM-verifier-required')
        self.coordinator = None
        self.halted = self.halt_persistence_error = False
        self.last_time = None

    def attach_coordinator(self, coordinator):
        need(self.coordinator is None and coordinator.journal is self.journal and
             (coordinator.verification is self or getattr(coordinator.verification, 'delegate', None) is self), 'authority-coordinator-binding')
        self.coordinator = coordinator

    def halt(self):
        self.halted = self.run_binding.halted = True
        try:
            if self.coordinator is not None:
                self.coordinator.halt()
            else:
                self.journal.halt()
        except BaseException:
            self.halt_persistence_error = True

    def _run(self, action):
        with self.journal.mutex:
            try:
                return action()
            except BaseException:
                self.halt()
                raise

    def _validate(self, contract, tx, phase):
        c, b = self.coordinator, self.contract['binding']
        need(c is not None and not c.halted and not self.halted, 'authority-HALTED-or-unbound')
        need(digest(canonical(contract)) == self.pin == digest(canonical(self.contract)) ==
             digest(canonical(self.journal.contract)) == self.run_binding.contract_pin, 'authority-contract-changed')
        need(canonical(tx) in [canonical(t) for t in self.contract['envelopes']], 'unapproved-unsigned-envelope')
        now = c.clock()
        need(type(now) is int and b['notBefore'] <= now < b['expiresAt'] and
             (self.last_time is None or now >= self.last_time), 'authority-expired-or-clock-rollback')
        self.last_time = self.verification_time = now
        body = self.binding.document['body']
        need(self.binding.document_pin == b['approvalSHA256'] and self.binding.trust_pin == b['trustSHA256'] and
             self.verifier is self.binding.verifier and body['approvalId'] == b['approvalId'] and
             body['notBefore'] == b['notBefore'] and body['expiresAt'] == b['expiresAt'], 'authority-anchors-or-window-mismatch')
        expected = approval_scope(self.contract)
        # Canonical comparison supplements the legacy verifier's Python equality.
        need(canonical(body['manifest']) == canonical(expected), 'authority-exact-signed-scope')
        self.binding.validate_scope(expected, self.journal.path, b['approvalId'],
                                    {'externalApprovalSHA256': b['approvalSHA256'], 'externalTrustSHA256': b['trustSHA256']})
        state = self.journal.recover()
        need(not self.journal.payload['halted'], 'durable-authority-HALTED')
        key = tx['role'] + ':' + str(tx['nonce'])
        record = state['records'].get(key)
        if phase == 'before-sign':
            need(record is None and len(state['records']) < len(self.contract['envelopes']) and
                 canonical(tx) == canonical(self.contract['envelopes'][len(state['records'])]) and
                 all(r['state'] == 'CONFIRMED' for r in state['records'].values()), 'already-reserved-or-out-of-order')
        else:
            required = {'before-signer-dispatch': 'SIGN_REQUESTED', 'accept-signed-result': 'SIGN_REQUESTED', 'before-submit': 'SIGNED', 'before-wire': 'SUBMIT_INTENT'}
            need(phase in required and record is not None and record['state'] == required[phase] and
                 record['unsignedSHA256'] == digest(canonical(tx)), 'authority-journal-phase')
        role = tx['role']
        extra = tx['gasLimit'] * tx['maxFee'] if phase == 'before-sign' else 0
        m = self.contract['manifest']
        need(state['reserved'][role] + state['spent'][role] + extra <= m['roleBudgets'][role] and
             sum(state['reserved'].values()) + sum(state['spent'].values()) + extra <= m['totalBudget'], 'authority-budget-overrun')
        need(self.run_binding.verify() == {k: tx[k] for k in ('runId', 'chainId', 'genesisSHA256')}, 'authority-run-genesis-mismatch')
        return record

    def authorize(self, contract, envelope, phase):
        def action():
            record = self._validate(contract, envelope, phase)
            if phase in ('before-submit', 'before-wire'):
                projection = self.evm.verify(envelope, bytes.fromhex(record['rawTransactionHex'][2:]))
                need(projection['txHash'] == record['txHash'], 'stored-EVM-hash-mismatch')
            # Reject approval/trust/time/Run changes during verification itself.
            self._validate(contract, envelope, phase)
            return True
        return self._run(action)

    def verify_signed(self, envelope, raw):
        def action():
            self._validate(self.contract, envelope, 'accept-signed-result')
            self.evm.verify(envelope, raw)
            self._validate(self.contract, envelope, 'accept-signed-result')
            return True
        return self._run(action)

    def verify_receipt(self, contract, record, evidence):
        return self._run(lambda: need(False, 'live-chain-receipt-verifier-not-implemented'))

    def authorize_recovery(self, contract, snapshot, record, evidence, approval):
        return self._run(lambda: need(False, 'live-recovery-chain-verifier-not-implemented'))

    def status(self):
        halted = self.halted or self.journal.payload['halted'] or (self.coordinator is not None and self.coordinator.halted)
        return {'operationalState': 'HALTED' if halted else 'AUTHORITY_VERIFIER_ONLY',
                'haltPersistenceError': self.halt_persistence_error, 'executionEnabled': False,
                'official5.08': 'BLOCKED', 'mainnet': 'NO-GO'}
