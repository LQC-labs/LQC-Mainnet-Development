"""Persistence coordinator, not an execution backend. No signer/submit calls.

Preserves journal_backend's reserve -> sign-request -> submit-intent -> submitted
-> confirm boundaries, restoring leases and budgets from journal.recover().
The verification boundary defaults to denial. Test doubles are NOT approvals.
"""
import copy
import time
from lqc_live508.journal_reuse import need, canonical, digest
from lqc_live508.live_contracts import UnimplementedVerification


class LiveCoordinator:
    def __init__(self, journal, verification=None, clock=None):
        self.journal = journal
        self.verification = verification if verification is not None else UnimplementedVerification()
        self.clock = clock if clock is not None else lambda: int(time.time())
        self.last_time = None
        self.contract_pin = digest(canonical(journal.contract))
        recovered = journal.recover()
        self.halted = recovered['blocked']
        if self.halted:
            # Persist restart ambiguity; never automatically sign or send again.
            journal.halt()

    def _check(self, tx, phase):
        need(not self.halted and not self.journal.payload['halted'], 'HALTED-no-retry')
        need(digest(canonical(self.journal.contract)) == self.contract_pin, 'contract-changed')
        now = self.clock(); b = self.journal.contract['binding']
        need(type(now) is int and b['notBefore'] <= now < b['expiresAt'] and
             (self.last_time is None or now >= self.last_time), 'approval-expired-or-clock-rollback')
        self.last_time = now
        # Only a verifier that raises on failure can implement this interface.
        need(self.verification.authorize(copy.deepcopy(self.journal.contract), copy.deepcopy(tx), phase) is True,
             'authorization-not-verified')

    def _run(self, action):
        with self.journal.mutex:
            try:
                return action()
            except BaseException:
                self.halted = True
                try:
                    self.journal.halt()
                except BaseException:
                    # Poisoned disk remains blocked; do not mask the original error.
                    pass
                raise

    def begin(self, envelope):
        def action():
            tx = copy.deepcopy(envelope)
            self._check(tx, 'before-sign')
            self.journal.reserve(tx)
            key = tx['role'] + ':' + str(tx['nonce'])
            self.journal.advance(key, 'SIGN_REQUESTED')
            return key
        return self._run(action)

    def record_signed(self, key, raw_transaction):
        def action():
            r = self.journal.recover()['records'][key]
            self._check(r['envelope'], 'accept-signed-result')
            need(r['state'] == 'SIGN_REQUESTED', 'not-awaiting-signature')
            need(type(raw_transaction) is bytes, 'immutable-raw-bytes-required')
            need(self.verification.verify_signed(copy.deepcopy(r['envelope']), raw_transaction) is True,
                 'signed-envelope-not-verified')
            self.journal.advance(key, 'SIGNED', raw=raw_transaction)
            return self.journal.recover()['records'][key]['txHash']
        return self._run(action)

    def prepare_submission(self, key):
        """One-shot data handoff AFTER durable intent, not permission to broadcast.

        A future transport must revalidate at its boundary. This module never
        sends, retries, replaces, bumps fees, or invokes a signing operation.
        """
        def action():
            r = self.journal.recover()['records'][key]
            self._check(r['envelope'], 'before-submit')
            need(r['state'] == 'SIGNED', 'submission-already-consumed-or-unsigned')
            self.journal.advance(key, 'SUBMIT_INTENT')
            stored = self.journal.recover()['records'][key]
            return {'rawTransactionHex': stored['rawTransactionHex'], 'txHash': stored['txHash'],
                    'unsignedSHA256': stored['unsignedSHA256']}
        return self._run(action)

    def record_submitted(self, key, returned_hash):
        def action():
            r = self.journal.recover()['records'][key]
            need(not self.halted and r['state'] == 'SUBMIT_INTENT' and returned_hash == r['txHash'], 'submission-result-uncertain')
            self.journal.advance(key, 'SUBMITTED')
        return self._run(action)

    def _settle(self, key, evidence, recovery_sha=None):
        r = self.journal.recover()['records'][key]
        need(r['state'] == ('UNCERTAIN' if recovery_sha else 'SUBMITTED'), 'receipt-phase')
        # Returned normalized summary is still independently checked by Journal.
        summary = self.verification.verify_receipt(copy.deepcopy(self.journal.contract), copy.deepcopy(r), copy.deepcopy(evidence))
        need(type(summary) is dict and type(summary.get('status')) is int and summary['status'] in (0, 1), 'receipt-verification')
        self.journal.advance(key, 'CONFIRMED' if summary['status'] == 1 else 'REVERTED', receipt=summary,
                             evidence=evidence, recovery_sha=recovery_sha)
        if summary['status'] == 0:
            self.halted = True

    def record_receipt(self, key, evidence):
        def action():
            need(not self.halted, 'HALTED-recovery-required')
            self._settle(key, evidence)
        return self._run(action)

    def reconcile(self, key, evidence, recovery_approval):
        """Account for an already observed transaction; never unhalt or resubmit."""
        def action():
            state = self.journal.recover(); r = state['records'][key]
            need(self.halted and r['state'] == 'UNCERTAIN' and r['txHash'] is not None, 'recovery-evidence-required')
            need(self.verification.authorize_recovery(copy.deepcopy(self.journal.contract), state['snapshotSHA256'],
                 copy.deepcopy(r), copy.deepcopy(evidence), copy.deepcopy(recovery_approval)) is True, 'recovery-not-authorized')
            self._settle(key, evidence, digest(canonical(recovery_approval)))
        return self._run(action)

    def halt(self):
        self.halted = True
        self.journal.halt()

    def status(self):
        state = self.journal.recover()
        operational = 'HALTED' if self.halted or self.journal.payload['halted'] else (
            'LOCAL_JOURNAL_ACTIVE' if state['blocked'] else 'LOCAL_JOURNAL_READY')
        return {**state, 'operationalState': operational,
                'executionEnabled': False, 'official5.08': 'BLOCKED', 'mainnet': 'NO-GO'}
