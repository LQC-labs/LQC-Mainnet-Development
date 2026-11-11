"""One gated send attempt -> bound observation -> durable evidence settlement.

No key provider, node lifecycle or automatic retries. Constructors default to
disabled. Tests use public synthetic bytes and fake sockets, never live RPC.
"""
import copy
from contextlib import contextmanager
from lqc_live508.execution_reuse import (need, canonical, digest, LoopbackTransport, READS,
    RPCBoundVerification, approval_scope, parse_signed_document, LiveAuthorityBinding)
from lqc_live508.live_signer import LiveSigner
from lqc_live508.live_evidence import EvidenceRPC, LiveEvidence


class _ExecutionCapability:
    """Opaque identity only. Fields supplied by a caller never grant authority.

    Python introspection is NOT an isolation boundary; see SECURITY.md.
    """
    __slots__ = ()
    def __new__(cls, *args, **kwargs):
        raise TypeError('capabilities are issued only by the verified execution path')


class SubmissionTransport(LoopbackTransport):
    """All write entrances require a registered, snapshot-bound capability."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__path = None
        self.__registry = {}
        self.__active = None
    def _allowed_methods(self):
        return READS | {'eth_call', 'eth_getTransactionByHash', 'eth_sendRawTransaction'}
    def _deny(self, reason):
        self.halted = True
        self.__registry.clear()
        self.__active = None
        if self.__path is not None:
            self.__path.rpc._halt()
        need(False, reason)
    def _bind_execution(self, path):
        if self.__path is not None or type(path) is not LivePath or path.rpc.transport is not self:
            self._deny('transport-execution-rebind')
        path._wiring(require_enabled=False)
        self.__path = path
    def _snapshot(self, rpc, record):
        path = self.__path
        need(path is not None and path.rpc is rpc and rpc.transport is self, 'capability-execution-binding')
        path._wiring()
        need(not self.halted and self.enabled and not rpc.halted, 'transport-HALTED')
        c = path.coordinator
        key = record['envelope']['role'] + ':' + str(record['envelope']['nonce'])
        state = c.journal.recover()
        need(not c.halted and not c.journal.payload['halted'], 'capability-HALTED')
        need(not c.journal.restored and state['records'].get(key) == record and record['state'] == 'SUBMIT_INTENT', 'capability-durable-intent')
        c._check(record['envelope'], 'before-wire')
        after = c.journal.recover()
        need(after == state, 'capability-journal-changed-during-validation')
        binding = c.journal.contract['binding']
        return {'txHash': record['txHash'], 'rawSHA256': record['rawSHA256'],
                'approvalSHA256': binding['approvalSHA256'], 'trustSHA256': binding['trustSHA256'],
                'runEvidenceSHA256': binding['runEvidenceSHA256'],
                'runIdentity': rpc.binding.verify(), 'runSpecSHA256': digest(canonical(rpc.binding.spec)),
                'contractSHA256': c.contract_pin, 'journalPath': str(c.journal.path),
                'generation': c.journal.payload['generation'], 'snapshotSHA256': after['snapshotSHA256']}
    def _issue_for(self, rpc, record):
        try:
            need(self.__path is not None, 'unbound-capability-issuer')
            with self.__path.coordinator.journal.mutex:
                need(not self.__registry and self.__active is None, 'capability-already-issued')
                snapshot = self._snapshot(rpc, record)
                key = (snapshot['contractSHA256'], record['envelope']['role'], record['envelope']['nonce'])
                need(key not in rpc._capability_issued, 'intent-capability-already-consumed')
                # Keep this history on the bound RPC, not just the transport.
                # Replacing a transport cannot mint another permit for this intent.
                rpc._capability_issued.add(key)
                cap = object.__new__(_ExecutionCapability)
                self.__registry[cap] = (rpc, copy.deepcopy(record), snapshot)
                return cap
        except BaseException:
            self._deny('capability-issue-denied')
    @contextmanager
    def authorize_once(self, *args, **kwargs):
        # Retained solely to fail closed for the old callback-based API.
        self._deny('caller-callbacks-cannot-authorize-transactions')
        yield
    def exchange(self, raw_request, *, deadline):
        from lqc_live508.shared.durable_journal import strict_json
        try:
            request = strict_json(raw_request)
            if request.get('method') == 'eth_sendRawTransaction':
                self._deny('direct-write-entry-forbidden')
            return super().exchange(raw_request, deadline=deadline)
        except BaseException:
            self._deny('transport-request-denied')
    def _validate_request(self, request):
        try:
            super()._validate_request(request)
            if request['method'] == 'eth_sendRawTransaction':
                need(self.__active is not None and self.__active in self.__registry, 'registered-capability-required')
                _, record, _ = self.__registry[self.__active]
                need(request['params'] == [record['rawTransactionHex']], 'capability-raw-mismatch')
        except BaseException:
            self._deny('transport-request-capability-denied')
    def _before_send(self, request):
        if request['method'] != 'eth_sendRawTransaction': return
        try:
            self._validate_request(request)
            rpc, record, pinned = self.__registry.pop(self.__active)  # consume BEFORE validation/send
            self.__active = None
            need(self._snapshot(rpc, record) == pinned, 'capability-binding-changed')
        except BaseException:
            self._deny('capability-wire-validation-failed')
    def _dispatch(self, raw_request, *, deadline, capability):
        try:
            need(self.__path is not None, 'unbound-capability-dispatch')
            # Preserve the same outer lock order as RPC/coordinator. Concurrent
            # supported API calls cannot double issue or dispatch a capability.
            with self.__path.coordinator.journal.mutex:
                need(type(capability) is _ExecutionCapability and capability in self.__registry and self.__active is None,
                     'unknown-reused-or-foreign-capability')
                self.__active = capability
                try:
                    return super().exchange(raw_request, deadline=deadline)
                finally:
                    self.__registry.clear()
                    self.__active = None
        except BaseException:
            self._deny('capability-dispatch-failed')


class ExecutionVerification(RPCBoundVerification):
    def __init__(self, rpc, authority, collector):
        super().__init__(rpc, authority)
        need(collector.rpc is rpc and collector.policy is rpc.policy and collector.evm is authority.evm, 'evidence-verification-binding')
        self.collector = collector
        self.recovery_ticket = None
    def verify_receipt(self, contract, record, evidence):
        need(digest(canonical(contract)) == self.rpc.pin, 'receipt-contract-changed')
        return self.collector.verify(record, evidence)
    def check_recovery_approval(self, contract, snapshot, evidence, approval):
        a = self.delegate
        need(digest(canonical(contract)) == a.pin and a.verifier.trust.pin == contract['binding']['trustSHA256'], 'recovery-contract-trust')
        a.verifier.verify(approval, approval_scope(contract), a.coordinator.clock(), purpose='MANUAL_RECOVERY')
        recovery = approval['body']['recovery']
        need(recovery == {'journalSHA256': snapshot, 'chainEvidenceSHA256': digest(canonical(evidence)), 'noResubmission': True}, 'recovery-exact-snapshot-evidence')
        return True
    def authorize_recovery(self, contract, snapshot, record, evidence, approval):
        self.check_recovery_approval(contract, snapshot, evidence, approval)
        need(self.recovery_ticket == (snapshot, record['txHash'], digest(canonical(evidence)), digest(canonical(approval))), 'independent-recovery-observation-required')
        self.collector.verify(record, evidence)
        self.recovery_ticket = None
        return True


class LivePath:
    def __init__(self, signer, rpc, collector, *, enabled=False):
        self.signer, self.rpc, self.collector = signer, rpc, collector
        self.coordinator, self.authority = signer.coordinator, signer.authority
        self.enabled = enabled is True
        self.attempted = set()
        self.cost_persistence_error = False
        self._wiring(require_enabled=False)
        self.rpc.transport._bind_execution(self)
    def _wiring(self, *, require_enabled=True):
        c = self.coordinator
        need(not require_enabled or self.enabled, 'path-default-disabled')
        need(type(self.signer) is LiveSigner and type(self.authority) is LiveAuthorityBinding and
             type(self.rpc) is EvidenceRPC and type(self.rpc.transport) is SubmissionTransport and
             type(c.verification) is ExecutionVerification and c.verification.collector is self.collector and
             c.verification.delegate is self.authority and c.verification.rpc is self.rpc and
             self.collector.rpc is self.rpc and self.rpc.coordinator is c and self.authority.coordinator is c and
             self.authority.run_binding is self.rpc.binding, 'path-components-rebound')
        self.collector.policy.check()
    def _fail(self, key):
        self.coordinator.halted = True
        try:
            state = self.coordinator.journal.recover()
            record = state['records'].get(key)
            candidate = self.collector.last_cost
            if record and record['state'] in ('SUBMITTED', 'UNCERTAIN') and record['receipt'] is None and candidate is not None:
                proof = candidate['evidence']
                summary = self.collector._cost_and_chain(record, proof['transaction'], proof['receipt'], proof['blocks'])
                need(summary == candidate['summary'], 'cost-candidate-changed')
                self.coordinator.journal.advance(key, 'UNCERTAIN', receipt=summary, evidence=proof)
        except BaseException:
            self.cost_persistence_error = True
        self.authority.halt()
        self.rpc._halt()
    def execute(self, envelope):
        """Optional full entry: uses only the explicitly configured signer port."""
        try:
            self._wiring()
            signed = self.signer.sign_operation(envelope)
            return self.submit_signed(signed['journalKey'])
        except BaseException:
            self._fail(None)
            raise
    def submit_signed(self, key):
        c = self.coordinator
        with c.journal.mutex:
            self.collector.last_cost = None
            try:
                self._wiring()
                record = c.journal.recover()['records'][key]
                need(record['state'] == 'SIGNED' and key not in self.attempted, 'no-automatic-resubmission')
                packet = self.signer.prepare_submission(key)
                record = c.journal.recover()['records'][key]
                need(record['state'] == 'SUBMIT_INTENT' and packet['txHash'] == record['txHash'] and
                     packet['rawTransactionHex'] == record['rawTransactionHex'], 'durable-submit-packet-link')
                self.attempted.add(key)
                def revalidate():
                    self._wiring()
                    current = c.journal.recover()['records'][key]
                    need(current == record, 'submission-record-changed')
                    return True
                revalidate()
                c._check(record['envelope'], 'before-wire')  # before connection
                revalidate()  # RPC repeats authorization immediately before sendall
                returned_hash = self.rpc.send_once(record)
                need(returned_hash == record['txHash'], 'RPC-submission-hash-mismatch')
                c.record_submitted(key, returned_hash)
                record = c.journal.recover()['records'][key]
                evidence = self.collector.collect(record)
                c.record_receipt(key, evidence)
                result = c.journal.recover()['records'][key]
                need(result['state'] in ('CONFIRMED', 'REVERTED') and result['evidenceSHA256'] == digest(canonical(evidence)) and
                     result['receipt']['transactionHash'] == record['txHash'], 'journal-evidence-confirmation-link')
                if result['state'] == 'REVERTED': self.authority.halt(); self.rpc._halt()
                return self.result(key)
            except BaseException:
                self._fail(key)
                raise
    def reconcile(self, key, candidate, signed_recovery_bytes, recovery_rpc):
        """Explicit read-only recovery; independently recollect then settle only.

        Caller supplies a fresh approved reader; original halted transport is
        never reset. A recovery signature must bind the exact candidate digest.
        """
        c = self.coordinator
        with c.journal.mutex:
            try:
                self._wiring()
                state = c.journal.recover(); record = state['records'][key]
                need(c.halted and record['state'] == 'UNCERTAIN' and record['txHash'] is not None, 'recovery-state')
                approval = parse_signed_document(signed_recovery_bytes)
                c.verification.check_recovery_approval(c.journal.contract, state['snapshotSHA256'], candidate, approval)
                need(type(recovery_rpc) is EvidenceRPC and recovery_rpc is not self.rpc and recovery_rpc.coordinator is None and
                     recovery_rpc.policy is self.collector.policy and recovery_rpc.counter == 0 and
                     recovery_rpc.binding.contract_pin == self.rpc.binding.contract_pin and
                     canonical(recovery_rpc.binding.spec) == canonical(self.rpc.binding.spec), 'fresh-bound-recovery-reader-required')
                fresh_collector = LiveEvidence(recovery_rpc, self.collector.policy, self.authority.evm, sleeper=self.collector.sleeper)
                fresh = fresh_collector.collect(record)
                need(canonical(fresh) == canonical(candidate), 'independent-recovery-evidence-mismatch')
                c.verification.check_recovery_approval(c.journal.contract, state['snapshotSHA256'], candidate, approval)
                self.collector.tickets.add(digest(canonical(fresh)))
                c.verification.recovery_ticket = (state['snapshotSHA256'], record['txHash'], digest(canonical(fresh)), digest(canonical(approval)))
                c.reconcile(key, fresh, approval)
                need(c.halted and c.journal.payload['halted'], 'recovery-must-remain-HALTED')
                return self.result(key)
            except BaseException:
                self._fail(key)
                raise
    def result(self, key):
        state = self.coordinator.status(); record = state['records'][key]
        return {'transactionState': record['state'], 'txHash': record['txHash'], 'evidenceSHA256': record['evidenceSHA256'],
                'journalSnapshotSHA256': state['snapshotSHA256'], 'reservedAtest': record['reservedAtest'],
                'spentAtest': record['spentAtest'], 'operationalState': state['operationalState'],
                'costPersistenceError': self.cost_persistence_error, 'executionEnabled': False,
                'official5.08': 'BLOCKED', 'mainnet': 'NO-GO'}
