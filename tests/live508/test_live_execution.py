from lqc_live508.node_runtime import node_executable, codec_path, codec_env
"""Synthetic public r=s=1 transactions, fake HTTP sockets, no signing/network."""
import copy
from functools import lru_cache
import json
import subprocess
import unittest
from unittest.mock import patch
from lqc_live508.execution_reuse import WORKSPACE, canonical, digest, Denied
from lqc_live508.live_evidence import EvidencePolicy, EvidenceRPC, LiveEvidence, EvidenceCodec
from lqc_live508.live_path import SubmissionTransport, ExecutionVerification, LivePath
import tests.live508.test_live_authority_signer as old
from lqc_live508.live_journal import LiveJournal
from lqc_live508.live_coordinator import LiveCoordinator
from lqc_live508.live_authority_binding import LiveAuthorityBinding
from lqc_live508.live_signer import LiveSigner
from lqc_live508.run_binding import RunBinding
from tests.live508.test_live_rpc import ObserverDouble

BLOCK = '0x' + 'ab' * 32
SECOND = '0x' + '55' * 20
OWNER = '0x' + '33' * 20
CODEC = EvidenceCodec()

@lru_cache(maxsize=8)
def local_keccak(raw):
    result = subprocess.run([node_executable(), str(WORKSPACE / 'lqc_live508/codecs/transaction_hash.cjs')], input=raw, capture_output=True, check=True)
    return result.stdout.decode()


def make_policy(cfg):
    tx = copy.deepcopy(cfg['envelopes'][0]); tx.update(gasLimit=100000, **{'from': old.VECTOR['sender']})
    encoded = old.rlp([bytes.fromhex(tx['from'][2:]), b''])
    target = '0x' + local_keccak(encoded)[-40:]
    abi = ['constructor()', 'function owner() view returns (address)', 'event OwnerSet(address indexed owner)']
    template = '0x60016002' + '00' * 32 + '60036004'
    artifact = {'abi': abi, 'abiSHA256': digest(canonical(abi)), 'bytecode': '0x6000',
        'creationSHA256': digest(bytes.fromhex('6000')), 'deployedBytecode': template,
        'runtimeTemplateSHA256': digest(bytes.fromhex(template[2:])), 'immutableReferences': {'1': [{'start': 4, 'length': 32}]},
        'compilerSHA256': 'a' * 64, 'sourceHashes': {'SYNTHETIC.sol': 'b' * 64}}
    aid = digest(canonical(artifact))
    contracts = [{'address': a, 'artifactId': aid, 'getters': [{'name': 'owner', 'function': 'owner', 'args': [], 'expected': [OWNER], 'gas': 50000}],
                  'immutableGetters': {'1': 'owner'}, 'events': [{'signature': 'OwnerSet(address)', 'args': [OWNER]}]} for a in (target, SECOND)]
    return {'schema': 'LQC_EVIDENCE_POLICY_V1', 'confirmations': 1, 'pollLimit': 2, 'pollIntervalMs': 1,
            'artifacts': {aid: artifact}, 'operations': {'Asset18': {'kind': 'CREATE', 'target': target, 'constructorArgs': [], 'call': None, 'contracts': contracts}}}


class FakeSocket:
    def __init__(self, h): self.h = h; self.buffer = b''
    def settimeout(self, value): pass
    def connect(self, target):
        self.target = target
        if getattr(self.h.transport, '_SubmissionTransport__active', None) is not None and self.h.connect_hook: self.h.connect_hook()
    def getpeername(self): return self.target
    def sendall(self, wire):
        request = json.loads(wire.split(b'\r\n\r\n', 1)[1]); self.h.requests.append(request)
        value = self.h.reply(request)
        body = canonical({'jsonrpc': '2.0', 'id': request['id'], 'result': value})
        self.buffer = b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body
    def recv(self, n): value, self.buffer = self.buffer[:n], self.buffer[n:]; return value
    def close(self): pass


class Harness(old.Harness):
    def __init__(self, policy_change=None, call=False):
        original = old.contract
        def configured(root):
            cfg = original(root); self.policy_document = make_policy(cfg)
            if policy_change: policy_change(self.policy_document)
            cfg['binding']['evidencePolicySHA256'] = digest(canonical(self.policy_document))
            return cfg
        def configure_call(trust):
            if not call: return
            data = local_keccak(b'setCore(address)')[:10] + '00' * 12 + OWNER[2:]
            self.call_raw = old.synthetic_raw(to=bytes.fromhex(SECOND[2:]), data=bytes.fromhex(data[2:]))
            recovered = old.EVM.decode(self.call_raw)
            tx = self.cfg['envelopes'][0]
            tx.update(operation='SetCore', role='owner', to=SECOND, data=data, **{'from': recovered['sender']})
            m = self.cfg['manifest']; m['roles']['owner'] = recovered['sender']
            entry = {k: tx[k] for k in ('operation', 'role', 'from', 'to', 'value', 'nonce', 'gasLimit', 'maxFee', 'maxPriority')}
            entry['dataSHA256'] = digest(bytes.fromhex(data[2:])); m['transactions'] = [entry]
            trust['keys']['RFC_FIXTURE_NOT_REAL_AUTHORITY']['operations'] = ['SetCore']
            a = next(iter(self.policy_document['artifacts'].values()))
            a['abi'].append('function setCore(address core)'); a['abiSHA256'] = digest(canonical(a['abi']))
            aid = digest(canonical(a)); self.policy_document['artifacts'] = {aid: a}
            op = self.policy_document['operations'].pop('Asset18')
            op.update(kind='CALL', target=SECOND, constructorArgs=None, call={'function':'setCore', 'args':[OWNER]})
            for c in op['contracts']: c['artifactId'] = aid
            self.policy_document['operations']['SetCore'] = op
            self.cfg['binding']['evidencePolicySHA256'] = digest(canonical(self.policy_document))
        with patch.object(old, 'contract', side_effect=configured): super().__init__(trust_change=configure_call)
        self.operation = self.cfg['envelopes'][0]['operation']
        self.key = self.cfg['envelopes'][0]['role'] + ':0'
        self.tx_hash = old.EVM.decode(self.call_raw)['txHash'] if call else old.VECTOR['txHash']
        if call:
            def synthetic_port(envelope, *, deadline):
                self.port.calls.append(copy.deepcopy(envelope)); return self.call_raw
            self.port.request_signature = synthetic_port
        self.policy = EvidencePolicy(self.cfg, self.policy_document, codec=CODEC)
        self.requests = []; self.sent = 0; self.hook = None; self.connect_hook = None
        self.transport = SubmissionTransport(self.binding.url, enabled=True, clock=self.monotonic, socket_factory=lambda *a: FakeSocket(self))
        self.rpc = EvidenceRPC(self.binding, self.policy, self.transport, enabled=True, clock=self.monotonic)
        self.collector = LiveEvidence(self.rpc, self.policy, old.EVM, sleeper=lambda _: None)
        self.c = LiveCoordinator(self.j, ExecutionVerification(self.rpc, self.authority, self.collector), lambda: self.now)
        self.authority.coordinator = None; self.authority.attach_coordinator(self.c); self.rpc.attach_coordinator(self.c)
        self.signer = LiveSigner(self.c, self.authority, self.port, enabled=True, clock=self.monotonic)
        self.path = LivePath(self.signer, self.rpc, self.collector, enabled=True)
        tx = self.cfg['envelopes'][0]; h = self.tx_hash
        self.tx = {'hash': h, 'from': tx['from'], 'to': tx['to'], 'input': tx['data'], 'chainId': hex(tx['chainId']), 'nonce': '0x0',
            'value': '0x0', 'gas': hex(tx['gasLimit']), 'maxFeePerGas': '0x5', 'maxPriorityFeePerGas': '0x1', 'type': '0x2',
            'blockHash': BLOCK, 'blockNumber': '0x1', 'transactionIndex': '0x0'}
        self.receipt = {'transactionHash': h, 'from': tx['from'], 'to': tx['to'], 'contractAddress': (None if call else self.policy_document['operations'][self.operation]['target']),
            'blockHash': BLOCK, 'blockNumber': '0x1', 'transactionIndex': '0x0', 'status': '0x1', 'gasUsed': hex(70000), 'effectiveGasPrice': '0x2', 'logs': []}
        for address, c in self.policy.prepared[self.operation]['contracts'].items():
            for event in c['events']:
                self.receipt['logs'].append({'address': address, 'topics': copy.deepcopy(event['topics']), 'data': event['data'], 'transactionHash': h,
                    'blockHash': BLOCK, 'blockNumber': '0x1', 'transactionIndex': '0x0', 'logIndex': hex(len(self.receipt['logs'])), 'removed': False})
        self.block = {'number': '0x1', 'hash': BLOCK, 'parentHash': '0x' + '00' * 32, 'baseFeePerGas': '0x1', 'gasLimit': hex(10000000), 'transactions': [h]}
        self.code = '0x60016002' + '00' * 12 + OWNER[2:] + '60036004'
    def reply(self, r):
        m, p = r['method'], r['params']
        if m == 'eth_sendRawTransaction':
            self.sent += 1
            assert self.j.recover()['records'][self.key]['state'] == 'SUBMIT_INTENT'
        if self.hook:
            override = self.hook(r)
            if override is not NotImplemented: return override
        if m == 'eth_chainId': return hex(917001)
        if m == 'eth_getBalance': return hex(1000000)
        if m == 'eth_getTransactionCount': return '0x0'
        if m == 'eth_sendRawTransaction': return self.tx_hash
        if m == 'eth_getTransactionByHash': return copy.deepcopy(self.tx)
        if m == 'eth_getTransactionReceipt': return copy.deepcopy(self.receipt)
        if m == 'eth_getBlockByNumber': return copy.deepcopy(self.block)
        if m == 'eth_getCode': return self.code
        if m == 'eth_call': return '0x' + '00' * 12 + OWNER[2:]
        raise AssertionError(m)
    def execute(self):
        with patch('lqc_live508.shared.offline_authority.verify_public_signature'): return self.path.execute(self.cfg['envelopes'][0])
    def record(self): return self.j.recover()['records'][self.key]


class ExecutionTests(unittest.TestCase):
    def setUp(self): self.h = Harness()
    def tearDown(self): self.h.close()
    def reject(self, *, sent=1, spent=0):
        with self.assertRaises(Exception): self.h.execute()
        self.assertEqual(self.h.sent, sent)
        self.assertEqual(self.h.c.status()['operationalState'], 'HALTED')
        record = self.h.record(); self.assertEqual(record['state'], 'UNCERTAIN')
        self.assertEqual(record['spentAtest'], spent)
        self.assertEqual(record['reservedAtest'] + record['spentAtest'], 500000)
        with patch('lqc_live508.shared.offline_authority.verify_public_signature'), self.assertRaises(Exception): self.h.path.submit_signed('deployer:0')
        self.assertEqual(self.h.sent, sent)
    def test_create_multicontract_runtime_getter_event_success(self):
        result = self.h.execute(); r = self.h.record()
        self.assertEqual(result['transactionState'], 'CONFIRMED'); self.assertEqual(self.h.sent, 1)
        self.assertEqual(r['spentAtest'], 140000); self.assertEqual(r['reservedAtest'], 0)
        self.assertEqual(r['evidenceSHA256'], digest(canonical(r['evidence'])))
        self.assertEqual(len(r['evidence']['projection']['emitters']), 2)
        self.assertEqual(result['official5.08'], 'BLOCKED'); self.assertEqual(result['mainnet'], 'NO-GO')
        for q in self.h.requests:
            if q['method'] in ('eth_call', 'eth_getCode'): self.assertEqual(q['params'][1], {'blockHash': BLOCK, 'requireCanonical': True})
    def test_returned_hash_mismatch(self):
        self.h.hook = lambda r: '0x' + 'ee' * 32 if r['method'] == 'eth_sendRawTransaction' else NotImplemented
        self.reject()
    def test_send_response_lost_no_retry(self):
        def hook(r):
            if r['method'] == 'eth_sendRawTransaction': raise TimeoutError('lost acknowledgement')
            return NotImplemented
        self.h.hook = hook; self.reject()
    def test_no_receipt_bounded_poll(self):
        self.h.hook = lambda r: None if r['method'] == 'eth_getTransactionReceipt' else NotImplemented
        self.reject(); self.assertEqual(sum(r['method'] == 'eth_getTransactionReceipt' for r in self.h.requests), 2)
    def test_revert_records_actual_cost_and_halts(self):
        self.h.receipt.update(status='0x0', contractAddress=None, logs=[])
        self.assertEqual(self.h.execute()['transactionState'], 'REVERTED')
        self.assertEqual(self.h.record()['spentAtest'], 140000); self.assertEqual(self.h.record()['reservedAtest'], 0)
        self.assertTrue(self.h.c.halted); self.assertFalse(any(r['method'] == 'eth_call' for r in self.h.requests))
    def test_unknown_emitter_keeps_observed_cost(self):
        self.h.receipt['logs'][0]['address'] = '0x' + '66' * 20; self.reject(spent=140000)
    def test_event_argument_mismatch(self):
        self.h.receipt['logs'][0]['topics'][1] = '0x' + '00' * 12 + '44' * 20; self.reject(spent=140000)
    def test_missing_second_emitter_event(self):
        self.h.receipt['logs'].pop(); self.reject(spent=140000)
    def test_getter_mismatch(self):
        self.h.hook = lambda r: '0x' + '00' * 32 if r['method'] == 'eth_call' else NotImplemented
        self.reject(spent=140000)
    def test_runtime_opcode_mismatch(self):
        self.h.code = self.h.code.replace('60016002', '60016005'); self.reject(spent=140000)
    def test_immutable_literal_mismatch_despite_correct_getter(self):
        self.h.code = self.h.code.replace(OWNER[2:], '44' * 20); self.reject(spent=140000)
    def test_code_read_transport_failure_preserves_cost(self):
        def hook(r):
            if r['method'] == 'eth_getCode': raise TimeoutError('synthetic read timeout')
            return NotImplemented
        self.h.hook = hook; self.reject(spent=140000)
    def test_queried_transaction_nonce_mismatch(self): self.h.tx['nonce'] = '0x1'; self.reject()
    def test_receipt_contract_address_mismatch(self): self.h.receipt['contractAddress'] = SECOND; self.reject()
    def test_block_transaction_inclusion_mismatch(self): self.h.block['transactions'] = []; self.reject()
    def test_effective_price_mismatch(self): self.h.receipt['effectiveGasPrice'] = '0x3'; self.reject()
    def test_log_duplicate_index(self): self.h.receipt['logs'][1]['logIndex'] = '0x0'; self.reject()
    def test_log_transaction_index_mismatch(self): self.h.receipt['logs'][1]['transactionIndex'] = '0x1'; self.reject()
    def test_anchor_changes_clear_cost(self):
        reads = [0]
        def hook(r):
            if r['method'] == 'eth_getTransactionReceipt':
                reads[0] += 1
                if reads[0] == 2:
                    changed = copy.deepcopy(self.h.receipt); changed['gasUsed'] = hex(70001); return changed
            return NotImplemented
        self.h.hook = hook; self.reject()
    def test_expiry_after_send_allows_read_only_evidence(self):
        def hook(r):
            if r['method'] == 'eth_getTransactionReceipt': self.h.now = 201
            return NotImplemented
        self.h.hook = hook; self.assertEqual(self.h.execute()['transactionState'], 'CONFIRMED')
    def test_expiry_at_connection_blocks_wire(self):
        self.h.connect_hook = lambda: setattr(self.h, 'now', 201); self.reject(sent=0)
    def test_genesis_change_at_connection_blocks_wire(self):
        self.h.connect_hook = lambda: self.h.observer.snapshot.update(genesisSHA256='0' * 64); self.reject(sent=0)
    def test_nonce_change_at_connection_blocks_wire(self):
        self.h.connect_hook = lambda: setattr(self.h, 'hook', lambda r: '0x1' if r['method'] == 'eth_getTransactionCount' else NotImplemented)
        self.reject(sent=0)
    def test_submit_intent_commit_failure_no_wire(self):
        store = self.h.j._store
        def failing(p):
            if any(r['state'] == 'SUBMIT_INTENT' for r in p['records'].values()): raise OSError('intent disk error')
            return store(p)
        with patch.object(self.h.j, '_store', side_effect=failing): self.reject(sent=0)
    def test_submitted_commit_failure_no_second_send(self):
        store = self.h.j._store
        def failing(p):
            if any(r['state'] == 'SUBMITTED' for r in p['records'].values()): raise OSError('ack disk error')
            return store(p)
        with patch.object(self.h.j, '_store', side_effect=failing): self.reject()
    def test_confirmation_commit_failure_cost_annotation(self):
        store = self.h.j._store
        def failing(p):
            if any(r['state'] == 'CONFIRMED' for r in p['records'].values()): raise OSError('evidence disk error')
            return store(p)
        with patch.object(self.h.j, '_store', side_effect=failing): self.reject(spent=140000)
    def test_restart_cost_and_nonce_reservations_retained(self):
        self.h.code = '0x6000'; self.reject(spent=140000)
        self.h.j.close(); self.h.j = LiveJournal(self.h.root / 'journal', self.h.cfg, self.h.root)
        c = LiveCoordinator(self.h.j); state = c.status()
        self.assertEqual(state['spent']['deployer'], 140000); self.assertEqual(state['reserved']['deployer'], 360000)
        self.assertEqual(state['records']['deployer:0']['state'], 'UNCERTAIN'); self.assertTrue(c.halted)
    def test_rpc_rejects_raw_not_equal_to_durable_intent(self):
        with patch('lqc_live508.shared.offline_authority.verify_public_signature'):
            signed = self.h.sign(); self.h.signer.prepare_submission(signed['journalKey'])
            forged = self.h.record(); forged['rawTransactionHex'] = '0x01'
            with self.assertRaises(Denied): self.h.rpc.send_once(forged)
        self.assertEqual(self.h.sent, 0)
    def test_revocation_at_connection_blocks_wire(self):
        self.h.connect_hook = lambda: self.h.verifier.trust.document['revokedKeyIds'].append('RFC_FIXTURE_NOT_REAL_AUTHORITY')
        self.reject(sent=0)
    def test_default_disabled_no_signer_or_socket(self):
        self.h.path.enabled = False
        with self.assertRaises(Denied): self.h.execute()
        self.assertEqual(self.h.requests, []); self.assertEqual(self.h.port.calls, [])
    def test_direct_raw_transport_without_grant_denied(self):
        with self.assertRaises(Denied): self.h.transport.exchange(canonical({'jsonrpc':'2.0','id':1,'method':'eth_sendRawTransaction','params':[old.VECTOR['rawTransactionHex']]}), deadline=5)
        self.assertEqual(self.h.sent, 0)
    def test_uncollected_evidence_cannot_confirm(self):
        self.h.execute(); r = self.h.record(); self.h.collector.tickets.clear()
        with self.assertRaises(Denied): self.h.collector.verify(r, r['evidence'])
    def test_policy_mutation_rejected_before_dispatch(self):
        self.h.policy.document['confirmations'] = 2
        with self.assertRaises(Denied): self.h.execute()
        self.assertFalse(self.h.port.calls)
    def test_prepared_query_mutation_rejected(self):
        next(iter(self.h.policy.prepared['Asset18']['contracts'].values()))['queries'][0]['data'] = '0x12345678'
        with self.assertRaises(Denied): self.h.execute()
        self.assertFalse(self.h.requests)

class AdditionalBoundaries(unittest.TestCase):
    def test_call_receipt_has_no_creation_address(self):
        h = Harness(call=True)
        try:
            result = h.execute(); r = h.record()
            self.assertEqual(result['transactionState'], 'CONFIRMED')
            self.assertIsNone(r['evidence']['receipt']['contractAddress'])
            self.assertEqual(r['envelope']['to'], SECOND)
            self.assertTrue(all(x['operationKind'] == 'CALL' for x in r['evidence']['projection']['emitters'].values()))
        finally: h.close()
    def test_call_creation_address_is_rejected(self):
        h = Harness(call=True)
        try:
            h.receipt['contractAddress'] = SECOND
            with self.assertRaises(Denied): h.execute()
            self.assertEqual(h.record()['state'], 'UNCERTAIN'); self.assertEqual(h.sent, 1)
        finally: h.close()
    def test_confirmation_parent_mismatch(self):
        h = Harness(policy_change=lambda p: p.update(confirmations=2))
        try:
            def hook(r):
                if r['method'] == 'eth_getBlockByNumber' and r['params'][0] == '0x2':
                    return {**h.block, 'number':'0x2', 'hash':'0x'+'cd'*32, 'parentHash':'0x'+'ef'*32, 'transactions':[]}
                return NotImplemented
            h.hook = hook
            with self.assertRaises(Denied): h.execute()
            self.assertEqual(h.record()['spentAtest'], 0)
        finally: h.close()
    def test_confirmation_missing_then_available(self):
        h = Harness(policy_change=lambda p: p.update(confirmations=2)); reads = [0]
        try:
            def hook(r):
                if r['method'] == 'eth_getBlockByNumber' and r['params'][0] == '0x2':
                    reads[0] += 1
                    if reads[0] == 1: return None
                    return {**h.block, 'number':'0x2', 'hash':'0x'+'cd'*32, 'parentHash':BLOCK, 'transactions':[]}
                return NotImplemented
            h.hook = hook
            self.assertEqual(h.execute()['transactionState'], 'CONFIRMED'); self.assertEqual(reads[0], 3)
        finally: h.close()
    def recovery_fixture(self):
        h = Harness(); captured = {}
        original = h.c.record_receipt
        def fail(key, evidence): captured['candidate'] = copy.deepcopy(evidence); raise OSError('crash before evidence commit')
        with patch.object(h.c, 'record_receipt', side_effect=fail), self.assertRaises(OSError): h.execute()
        approval = copy.deepcopy(h.signed)
        approval['body'].update(approvalId='f'*64, purpose='MANUAL_RECOVERY', recovery={
            'journalSHA256':h.j.recover()['snapshotSHA256'], 'chainEvidenceSHA256':digest(canonical(captured['candidate'])), 'noResubmission':True})
        binding = RunBinding(h.cfg, h.spec, ObserverDouble(h.spec))
        transport = SubmissionTransport(binding.url, enabled=True, clock=h.monotonic, socket_factory=lambda *a: FakeSocket(h))
        rpc = EvidenceRPC(binding, h.policy, transport, enabled=True, clock=h.monotonic)
        return h, captured['candidate'], approval, rpc
    def test_explicit_recovery_recollects_and_stays_halted(self):
        h, candidate, approval, rpc = self.recovery_fixture()
        try:
            with patch('lqc_live508.shared.offline_authority.verify_public_signature'):
                result = h.path.reconcile(h.key, candidate, canonical(approval), rpc)
            self.assertEqual(result['transactionState'], 'CONFIRMED'); self.assertEqual(result['operationalState'], 'HALTED')
            self.assertEqual(result['spentAtest'], 140000); self.assertEqual(result['reservedAtest'], 0)
            self.assertEqual(h.sent, 1); self.assertEqual(len(h.port.calls), 1)
            self.assertTrue(rpc.counter > 0); self.assertEqual(h.record()['recoveryAuthorizationSHA256'], digest(canonical(approval)))
        finally: h.close()
    def test_recovery_wrong_snapshot_sends_no_reads(self):
        h, candidate, approval, rpc = self.recovery_fixture()
        try:
            approval['body']['recovery']['journalSHA256'] = '0'*64
            with patch('lqc_live508.shared.offline_authority.verify_public_signature'), self.assertRaises(Denied): h.path.reconcile(h.key, candidate, canonical(approval), rpc)
            self.assertEqual(rpc.counter, 0); self.assertEqual(h.sent, 1)
        finally: h.close()
    def test_recovery_independent_observation_disagrees(self):
        h, candidate, approval, rpc = self.recovery_fixture()
        try:
            h.receipt['gasUsed'] = hex(70001)
            with patch('lqc_live508.shared.offline_authority.verify_public_signature'), self.assertRaises(Denied): h.path.reconcile(h.key, candidate, canonical(approval), rpc)
            self.assertEqual(h.record()['state'], 'UNCERTAIN'); self.assertEqual(h.record()['spentAtest'], 140000)
            self.assertEqual(h.sent, 1)
        finally: h.close()
    def test_cost_annotation_cannot_be_rewritten(self):
        h = Harness()
        try:
            h.code = '0x6000'
            with self.assertRaises(Exception): h.execute()
            r = h.record()
            with self.assertRaises(Denied): h.j.advance(h.key, 'UNCERTAIN', receipt=r['receipt'], evidence=r['evidence'])
            self.assertEqual(h.record()['spentAtest'], 140000)
        finally: h.close()

class ExistingArtifactTests(unittest.TestCase):
    def test_existing_testtoken_compiler_immutable_offsets(self):
        from types import SimpleNamespace
        artifact = json.loads((WORKSPACE / 'tests/live508/fixtures/LQCTestToken.json').read_text())
        raw = '0x' + (18).to_bytes(32, 'big').hex()
        actual = bytearray.fromhex(artifact['deployedBytecode'][2:])
        mapping = {}
        for identifier, refs in artifact['immutableReferences'].items():
            mapping[identifier] = 'decimals'
            for ref in refs: actual[ref['start']:ref['start'] + ref['length']] = bytes.fromhex(raw[2:])
        collector = object.__new__(LiveEvidence)
        collector.policy = SimpleNamespace(document={'artifacts': {'fixture': artifact}})
        c = {'artifactId':'fixture', 'immutableGetters':mapping}
        decoded = {'decimals':{'raw':raw, 'expected':'18', 'value':'18'}}
        collector._runtime(c, {'runtimeCode':'0x'+actual.hex()}, decoded)
        actual[0] ^= 1
        with self.assertRaises(Exception): collector._runtime(c, {'runtimeCode':'0x'+actual.hex()}, decoded)

if __name__ == '__main__': unittest.main(verbosity=2)
