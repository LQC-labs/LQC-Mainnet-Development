"""No signing or keys: fixed public scalar EVM vectors and explicit approval seam.

Positive structured approval tests patch ONLY the legacy Ed25519 verify call.
EVM transaction decoding/recovery is real unless a test injects a failure.
"""
import copy
import json
import pathlib
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from lqc_live508.authority_reuse import WORKSPACE, canonical, digest, Denied, TrustConfig, OfflineApprovalVerifier
from lqc_live508.live_authority_binding import LiveAuthorityBinding, approval_scope
from lqc_live508.live_signer import EVMTransactionVerifier, LiveSigner, UnavailableSigner
from lqc_live508.live_journal import LiveJournal
from lqc_live508.live_coordinator import LiveCoordinator
from lqc_live508.live_rpc import LiveRPC, RPCBoundVerification
from lqc_live508.run_binding import RunBinding
from tests.live508.test_live_journal import contract
from tests.live508.test_live_rpc import make_spec, ObserverDouble, TransportDouble, Clock

ROOT = pathlib.Path(__file__).resolve().parent / 'fixtures'
VECTOR = json.loads((ROOT / 'SYNTHETIC-EVM-VECTOR.json').read_text())
RAW = bytes.fromhex(VECTOR['rawTransactionHex'][2:])
RFC = json.loads((WORKSPACE / 'tests/live508/fixtures/RFC8032-PUBLIC-VECTORS.json').read_text())['vectors'][1]
EVM = EVMTransactionVerifier()


class RecordingSignerDouble:
    """Returns existing synthetic bytes; does not request or compute a signature."""
    def __init__(self, harness):
        self.h = harness; self.calls = []; self.callback = None; self.raw = RAW
    def request_signature(self, envelope, *, deadline):
        self.calls.append({'envelope': copy.deepcopy(envelope), 'deadline': deadline,
                           'durableState': self.h.j.recover()['records']['deployer:0']['state']})
        if self.callback: self.callback(envelope)
        return self.raw


class Harness:
    def __init__(self, trust_change=None, document_change=None):
        self.tmp = tempfile.TemporaryDirectory(prefix='lqc-live-authority-test-')
        self.root = pathlib.Path(self.tmp.name)
        self.cfg = contract(self.root)
        self.cfg['envelopes'] = self.cfg['envelopes'][:1]
        tx = self.cfg['envelopes'][0]
        tx.update(gasLimit=100000, **{'from': VECTOR['sender']})
        m = self.cfg['manifest']; m['roles']['deployer'] = VECTOR['sender']
        m['roleBudgets'] = dict.fromkeys(m['roles'], 1000000); m['totalBudget'] = 1000000
        entry = {k: tx[k] for k in ('operation', 'role', 'from', 'to', 'value', 'nonce', 'gasLimit', 'maxFee', 'maxPriority')}
        entry['dataSHA256'] = digest(bytes.fromhex(tx['data'][2:])); m['transactions'] = [entry]
        self.cfg['binding']['expiresAt'] = 200
        self.spec = make_spec(self.cfg)
        self.cfg['binding']['runEvidenceSHA256'] = digest(canonical(self.spec))
        self.trust_document = {'schema': 1, 'status': 'PINNED_EXTERNAL_IDENTITY_ASSERTIONS', 'revision': 1,
            'validFrom': 0, 'validUntil': 1000, 'revokedApprovalIds': [], 'revokedKeyIds': [],
            'journalBindings': {m['runId']: {'genesisSHA256': m['genesisSHA256'], 'approvalId': self.cfg['binding']['approvalId'],
                                          'pathSHA256': self.cfg['binding']['journalPathSHA256']}},
            'keys': {'RFC_FIXTURE_NOT_REAL_AUTHORITY': {'issuerId': 'SYNTHETIC_AUTHORITY',
                'publicKeyHex': RFC['publicKeyHex'], 'identityStatus': 'VERIFIED_BY_PINNED_EXTERNAL_EVIDENCE',
                'authorityStatus': 'VERIFIED_BY_PINNED_EXTERNAL_EVIDENCE', 'identityEvidenceSHA256': 'a' * 64,
                'authorityEvidenceSHA256': 'b' * 64, 'notBefore': 0, 'expiresAt': 1000,
                'purposes': ['DEPLOYMENT', 'MANUAL_RECOVERY'], 'chainIds': [917001],
                'roles': ['deployer', 'owner', 'guardian'], 'operations': ['Asset18'],
                'maximumTotalBudgetAtest': 1000000,
                'maximumRoleBudgetAtest': dict.fromkeys(m['roles'], 1000000)}}}
        if trust_change: trust_change(self.trust_document)
        self.cfg['binding']['trustSHA256'] = digest(canonical(self.trust_document))
        self.signed = {'body': {'schema': 'LQC_APPROVAL_V1', 'approvalId': self.cfg['binding']['approvalId'],
            'issuerId': 'SYNTHETIC_AUTHORITY', 'purpose': 'DEPLOYMENT', 'issuedAt': 90,
            'notBefore': 100, 'expiresAt': 200, 'manifest': approval_scope(self.cfg), 'recovery': None},
            'signature': {'algorithm': 'Ed25519', 'keyId': 'RFC_FIXTURE_NOT_REAL_AUTHORITY', 'signatureHex': RFC['signatureHex']}}
        if document_change: document_change(self.signed)
        self.cfg['binding']['approvalSHA256'] = digest(canonical(self.signed))
        self.now = 101; self.monotonic = Clock()
        self.observer = ObserverDouble(self.spec)
        self.binding = RunBinding(self.cfg, self.spec, self.observer)
        self.transport = TransportDouble(self.binding.url)
        self.rpc = LiveRPC(self.binding, self.transport, enabled=True, clock=self.monotonic)
        self.j = LiveJournal(self.root / 'journal', self.cfg, self.root, create=True)
        self.verifier = OfflineApprovalVerifier(TrustConfig(self.trust_document, self.cfg['binding']['trustSHA256']))
        self.authority = LiveAuthorityBinding(self.cfg, self.j, self.binding, self.verifier, canonical(self.signed), evm_verifier=EVM)
        self.c = LiveCoordinator(self.j, RPCBoundVerification(self.rpc, self.authority), lambda: self.now)
        self.authority.attach_coordinator(self.c); self.rpc.attach_coordinator(self.c)
        self.port = RecordingSignerDouble(self)
        self.signer = LiveSigner(self.c, self.authority, self.port, enabled=True, clock=self.monotonic)
    def close(self): self.j.close(); self.tmp.cleanup()
    def sign(self): return self.signer.sign_operation(self.cfg['envelopes'][0])


def rlp(item):
    """Small test-only serializer for synthetic public scalar vectors; no crypto."""
    if isinstance(item, list):
        data, base = b''.join(rlp(x) for x in item), 0xc0
    else:
        data, base = item, 0x80
        if len(data) == 1 and data[0] < 0x80: return data
    if len(data) < 56: return bytes([base + len(data)]) + data
    size = len(data).to_bytes((len(data).bit_length() + 7) // 8, 'big')
    return bytes([base + 55 + len(size)]) + size + data


def synthetic_raw(**changes):
    fields = [bytes.fromhex('0dfe09'), b'', b'\x01', b'\x05', bytes.fromhex('0186a0'), b'', b'', bytes.fromhex('6000'), [], b'', b'\x01', b'\x01']
    names = ['chainId', 'nonce', 'priority', 'fee', 'gas', 'to', 'value', 'data', 'accessList', 'parity', 'r', 's']
    for key, value in changes.items(): fields[names.index(key)] = value
    return b'\x02' + rlp(fields)


class EVMTests(unittest.TestCase):
    def envelope(self):
        return {'scope': 'DEVNET_TRANSACTION_V1', 'chainId': 917001, 'nonce': 0, 'from': VECTOR['sender'],
                'to': None, 'value': 0, 'data': '0x6000', 'gasLimit': 100000, 'maxFee': 5, 'maxPriority': 1}
    def test_fixed_vector_recovery_unmocked(self):
        self.assertEqual(synthetic_raw(), RAW)
        result = EVM.verify(self.envelope(), RAW)
        self.assertEqual(result['sender'], VECTOR['sender'])
        self.assertEqual(result['txHash'], VECTOR['txHash'])
        self.assertEqual(result['evmSigningHash'], VECTOR['evmSigningHash'])
    def test_all_approved_fields_compared(self):
        mutations = {'from': '0x' + '9' * 40, 'chainId': 97, 'nonce': 1, 'to': '0x' + '2' * 40,
                     'value': 1, 'data': '0x6001', 'gasLimit': 100001, 'maxFee': 6, 'maxPriority': 2}
        for key, value in mutations.items():
            tx = self.envelope(); tx[key] = value
            with self.subTest(field=key), self.assertRaises(Denied): EVM.verify(tx, RAW)
    def test_boolean_numeric_fields_rejected(self):
        for key in ('chainId', 'nonce', 'value', 'gasLimit', 'maxFee', 'maxPriority'):
            tx = self.envelope(); tx[key] = False
            with self.subTest(field=key), self.assertRaises(Denied): EVM.verify(tx, RAW)
    def test_bad_signature_scalars_or_parity(self):
        order = int('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 16)
        for changes in ({'r': b''}, {'s': b''}, {'s': (order - 1).to_bytes(32, 'big')}, {'parity': b'\x02'}):
            with self.subTest(changes=list(changes)), self.assertRaises(Denied): EVM.decode(synthetic_raw(**changes))
    def test_unapproved_access_list(self):
        raw = synthetic_raw(accessList=[[bytes.fromhex('22' * 20), []]])
        with self.assertRaises(Denied): EVM.decode(raw)
    def test_unsigned_transaction_rejected(self):
        fields = [bytes.fromhex('0dfe09'), b'', b'\x01', b'\x05', bytes.fromhex('0186a0'), b'', b'', bytes.fromhex('6000'), []]
        with self.assertRaises(Denied): EVM.decode(b'\x02' + rlp(fields))
    def test_legacy_and_unknown_type_rejected(self):
        legacy = rlp([b'', b'\x05', bytes.fromhex('0186a0'), b'', b'', bytes.fromhex('6000'), b'\x1b', b'\x01', b'\x01'])
        for raw in (legacy, b'\x7f' + RAW[1:]):
            with self.subTest(type=raw[0]), self.assertRaises(Denied): EVM.decode(raw)
    def test_noncanonical_integer_and_trailing_bytes(self):
        for raw in (synthetic_raw(nonce=b'\x00'), RAW + b'\x00'):
            with self.assertRaises(Denied): EVM.decode(raw)
    def test_modified_payload_does_not_match_original_sender(self):
        with self.assertRaises(Denied): EVM.verify(self.envelope(), synthetic_raw(data=b'\x60\x01'))
    def test_synthetic_call_decodes_target_and_recovers_sender(self):
        raw = synthetic_raw(to=bytes.fromhex('22' * 20))
        result = EVM.decode(raw)
        tx = self.envelope(); tx.update(to='0x' + '22' * 20, **{'from': result['sender']})
        self.assertEqual(EVM.verify(tx, raw)['to'], tx['to'])
    def test_cache_return_is_defensive_copy(self):
        result = EVM.decode(RAW); result['sender'] = 'changed'
        self.assertEqual(EVM.decode(RAW)['sender'], VECTOR['sender'])
    def test_oversized_and_mutable_bytes_rejected(self):
        for value in (bytearray(RAW), b'', b'x' * 131001, '0x00'):
            with self.assertRaises(Denied): EVM.decode(value)


class AuthoritySignerTests(unittest.TestCase):
    def setUp(self): self.h = Harness()
    def tearDown(self): self.h.close()
    def policy(self): return patch('lqc_live508.shared.offline_authority.verify_public_signature')
    def test_real_ed25519_rejects_rfc_signature_for_new_json(self):
        with self.assertRaisesRegex(Denied, 'signature-invalid'): self.h.sign()
        self.assertFalse(self.h.port.calls)
        self.assertFalse(self.h.transport.requests)
        self.assertEqual(self.h.c.status()['operationalState'], 'HALTED')
    def test_normal_signer_double_to_durable_signed_and_intent(self):
        with self.policy():
            signed = self.h.sign()
            record = self.h.j.recover()['records'][signed['journalKey']]
            self.assertEqual(record['state'], 'SIGNED')
            self.assertEqual(record['txHash'], VECTOR['txHash'])
            self.assertNotEqual(record['unsignedSHA256'], record['txHash'][2:])
            packet = self.h.signer.prepare_submission(signed['journalKey'])
        self.assertEqual(packet['txHash'], VECTOR['txHash'])
        self.assertEqual(self.h.j.recover()['records'][signed['journalKey']]['state'], 'SUBMIT_INTENT')
        self.assertEqual(len(self.h.port.calls), 1)
        self.assertEqual(self.h.port.calls[0]['durableState'], 'SIGN_REQUESTED')
        self.assertEqual(self.h.port.calls[0]['envelope'], self.h.cfg['envelopes'][0])
    def test_signed_ed25519_scope_contains_live_binding(self):
        with self.policy() as verify:
            self.h.c.begin(self.h.cfg['envelopes'][0])
        from lqc_live508.shared.offline_authority import DOMAIN
        self.assertEqual(verify.call_args.args[1], DOMAIN + canonical(self.h.signed['body']))
        binding = self.h.signed['body']['manifest']['liveBinding']
        self.assertEqual(binding['runEvidenceSHA256'], self.h.cfg['binding']['runEvidenceSHA256'])
        self.assertEqual(binding['transactionType'], 2)
    def test_default_disabled_signer_never_calls_port(self):
        self.h.signer.enabled = False
        with self.policy(), self.assertRaises(Denied): self.h.sign()
        self.assertFalse(self.h.port.calls)
    def test_missing_production_signer_denies_and_preserves_lease(self):
        self.h.signer.port = UnavailableSigner()
        with self.policy(), self.assertRaises(Denied): self.h.sign()
        state = self.h.c.status()
        self.assertEqual(state['records']['deployer:0']['state'], 'UNCERTAIN')
        self.assertEqual(state['reserved']['deployer'], 500000)
    def test_unapproved_envelope_never_reaches_port(self):
        tx = copy.deepcopy(self.h.cfg['envelopes'][0]); tx['data'] = '0x6001'
        with self.policy(), self.assertRaises(Denied): self.h.signer.sign_operation(tx)
        self.assertFalse(self.h.port.calls)
    def test_approval_expired_before_sign(self):
        self.h.now = 200
        with self.policy(), self.assertRaises(Denied): self.h.sign()
        self.assertFalse(self.h.port.calls)
    def test_approval_expires_in_signer_port(self):
        self.h.port.callback = lambda _: setattr(self.h, 'now', 200)
        with self.policy(), self.assertRaises(Denied): self.h.sign()
        self.assertEqual(self.h.c.status()['records']['deployer:0']['state'], 'UNCERTAIN')
        self.assertIsNone(self.h.c.status()['records']['deployer:0']['txHash'])
    def test_changed_trust_during_rpc_preflight_stops_dispatch(self):
        self.h.transport.mutate = lambda _: self.h.verifier.trust.document.update(revision=2)
        with self.policy(), self.assertRaises(Denied): self.h.sign()
        self.assertFalse(self.h.port.calls)
    def test_run_binding_changes_during_signer_port(self):
        self.h.port.callback = lambda _: self.h.observer.snapshot.update(genesisSHA256='0' * 64)
        with self.policy(), self.assertRaises(Denied): self.h.sign()
        self.assertEqual(self.h.c.status()['records']['deployer:0']['state'], 'UNCERTAIN')
    def test_envelope_copy_mutation_by_port_not_accepted(self):
        def change(tx): tx['data'] = '0x6001'; self.h.port.raw = synthetic_raw(data=b'\x60\x01')
        self.h.port.callback = change
        with self.policy(), self.assertRaises(Denied): self.h.sign()
        self.assertEqual(self.h.cfg['envelopes'][0]['data'], '0x6000')
    def test_invalid_returned_signature_halts(self):
        self.h.port.raw = synthetic_raw(s=b'')
        with self.policy(), self.assertRaises(Denied): self.h.sign()
        self.assertIsNone(self.h.j.recover()['records']['deployer:0']['rawTransactionHex'])
    def test_signer_exception_no_retry(self):
        def failure(_): raise TimeoutError('synthetic signer failure')
        self.h.port.callback = failure
        with self.policy(), self.assertRaises(TimeoutError): self.h.sign()
        with self.policy(), self.assertRaises(Denied): self.h.sign()
        self.assertEqual(len(self.h.port.calls), 1)
    def test_signer_deadline_late_return_rejected(self):
        self.h.port.callback = lambda _: setattr(self.h.monotonic, 'value', 11)
        with self.policy(), self.assertRaises(Denied): self.h.sign()
    def test_expiry_during_evm_verification_not_persisted_as_signed(self):
        original = self.h.authority.evm.verify
        def delayed(tx, raw):
            result = original(tx, raw); self.h.now = 200; return result
        with self.policy(), patch.object(self.h.authority.evm, 'verify', side_effect=delayed), self.assertRaises(Denied):
            self.h.sign()
        self.assertIsNone(self.h.j.recover()['records']['deployer:0']['txHash'])
    def test_concurrent_sign_requests_only_one_port_call(self):
        def attempt():
            try: return self.h.sign()
            except Denied: return None
        with self.policy(), ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: attempt(), range(2)))
        self.assertEqual(sum(r is not None for r in results), 1)
        self.assertEqual(len(self.h.port.calls), 1)
        self.assertTrue(self.h.c.halted)
    def test_exact_evm_verifier_dependency_required(self):
        with self.assertRaises(Denied):
            LiveAuthorityBinding(self.h.cfg, self.h.j, self.h.binding, self.h.verifier, canonical(self.h.signed), evm_verifier=object())
    def test_approval_changes_before_submit(self):
        with self.policy():
            signed = self.h.sign()
            self.h.authority.binding.document['body']['issuerId'] = 'CHANGED'
            with self.assertRaises(Denied): self.h.signer.prepare_submission(signed['journalKey'])
        self.assertEqual(self.h.c.status()['records']['deployer:0']['state'], 'UNCERTAIN')
    def test_revocation_update_before_submit_halts(self):
        with self.policy():
            signed = self.h.sign()
            self.h.verifier.trust.document['revokedKeyIds'] = ['RFC_FIXTURE_NOT_REAL_AUTHORITY']
            with self.assertRaises(Denied): self.h.signer.prepare_submission(signed['journalKey'])
        self.assertTrue(self.h.authority.halted)
    def test_decoder_timeout_cannot_confirm_signed_result(self):
        self.h.authority.evm = EVMTransactionVerifier()
        with self.policy(), patch('lqc_live508.live_signer.subprocess.run', side_effect=TimeoutError('synthetic codec timeout')):
            with self.assertRaises(TimeoutError): self.h.sign()
        self.assertIsNone(self.h.j.recover()['records']['deployer:0']['txHash'])
    def test_expired_before_submit(self):
        with self.policy():
            signed = self.h.sign(); self.h.now = 200
            with self.assertRaises(Denied): self.h.signer.prepare_submission(signed['journalKey'])
        self.assertEqual(self.h.c.status()['reserved']['deployer'], 500000)
    def test_double_sign_request_denied(self):
        with self.policy():
            self.h.sign()
            with self.assertRaises(Denied): self.h.sign()
        self.assertEqual(len(self.h.port.calls), 1)
    def test_double_intent_handoff_denied(self):
        with self.policy():
            signed = self.h.sign(); self.h.signer.prepare_submission(signed['journalKey'])
            with self.assertRaises(Denied): self.h.signer.prepare_submission(signed['journalKey'])
        self.assertEqual(self.h.c.status()['records']['deployer:0']['state'], 'UNCERTAIN')
    def test_restart_never_calls_signer_or_releases_budget(self):
        with self.policy(): self.h.sign()
        self.h.j.close(); self.h.j = LiveJournal(self.h.root / 'journal', self.h.cfg, self.h.root)
        restarted = LiveCoordinator(self.h.j)
        self.assertEqual(restarted.status()['records']['deployer:0']['state'], 'UNCERTAIN')
        self.assertEqual(restarted.status()['reserved']['deployer'], 500000)
        self.assertEqual(len(self.h.port.calls), 1)
    def test_sign_requested_commit_failure_prevents_port(self):
        original = self.h.j._store
        def fail(payload):
            if any(r['state'] == 'SIGN_REQUESTED' for r in payload['records'].values()): raise OSError('synthetic disk failure')
            return original(payload)
        with self.policy(), patch.object(self.h.j, '_store', side_effect=fail), self.assertRaises(OSError): self.h.sign()
        self.assertFalse(self.h.port.calls)
    def test_signed_commit_failure_keeps_reservation_and_halts(self):
        original = self.h.j._new_file
        def fail(name, content):
            if b'"state":"SIGNED"' in content: raise OSError('synthetic disk failure')
            return original(name, content)
        with self.policy(), patch.object(self.h.j, '_new_file', side_effect=fail), self.assertRaises(OSError): self.h.sign()
        self.assertTrue(self.h.c.halted)
        self.h.j.close(); self.h.j = LiveJournal(self.h.root / 'journal', self.h.cfg, self.h.root)
        self.assertEqual(LiveCoordinator(self.h.j).status()['reserved']['deployer'], 500000)
    def test_submit_intent_commit_failure_returns_no_packet(self):
        with self.policy():
            signed = self.h.sign()
            with patch.object(self.h.j, '_new_file', side_effect=OSError('synthetic disk failure')):
                with self.assertRaises(OSError): self.h.signer.prepare_submission(signed['journalKey'])
        self.assertTrue(self.h.authority.halted)
    def test_receipt_and_recovery_remain_denied(self):
        with self.assertRaises(Denied): self.h.authority.verify_receipt(self.h.cfg, {}, {})
        with self.assertRaises(Denied): self.h.authority.authorize_recovery(self.h.cfg, '0' * 64, {}, {}, {})
    def test_state_never_enables_mainnet(self):
        self.assertFalse(self.h.authority.status()['executionEnabled'])
        self.assertEqual(self.h.authority.status()['official5.08'], 'BLOCKED')
        self.assertEqual(self.h.authority.status()['mainnet'], 'NO-GO')


class PolicyTests(unittest.TestCase):
    def rejection(self, trust_change=None, document_change=None):
        h = Harness(trust_change, document_change)
        try:
            with patch('lqc_live508.shared.offline_authority.verify_public_signature'), self.assertRaises(Denied): h.sign()
            self.assertFalse(h.port.calls)
            self.assertEqual(h.c.status()['operationalState'], 'HALTED')
        finally: h.close()
    def test_revoked_approval_and_key(self):
        for key, value in [('revokedApprovalIds', ['e' * 64]), ('revokedKeyIds', ['RFC_FIXTURE_NOT_REAL_AUTHORITY'])]:
            with self.subTest(field=key): self.rejection(trust_change=lambda t: t.update({key: value}))
    def test_role_allowlist_budget_and_identity_authority(self):
        for field, value in [('roles', ['owner', 'guardian']), ('operations', []), ('maximumTotalBudgetAtest', 499999),
                             ('maximumRoleBudgetAtest', {'deployer': 1, 'owner': 1000000, 'guardian': 1000000}),
                             ('identityStatus', 'UNKNOWN'), ('authorityStatus', 'UNKNOWN'), ('expiresAt', 100), ('chainIds', [97])]:
            with self.subTest(field=field):
                self.rejection(trust_change=lambda t: t['keys']['RFC_FIXTURE_NOT_REAL_AUTHORITY'].update({field: value}))
    def test_trust_config_expiry(self):
        self.rejection(trust_change=lambda t: t.update(validUntil=100))
    def test_wrong_journal_registration(self):
        self.rejection(trust_change=lambda t: t['journalBindings']['a' * 32].update(pathSHA256='0' * 64))
    def test_wrong_key_issuer_or_algorithm(self):
        for change in (lambda d: d['signature'].update(keyId='UNKNOWN'), lambda d: d['body'].update(issuerId='OTHER'),
                       lambda d: d['signature'].update(algorithm='secp256k1')):
            self.rejection(document_change=change)
    def test_missing_or_changed_live_signed_binding(self):
        for field in ('runEvidenceSHA256', 'journalPathSHA256', 'trustSHA256', 'envelopesSHA256'):
            with self.subTest(field=field):
                self.rejection(document_change=lambda d: d['body']['manifest']['liveBinding'].update({field: '0' * 64}))
    def test_recovery_approval_not_deployment(self):
        self.rejection(document_change=lambda d: d['body'].update(purpose='MANUAL_RECOVERY'))


if __name__ == '__main__': unittest.main(verbosity=2)
