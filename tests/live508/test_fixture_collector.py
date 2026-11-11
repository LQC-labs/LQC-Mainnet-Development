"""Historical collector activation through real offline receipt/journal boundaries."""
import copy
import json
import unittest
from unittest.mock import patch
from lqc_live508.shared.fixture_collector import FixtureCollector, OfflineCodec, ARTIFACTS
from lqc_live508.shared.mock_backend import Denied, canonical, digest
from tests.live508 import test_offline_adapters as adapter_tests

class FixtureCollectorTests(unittest.TestCase):
    def setUp(self):
        self.base = adapter_tests.IntegratedTests(); self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.io = self.base.io

    def prepare(self, mutate=None):
        b = self.base.bound()
        artifacts = [json.loads(p.read_text()) for p in ARTIFACTS.glob('LQC*.json')]
        bundle = {}
        for height, (op, entry) in enumerate(b.entries.items(), 2):
            tx = b.expected_envelope(op)
            artifact = next(a for a in artifacts if digest(canonical(a['abi'])) == entry['abiSHA256'])
            txhash = '0x'+digest(canonical(tx)); blockhash = '0x'+digest(str(height).encode())
            address = entry.get('predictedAddress') or entry['transaction']['to']
            logs = []; events = []
            if op == 'Asset18':
                # Public ERC20 Transfer event bytes, no signing/key operation.
                topic = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef'
                logs = [dict(address=address, transactionHash=txhash, blockHash=blockhash,
                    blockNumber=hex(height), logIndex='0x0', removed=False,
                    topics=[topic, '0x'+'0'*64, '0x'+'0'*24+b.p['roles']['owner'][2:]], data='0x'+format(1,'064x'))]
                events = ['Transfer']
            bundle[op] = dict(scope='SYNTHETIC_NOT_CHAIN_EVIDENCE', artifact=artifact,
                runtimeHex=artifact['deployedBytecode'], getters={}, expectedGetters={},
                receipt=dict(transactionHash=txhash, blockHash=blockhash, blockNumber=hex(height),
                    contractAddress=entry.get('predictedAddress'),status='0x1', gasUsed='0x1',effectiveGasPrice='0x1',logs=logs),
                block=dict(hash=blockhash,number=hex(height)), requiredEvents=events)
        if mutate: mutate(bundle['Asset18'])
        c = FixtureCollector(b.p,b.packet,bundle,OfflineCodec(fixture=True),fixture=True)
        self.io.proof_collector = self.io.required_proof_collector = c
        return b,c

    def test_all24_receipts_create_call_and_journal_proof(self):
        with patch('lqc_live508.shared.offline_authority.verify_public_signature'):
            b,c = self.prepare()
            for op, tx in b.plan.items(): b.execute_mock(op,tx['senderRole'])
        self.assertEqual(len(c.proofs),24)
        self.assertEqual(c.proofs['Asset18']['kind'],'CREATE')
        self.assertEqual(c.proofs['SetCore']['kind'],'CALL')
        self.assertEqual(c.proofs['Asset18']['eventProjection']['events'][0]['name'],'Transfer')
        records = self.base.f.j.recover()['records']
        for receipt in b.evidence:
            self.assertEqual(receipt['integrationProofSHA256'], digest(canonical(c.proofs[receipt['operation']])))
            key = receipt['role']+':'+str(receipt['nonce'])
            self.assertEqual(records[key]['receiptSHA256'], digest(canonical(receipt)))
        self.assertTrue(all(x['state']=='CONFIRMED' for x in self.base.f.j.recover()['records'].values()))

    def check_bad(self, mutate):
        with patch('lqc_live508.shared.offline_authority.verify_public_signature'):
            b,c = self.prepare(mutate)
            with self.assertRaises((Denied,ValueError,KeyError)): b.execute_mock('Asset18','deployer')
            self.assertTrue(b.halted)
            calls=list(self.io.calls)
            with self.assertRaises(Denied): b.execute_mock('Asset18','deployer')
            self.assertEqual(calls,self.io.calls)
        self.assertFalse(c.proofs)
        self.assertNotEqual(self.base.f.j.recover()['records']['deployer:0']['state'],'CONFIRMED')

    def test_artifact_mismatch_halts(self): self.check_bad(lambda p:p['artifact'].update(compilerSHA256='0'*64))
    def test_runtime_mismatch_halts(self): self.check_bad(lambda p:p.update(runtimeHex='0x00'))
    def test_getter_mismatch_halts(self): self.check_bad(lambda p:p.update(expectedGetters={'owner':'wrong'}))
    def test_missing_event_halts(self): self.check_bad(lambda p:p['receipt'].update(logs=[]))
    def test_block_mismatch_halts(self): self.check_bad(lambda p:p['block'].update(hash='0x'+'0'*64))
    def test_scope_mismatch_halts(self): self.check_bad(lambda p:p.update(scope='CHAIN_EVIDENCE'))

    def test_collector_removed_halts(self):
        with patch('lqc_live508.shared.offline_authority.verify_public_signature'):
            b,c=self.prepare();self.io.proof_collector=None
            with self.assertRaisesRegex(Denied,'required-proof-collector-removed'): b.execute_mock('Asset18','deployer')
            self.assertTrue(b.halted)

    def test_lookalike_rejected(self):
        with patch('lqc_live508.shared.offline_authority.verify_public_signature'):
            b,c=self.prepare();self.io.proof_collector=self.io.required_proof_collector=object()
            with self.assertRaisesRegex(Denied,'exact-fixture-collector-only'): b.execute_mock('Asset18','deployer')
            self.assertTrue(b.halted)

    def test_no_approval_no_receipt_or_signer(self):
        with self.assertRaises(Denied): self.prepare()
        self.assertEqual(self.io.calls,[])

    def test_disabled_live_and_plan_rejected(self):
        for make in [lambda:OfflineCodec(live=True),lambda:OfflineCodec().exchange({'action':'events'}),lambda:OfflineCodec(fixture=True).exchange({'action':'plan'})]:
            with self.assertRaises(Denied):make()

    def test_bundle_mutation_and_duplicate_proof_rejected(self):
        with patch('lqc_live508.shared.offline_authority.verify_public_signature'):
            b,c=self.prepare();b.execute_mock('Asset18','deployer')
            tx=b.expected_envelope('Asset18')
            with self.assertRaisesRegex(Denied,'fixture-or-duplicate-proof'):c.verify(tx,'unused',{}, {})
            c.bundle['Asset18']['scope']='changed'
            with self.assertRaisesRegex(Denied,'evidence-input-changed'):c.verify(tx,'unused',{}, {})
