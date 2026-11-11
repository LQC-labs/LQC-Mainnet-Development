"""Local persistence tests. All approval/chain/signature verification is a DOUBLE.

The bytes used here are deliberately NOT serialized signed EVM transactions.
No keys, signatures, HTTP requests, nodes or submissions are produced.
"""
import copy
import errno
import multiprocessing
import os
import pathlib
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import patch

from lqc_live508.journal_reuse import Denied, canonical, digest, Journal, plan_from_backend
from lqc_live508.live_contracts import validate_contract
from lqc_live508.live_hash import transaction_hash
from lqc_live508.live_journal import LiveJournal
from lqc_live508.live_coordinator import LiveCoordinator

RAW = b'SYNTHETIC STORAGE TEST; NOT A SIGNED TRANSACTION'


def contract(root):
    roles = {r: '0x' + str(i) * 40 for i, r in enumerate(('deployer', 'owner', 'guardian'), 1)}
    envelopes = [{'runId': 'a' * 32, 'chainId': 917001, 'genesisSHA256': 'b' * 64,
                  'scope': 'DEVNET_TRANSACTION_V1', 'operation': op, 'role': 'deployer',
                  'from': roles['deployer'], 'to': None, 'data': '0x6000', 'nonce': i,
                  'gasLimit': 100, 'maxFee': 5, 'maxPriority': 1, 'value': 0}
                 for i, op in enumerate(('Asset18', 'Asset6'))]
    entries = []
    for tx in envelopes:
        e = {k: tx[k] for k in ('operation', 'role', 'from', 'to', 'value', 'nonce', 'gasLimit', 'maxFee', 'maxPriority')}
        e['dataSHA256'] = digest(bytes.fromhex(tx['data'][2:])); entries.append(e)
    return {'schema': 'LQC_DEVNET_JOURNAL_V1', 'envelopes': envelopes,
            'manifest': {'runId': 'a' * 32, 'chainId': 917001, 'genesisSHA256': 'b' * 64,
                         'profileSHA256': 'c' * 64, 'ABIPlanSHA256': 'd' * 64,
                         'roles': roles, 'roleBudgets': dict.fromkeys(roles, 1000),
                         'totalBudget': 1000, 'transactions': entries},
            'binding': {'approvalId': 'e' * 64, 'approvalSHA256': 'f' * 64,
                        'trustSHA256': '1' * 64, 'runEvidenceSHA256': '2' * 64,
                        'journalPathSHA256': digest(str(root / 'journal').encode()),
                        'notBefore': 100, 'expiresAt': 340, 'cosmosChainId': 'lqc-devnet-test-1'}}


class VerificationDouble:
    """Not a production implementation; never claims synthetic bytes are real."""
    def authorize(self, contract, envelope, phase):
        return True

    def verify_signed(self, envelope, raw):
        return raw in (RAW, RAW + b'2')

    def verify_receipt(self, contract, record, evidence):
        return evidence['summary']

    def authorize_recovery(self, contract, snapshot, record, evidence, approval):
        return approval == {'snapshot': snapshot, 'evidenceSHA256': digest(canonical(evidence)), 'noResubmission': True}


def crash_writer(root_text, cfg, phase):
    """A fresh local Python process dies at an actual storage boundary."""
    root = pathlib.Path(root_text)
    j = LiveJournal(root / 'journal', cfg, root)
    if phase == 'before-replace':
        def crash_replace(*args):
            os._exit(71)
        os.replace = crash_replace
    else:
        original = j._atomic
        def crash_after(name, content):
            original(name, content)
            os._exit(72)
        j._atomic = crash_after
    j.reserve(cfg['envelopes'][0])


class LiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='lqc-live-journal-test-')
        self.root = pathlib.Path(self.tmp.name)
        self.cfg = contract(self.root)
        self.j = LiveJournal(self.root / 'journal', self.cfg, self.root, create=True)
        self.c = LiveCoordinator(self.j, VerificationDouble(), lambda: 101)

    def tearDown(self):
        self.j.close()
        self.tmp.cleanup()

    def reopen(self):
        self.j.close()
        self.j = LiveJournal(self.root / 'journal', self.cfg, self.root)
        self.c = LiveCoordinator(self.j, VerificationDouble(), lambda: 102)

    def signed(self):
        key = self.c.begin(self.cfg['envelopes'][0])
        txhash = self.c.record_signed(key, RAW)
        return key, txhash

    def submitted(self):
        key, txhash = self.signed()
        self.c.prepare_submission(key)
        self.c.record_submitted(key, txhash)
        return key, txhash

    def evidence(self, txhash, status=1):
        return {'summary': {'transactionHash': txhash, 'blockHash': '0x' + '9' * 64,
                            'blockNumber': 1, 'status': status, 'gasUsed': 70, 'effectiveGasPrice': 3},
                'classification': 'SYNTHETIC_TEST_NOT_CHAIN_EVIDENCE'}

    def test_reuses_storage_primitives(self):
        for name in ('_atomic', '_new_file', '_safe_file', '_guard', 'close'):
            self.assertIs(getattr(LiveJournal, name), getattr(Journal, name))

    def test_reuses_existing_backend_envelope_and_manifest_builder(self):
        m = self.cfg['manifest']
        p = {k: m[k] for k in ('chainId', 'genesisSHA256', 'runId', 'roles')}
        plan, entries = {}, {}
        for tx in self.cfg['envelopes']:
            plan[tx['operation']] = {'senderRole': tx['role'], 'nonce': str(tx['nonce']),
                'gasLimit': str(tx['gasLimit']), 'maxFeePerGasAtest': str(tx['maxFee']),
                'maxPriorityFeePerGasAtest': str(tx['maxPriority'])}
            entries[tx['operation']] = {'transaction': {'data': tx['data'], 'to': tx['to']}}
        backend = SimpleNamespace(p=p, plan=plan, entries=entries, packet={'entries': list(entries.values())},
                                  budgets=m['roleBudgets'], total=m['totalBudget'])
        manifest, envelopes = plan_from_backend(backend)
        self.assertEqual(envelopes, self.cfg['envelopes'])
        self.assertEqual(manifest['transactions'], m['transactions'])

    def test_keccak_is_not_sha256_or_sha3(self):
        self.assertEqual(transaction_hash(b'abc'), '0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45')

    def test_default_verification_denies(self):
        c = LiveCoordinator(self.j, clock=lambda: 101)
        with self.assertRaises(Denied): c.begin(self.cfg['envelopes'][0])
        self.reopen()
        self.assertEqual(self.c.status()['operationalState'], 'HALTED')

    def test_binding_rejects_context_change(self):
        self.j.close()
        for field in ('approvalSHA256', 'trustSHA256', 'runEvidenceSHA256'):
            changed = copy.deepcopy(self.cfg); changed['binding'][field] = '8' * 64
            with self.subTest(field=field), self.assertRaises(Denied):
                LiveJournal(self.root / 'journal', changed, self.root)

    def test_genesis_and_run_mismatch(self):
        for field in ('runId', 'genesisSHA256', 'chainId'):
            changed = copy.deepcopy(self.cfg); changed['envelopes'][0][field] = 1
            with self.subTest(field=field), self.assertRaises(Denied): validate_contract(changed)

    def test_path_binding(self):
        changed = copy.deepcopy(self.cfg); changed['binding']['journalPathSHA256'] = '0' * 64
        with self.assertRaises(Denied): LiveJournal(self.root / 'journal', changed, self.root)

    def test_exact_scope_and_budget(self):
        for mutation in ('budget', 'data', 'nonce', 'role', 'boolean'):
            changed = copy.deepcopy(self.cfg)
            if mutation == 'budget': changed['manifest']['totalBudget'] = 999
            elif mutation == 'boolean': changed['envelopes'][0]['nonce'] = False
            else: changed['envelopes'][0][mutation] = {'data': '0x6001', 'nonce': 7, 'role': 'guardian'}[mutation]
            with self.subTest(mutation=mutation), self.assertRaises(Denied): validate_contract(changed)

    def test_signed_hash_separation_and_durable_intent(self):
        key, txhash = self.signed()
        packet = self.c.prepare_submission(key)
        disk = __import__('json').loads((self.root / 'journal/journal.json').read_text())['payload']['records'][key]
        self.assertEqual(disk['state'], 'SUBMIT_INTENT')
        self.assertEqual(disk['rawTransactionHex'], '0x' + RAW.hex())
        self.assertEqual(packet['txHash'], txhash)
        self.assertNotEqual(txhash[2:], disk['unsignedSHA256'])
        self.assertNotEqual(txhash[2:], disk['rawSHA256'])
        self.assertFalse((self.root / 'journal/checkpoint.json').exists())

    def test_failed_signature_validation_never_stores_signed_bytes(self):
        key = self.c.begin(self.cfg['envelopes'][0])
        with self.assertRaises(Denied): self.c.record_signed(key, b'wrong bytes')
        r = self.c.status()['records'][key]
        self.assertIsNone(r['rawTransactionHex'])
        self.assertEqual(r['state'], 'UNCERTAIN')

    def test_concurrent_submission_handoffs_only_one_succeeds(self):
        key, _ = self.signed()
        def handoff():
            try: return self.c.prepare_submission(key)
            except Denied: return None
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: handoff(), range(2)))
        self.assertEqual(sum(x is not None for x in results), 1)
        self.assertTrue(self.c.halted)

    def test_duplicate_signed_hash_rejected_before_commit(self):
        key, h = self.submitted(); self.c.record_receipt(key, self.evidence(h))
        second = self.c.begin(self.cfg['envelopes'][1])
        with self.assertRaises(Denied): self.c.record_signed(second, RAW)
        state = self.c.status()
        self.assertIsNone(state['records'][second]['txHash'])
        self.assertEqual(state['records'][key]['state'], 'CONFIRMED')

    def test_duplicate_handoff_halts_and_preserves_reserve(self):
        key, _ = self.signed(); self.c.prepare_submission(key)
        with self.assertRaises(Denied): self.c.prepare_submission(key)
        self.reopen()
        state = self.c.status()
        self.assertEqual(state['records'][key]['state'], 'UNCERTAIN')
        self.assertEqual(state['reserved']['deployer'], 500)
        self.assertEqual(state['leases'], [key])

    def test_restart_before_sign_result_never_resigns(self):
        key = self.c.begin(self.cfg['envelopes'][0]); self.reopen()
        self.assertEqual(self.c.status()['records'][key]['state'], 'UNCERTAIN')
        with self.assertRaises(Denied): self.c.record_signed(key, RAW)

    def test_restart_after_signed_never_submits(self):
        key, _ = self.signed(); self.reopen()
        with self.assertRaises(Denied): self.c.prepare_submission(key)
        self.assertEqual(self.c.status()['reserved']['deployer'], 500)

    def test_restart_after_submit_ack_is_uncertain(self):
        key, _ = self.submitted(); self.reopen()
        self.assertEqual(self.c.status()['records'][key]['state'], 'UNCERTAIN')

    def test_wrong_ack_hash_halts(self):
        key, _ = self.signed(); self.c.prepare_submission(key)
        with self.assertRaises(Denied): self.c.record_submitted(key, '0x' + '0' * 64)
        self.assertEqual(self.c.status()['records'][key]['state'], 'UNCERTAIN')

    def test_confirm_and_restart_accounting(self):
        key, h = self.submitted(); self.c.record_receipt(key, self.evidence(h)); self.reopen()
        state = self.c.status()
        self.assertEqual(state['reserved']['deployer'], 0)
        self.assertEqual(state['spent']['deployer'], 210)
        self.assertEqual(state['leases'], [key])
        self.assertEqual(state['records'][key]['evidence'], self.evidence(h))
        self.assertEqual(state['operationalState'], 'HALTED')
        with self.assertRaises(Denied): self.c.begin(self.cfg['envelopes'][1])

    def test_revert_records_cost_and_halts(self):
        key, h = self.submitted(); self.c.record_receipt(key, self.evidence(h, 0)); self.reopen()
        self.assertEqual(self.c.status()['spent']['deployer'], 210)
        self.assertEqual(self.c.status()['records'][key]['state'], 'REVERTED')
        with self.assertRaises(Denied): self.c.begin(self.cfg['envelopes'][1])

    def test_invalid_receipt_retains_reservation(self):
        key, h = self.submitted(); evidence = self.evidence(h); evidence['summary']['gasUsed'] = 101
        with self.assertRaises(Denied): self.c.record_receipt(key, evidence)
        self.assertEqual(self.c.status()['reserved']['deployer'], 500)

    def test_separate_recovery_can_account_but_not_unhalt(self):
        key, h = self.submitted(); self.reopen()
        evidence = self.evidence(h)
        approval = {'snapshot': self.c.status()['snapshotSHA256'], 'evidenceSHA256': digest(canonical(evidence)), 'noResubmission': True}
        self.c.reconcile(key, evidence, approval); self.reopen()
        self.assertEqual(self.c.status()['spent']['deployer'], 210)
        self.assertEqual(self.c.status()['operationalState'], 'HALTED')
        with self.assertRaises(Denied): self.c.begin(self.cfg['envelopes'][1])

    def test_wrong_recovery_snapshot_denied(self):
        key, h = self.submitted(); self.reopen()
        with self.assertRaises(Denied): self.c.reconcile(key, self.evidence(h), {'snapshot': 'old'})
        self.assertEqual(self.c.status()['reserved']['deployer'], 500)

    def test_expiration_and_clock_rollback(self):
        self.c.clock = lambda: 340
        with self.assertRaises(Denied): self.c.begin(self.cfg['envelopes'][0])

    def test_backward_clock_halts(self):
        key = self.c.begin(self.cfg['envelopes'][0]); self.c.clock = lambda: 100
        with self.assertRaises(Denied): self.c.record_signed(key, RAW)

    def test_plan_order(self):
        with self.assertRaises(Denied): self.c.begin(self.cfg['envelopes'][1])

    def test_lock_exclusion(self):
        with self.assertRaises(BlockingIOError): LiveJournal(self.root / 'journal', self.cfg, self.root)

    def test_symlink_and_permissions_rejected(self):
        self.j.close()
        p = self.root / 'journal/journal.json'; p.chmod(0o644)
        with self.assertRaises(Denied): LiveJournal(self.root / 'journal', self.cfg, self.root)
        p.chmod(0o600)
        p.rename(self.root / 'saved'); p.symlink_to(self.root / 'saved')
        with self.assertRaises(Denied): LiveJournal(self.root / 'journal', self.cfg, self.root)

    def test_checksum_corruption(self):
        self.j.close()
        p = self.root / 'journal/journal.json'; p.write_bytes(p.read_bytes().replace(b'"generation":0', b'"generation":1'))
        with self.assertRaises(Denied): LiveJournal(self.root / 'journal', self.cfg, self.root)

    def test_disk_full_prevents_handoff(self):
        key, _ = self.signed()
        with patch.object(self.j, '_new_file', side_effect=OSError(errno.ENOSPC, 'injected disk full')):
            with self.assertRaises(OSError): self.c.prepare_submission(key)
        self.assertTrue(self.j.poisoned)
        self.reopen()
        self.assertEqual(self.c.status()['records'][key]['state'], 'UNCERTAIN')

    def test_directory_fsync_failure_prevents_handoff(self):
        key, _ = self.signed()
        actual = os.fsync; calls = []
        def fail_second(fd):
            calls.append(fd)
            if len(calls) == 2: raise OSError('injected directory fsync failure')
            return actual(fd)
        with patch('os.fsync', side_effect=fail_second):
            with self.assertRaises(OSError): self.c.prepare_submission(key)
        self.reopen()
        self.assertEqual(self.c.status()['records'][key]['state'], 'UNCERTAIN')

    def test_process_death_before_atomic_replace_blocks(self):
        self.j.close()
        p = multiprocessing.get_context('fork').Process(target=crash_writer, args=(str(self.root), self.cfg, 'before-replace'))
        p.start(); p.join(10)
        if p.is_alive(): p.kill(); p.join(); self.fail('local child timeout')
        self.assertEqual(p.exitcode, 71)
        self.assertTrue((self.root / 'journal/journal.json.new').exists())
        with self.assertRaises(Denied): LiveJournal(self.root / 'journal', self.cfg, self.root)

    def test_process_death_after_commit_restores_reservation(self):
        self.j.close()
        p = multiprocessing.get_context('fork').Process(target=crash_writer, args=(str(self.root), self.cfg, 'after-commit'))
        p.start(); p.join(10)
        if p.is_alive(): p.kill(); p.join(); self.fail('local child timeout')
        self.assertEqual(p.exitcode, 72)
        self.reopen()
        self.assertEqual(self.c.status()['reserved']['deployer'], 500)
        self.assertEqual(self.c.status()['records']['deployer:0']['state'], 'UNCERTAIN')

    def test_status_does_not_enable_deployment(self):
        status = self.c.status()
        self.assertFalse(status['executionEnabled'])
        self.assertEqual((status['official5.08'], status['mainnet']), ('BLOCKED', 'NO-GO'))

    def test_active_is_not_automatically_halted_until_restart(self):
        self.c.begin(self.cfg['envelopes'][0])
        self.assertEqual(self.c.status()['operationalState'], 'LOCAL_JOURNAL_ACTIVE')

    def test_contract_mutation_poisoned(self):
        self.j.contract['binding']['trustSHA256'] = '0' * 64
        with self.assertRaises(Denied): self.c.begin(self.cfg['envelopes'][0])
        self.assertTrue(self.c.halted)


if __name__ == '__main__':
    unittest.main(verbosity=2)
