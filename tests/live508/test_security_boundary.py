"""Supported API bypass tests. No claim of isolation from hostile Python code."""
import copy
import pathlib
import tempfile
import unittest
from unittest.mock import patch
from lqc_live508.shared.mock_backend import canonical, digest, Denied
from lqc_live508.shared.durable_journal import strict_json
from lqc_live508.live_path import SubmissionTransport, _ExecutionCapability
from lqc_live508.live_rpc import LoopbackTransport
from lqc_live508.run_binding import endpoint, canonical_endpoint
from lqc_live508.live_journal import LiveJournal
from lqc_live508.live_coordinator import LiveCoordinator
from tests.live508.test_live_execution import Harness, FakeSocket
from tests.live508.test_live_journal import contract

class CapabilityTests(unittest.TestCase):
    def setUp(self): self.h = Harness()
    def tearDown(self): self.h.close()
    def approval(self): return patch('lqc_live508.shared.offline_authority.verify_public_signature')
    def intent(self):
        with self.approval():
            signed = self.h.sign(); self.h.signer.prepare_submission(signed['journalKey'])
        return self.h.record()
    def issued(self):
        r = self.intent()
        with self.approval(): cap = self.h.transport._issue_for(self.h.rpc, r)
        return r, cap
    def wire(self, r): return canonical({'jsonrpc':'2.0','id':500,'method':'eth_sendRawTransaction','params':[r['rawTransactionHex']]})
    def blocked(self):
        self.assertEqual(self.h.sent, 0)
        self.assertTrue(self.h.transport.halted); self.assertTrue(self.h.c.halted)
        self.assertTrue(self.h.j.payload['halted'])
    def dispatch(self, r, cap):
        with self.approval(): return self.h.transport._dispatch(self.wire(r), deadline=5, capability=cap)
    def test_old_true_callback_without_approval_denied(self):
        with self.assertRaises(Denied):
            with self.h.transport.authorize_once('0x01', lambda: True): pass
        self.blocked()
    def test_old_true_callback_even_after_valid_intent_denied(self):
        r = self.intent()
        with self.assertRaises(Denied):
            with self.h.transport.authorize_once(r['rawTransactionHex'], lambda: True): pass
        self.blocked()
    def test_direct_exchange_denied_after_intent(self):
        r = self.intent()
        with self.assertRaises(Denied): self.h.transport.exchange(self.wire(r), deadline=5)
        self.blocked()
    def test_base_class_exchange_cannot_bypass(self):
        r = self.intent()
        with self.assertRaises(Denied): LoopbackTransport.exchange(self.h.transport, self.wire(r), deadline=5)
        self.blocked()
    def test_capability_constructor_cannot_mint(self):
        with self.assertRaises(TypeError): _ExecutionCapability()
    def test_object_new_forgery_not_registered(self):
        r = self.intent(); fake = object.__new__(_ExecutionCapability)
        with self.assertRaises(Denied): self.dispatch(r, fake)
        self.blocked()
    def test_dictionary_lookalike_denied(self):
        r = self.intent()
        with self.assertRaises(Denied): self.dispatch(r, {'txHash':r['txHash'], 'approved':True})
        self.blocked()
    def test_copied_capability_denied(self):
        r, cap = self.issued(); fake = object.__new__(type(cap))
        with self.assertRaises(Denied): self.dispatch(r, fake)
        self.blocked()
    def test_unbound_transport_cannot_issue(self):
        r = self.intent(); t = SubmissionTransport(self.h.binding.url, enabled=True)
        with self.assertRaises(Denied): t._issue_for(self.h.rpc, r)
        self.assertTrue(t.halted); self.assertEqual(self.h.sent, 0)
    def test_foreign_transport_capability_denied(self):
        r, cap = self.issued(); t = SubmissionTransport(self.h.binding.url, enabled=True)
        with self.assertRaises(Denied): t._dispatch(self.wire(r), deadline=5, capability=cap)
        self.assertTrue(t.halted); self.assertEqual(self.h.sent, 0)
    def test_capability_single_use(self):
        r, cap = self.issued(); self.dispatch(r, cap); self.assertEqual(self.h.sent, 1)
        with self.assertRaises(Denied): self.dispatch(r, cap)
        self.assertEqual(self.h.sent, 1); self.assertTrue(self.h.c.halted)
    def test_fresh_capability_for_consumed_intent_denied(self):
        r, cap=self.issued();self.dispatch(r,cap)
        with self.approval(),self.assertRaises(Denied):self.h.transport._issue_for(self.h.rpc,r)
        self.assertEqual(self.h.sent,1);self.assertTrue(self.h.c.halted)
    def test_replacing_transport_cannot_reissue_intent(self):
        r, cap=self.issued();self.dispatch(r,cap)
        t=SubmissionTransport(self.h.binding.url,enabled=True,clock=self.h.monotonic,socket_factory=lambda *args:FakeSocket(self.h))
        self.h.rpc.transport=t;self.h.transport=t;t._bind_execution(self.h.path)
        with self.approval(),self.assertRaises(Denied):t._issue_for(self.h.rpc,r)
        self.assertEqual(self.h.sent,1);self.assertTrue(self.h.c.halted)
    def test_concurrent_issue_fails_closed(self):
        from concurrent.futures import ThreadPoolExecutor
        r=self.intent()
        def issue():
            try:return self.h.transport._issue_for(self.h.rpc,r)
            except Denied:return None
        with self.approval(),ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(lambda _:issue(),range(2)))
        self.assertEqual(sum(x is not None for x in results),1)
        self.blocked()
    def test_concurrent_dispatch_sends_at_most_once(self):
        from concurrent.futures import ThreadPoolExecutor
        r,cap=self.issued()
        def send():
            try:return self.h.transport._dispatch(self.wire(r),deadline=5,capability=cap)
            except Denied:return None
        with self.approval(),ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(lambda _:send(),range(2)))
        self.assertEqual(sum(x is not None for x in results),1)
        self.assertEqual(self.h.sent,1);self.assertTrue(self.h.c.halted)
    def test_public_exchange_cannot_use_outstanding_capability(self):
        r, cap = self.issued()
        with self.assertRaises(Denied): self.h.transport.exchange(self.wire(r), deadline=5)
        self.blocked()
    def test_changed_raw_denied(self):
        r, cap = self.issued(); r['rawTransactionHex'] = '0x01'
        with self.assertRaises(Denied): self.dispatch(r, cap)
        self.blocked()
    def test_changed_hash_before_issue_denied(self):
        r = self.intent(); r['txHash'] = '0x' + '00'*32
        with self.approval(), self.assertRaises(Denied): self.h.transport._issue_for(self.h.rpc, r)
        self.blocked()
    def test_expired_after_issue_denied(self):
        r, cap = self.issued(); self.h.now = 201
        with self.assertRaises(Denied): self.dispatch(r, cap)
        self.blocked()
    def test_approval_digest_after_issue_denied(self):
        r, cap = self.issued(); self.h.authority.binding.document['body']['approvalId'] = '0'*64
        with self.assertRaises(Denied): self.dispatch(r, cap)
        self.blocked()
    def test_run_change_after_issue_denied(self):
        r, cap = self.issued(); self.h.observer.snapshot['genesisSHA256'] = '0'*64
        with self.assertRaises(Denied): self.dispatch(r, cap)
        self.blocked()
    def test_journal_halted_after_issue_denied(self):
        r, cap = self.issued(); self.h.c.halt()
        with self.assertRaises(Denied): self.dispatch(r, cap)
        self.blocked()
    def test_journal_generation_change_after_issue_denied(self):
        r, cap = self.issued(); self.h.j.advance(self.h.key, 'SUBMITTED')
        with self.assertRaises(Denied): self.dispatch(r, cap)
        self.blocked()
    def test_rebinding_path_denied(self):
        with self.assertRaises(Denied): self.h.transport._bind_execution(self.h.path)
        self.blocked()
    def test_double_issue_invalidates_all_grants(self):
        r, cap = self.issued()
        with self.approval(), self.assertRaises(Denied): self.h.transport._issue_for(self.h.rpc, r)
        with self.assertRaises(Denied): self.dispatch(r, cap)
        self.blocked()
    def test_connection_failure_consumes_permission(self):
        r, cap = self.issued()
        def fail(): raise OSError('fake connection boundary failure')
        self.h.connect_hook = fail
        with self.assertRaises(Denied): self.dispatch(r, cap)
        with self.assertRaises(Denied): self.dispatch(r, cap)
        self.blocked()

class RollbackTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='lqc508-rollback-');self.root=pathlib.Path(self.tmp.name)
        self.cfg=contract(self.root);self.j=LiveJournal(self.root/'journal',self.cfg,self.root,create=True)
    def tearDown(self): self.j.close();self.tmp.cleanup()
    def test_empty_snapshot_reopen_halts_without_checkpoint(self):
        self.j.close();self.j=LiveJournal(self.root/'journal',self.cfg,self.root)
        c=LiveCoordinator(self.j)
        self.assertTrue(c.halted);self.assertTrue(self.j.payload['halted'])
        with self.assertRaises(Denied): self.j.reserve(self.cfg['envelopes'][0])
    def test_in_process_older_valid_snapshot_denied(self):
        old=(self.j.path/'journal.json').read_bytes()
        self.j.reserve(self.cfg['envelopes'][0]);(self.j.path/'journal.json').write_bytes(old)
        with self.assertRaisesRegex(Denied,'rollback'): self.j.recover()
        self.assertTrue(self.j.poisoned)
    def test_restore_old_empty_snapshot_after_close_halts(self):
        old=(self.j.path/'journal.json').read_bytes();self.j.reserve(self.cfg['envelopes'][0]);self.j.close()
        (self.root/'journal/journal.json').write_bytes(old)
        self.j=LiveJournal(self.root/'journal',self.cfg,self.root);c=LiveCoordinator(self.j)
        self.assertTrue(c.halted)
        with self.assertRaises(Denied): c.begin(self.cfg['envelopes'][0])
    def test_hash_valid_same_generation_replacement_denied(self):
        self.j.reserve(self.cfg['envelopes'][0])
        payload=copy.deepcopy(self.j.payload)
        event={'seq':1,'key':None,'record':None,'previous':'0'*64,'halted':True}
        event['sha256']=digest(canonical(event))
        payload.update(records={},events=[event],halted=True)
        wrapper={'payload':payload,'sha256':digest(canonical(payload))}
        self.j._validate_payload(wrapper)  # valid alternative history, same generation
        (self.j.path/'journal.json').write_bytes(canonical(wrapper))
        with self.assertRaisesRegex(Denied,'rollback'): self.j.recover()
        self.assertTrue(self.j.poisoned)
    def test_create_existing_snapshot_never_overwrites(self):
        before=(self.j.path/'journal.json').read_bytes()
        with self.assertRaises(Denied): LiveJournal(self.root/'journal',self.cfg,self.root,create=True)
        self.assertEqual((self.j.path/'journal.json').read_bytes(),before)

class EndpointTests(unittest.TestCase):
    def test_flow_root_url_normalizes_only_trailing_slash(self):
        for url in ['http://127.0.0.1:8545','http://127.0.0.1:8545/']:
            self.assertEqual(endpoint(url),('127.0.0.1',8545));self.assertEqual(canonical_endpoint(url),'http://127.0.0.1:8545/')
    def test_host_scheme_port_path_not_rewritten(self):
        for url in ['https://127.0.0.1:8545','http://localhost:8545','http://127.0.0.2:8545',
                    'http://127.0.0.1:08545','http://127.0.0.1:8545/rpc','http://127.0.0.1:8545//',
                    'http://127.0.0.1:8545?x=1','http://127.0.0.1:8545/#x','http://127.0.0.1:0',
                    'http://127.0.0.1:65536','http://127.0.0.1:8545/../','http://127.0.0.1:8545/%2f']:
            with self.subTest(url=url),self.assertRaises(Denied): canonical_endpoint(url)
    def test_port_is_preserved_not_defaulted(self):
        self.assertEqual(canonical_endpoint('http://127.0.0.1:9545'),'http://127.0.0.1:9545/')
    def test_signed_endpoint_change_invalidates_binding(self):
        h=Harness()
        try:
            h.binding.spec['rpc']['url']=h.binding.spec['rpc']['url'].rstrip('/')
            with self.assertRaises(Denied):h.binding.verify()
            self.assertTrue(h.binding.halted);self.assertEqual(h.sent,0)
        finally:h.close()

class FlowRootIntegrationTests(unittest.TestCase):
    def test_existing_flow_endpoint_without_slash_executes_synthetic_path(self):
        from tests.live508 import test_live_authority_signer as fixture
        original=fixture.make_spec
        def no_slash(cfg):
            spec=original(cfg);spec['rpc']['url']=spec['rpc']['url'].rstrip('/');return spec
        with patch.object(fixture,'make_spec',side_effect=no_slash):h=Harness()
        try:
            self.assertEqual(h.binding.url,'http://127.0.0.1:8545')
            self.assertEqual(h.execute()['transactionState'],'CONFIRMED')
            self.assertEqual(h.sent,1)
        finally:h.close()
