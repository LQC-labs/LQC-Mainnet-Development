"""Synthetic responses and local public-file fixtures only; no RPC server."""
import copy
import io
import json
import os
import pathlib
import tempfile
import unittest
from unittest.mock import patch
from lqc_live508.rpc_reuse import Denied, canonical, digest, WORKSPACE
from lqc_live508.run_binding import RunBinding, LinuxRunObserver, endpoint
from lqc_live508.live_rpc import LiveRPC, LoopbackTransport, RPCBoundVerification
from lqc_live508.live_journal import LiveJournal
from lqc_live508.live_coordinator import LiveCoordinator
# Reuse only fixture constructors; do not rerun the preceding journal suite.
from tests.live508.test_live_journal import contract, VerificationDouble


class Clock:
    def __init__(self): self.value = 0.0
    def __call__(self): return self.value


def make_spec(cfg):
    return {'schema': 'LQC_RUN_BINDING_V1', 'runId': cfg['manifest']['runId'],
            'chainId': 917001, 'cosmosChainId': 'lqc-devnet-test-1',
            'genesisSHA256': cfg['manifest']['genesisSHA256'], 'home': '/approved/node',
            'homeIdentity': {'device': 1, 'inode': 2}, 'identitySHA256': '3' * 64,
            'process': {'pid': 1234, 'startTicks': 500, 'uid': os.getuid(),
                        'bootId': '11111111-2222-3333-4444-555555555555', 'exe': '/approved/lqcd',
                        'exeSHA256': '4' * 64, 'cmdlineSHA256': '5' * 64, 'netNamespace': 'net:[123]'},
            'rpc': {'url': 'http://127.0.0.1:8545/', 'listenerInode': 700}}


class ObserverDouble:
    def __init__(self, spec):
        self.snapshot = {k: copy.deepcopy(v) for k, v in spec.items() if k not in {'schema', 'runId'}}
        self.calls = 0
    def observe(self, spec):
        self.calls += 1
        return copy.deepcopy(self.snapshot)


class TransportDouble:
    def __init__(self, url):
        self.url, self.halted = url, False
        self.requests = []
        self.overrides = {}
        self.mutate = None
        self.fault = None
    def exchange(self, raw, *, deadline):
        request = json.loads(raw); self.requests.append(request)
        method, params = request['method'], request['params']
        defaults = {'eth_chainId': '0xdfe09', 'eth_getBalance': '0xf4240',
                    'eth_getTransactionCount': '0x0', 'eth_getTransactionReceipt': None,
                    'eth_getCode': '0x', 'eth_blockNumber': '0x1', 'eth_estimateGas': '0x64',
                    'eth_gasPrice': '0x1', 'eth_maxPriorityFeePerGas': '0x1',
                    'eth_getBlockByNumber': {'number': '0x1', 'hash': '0x' + 'a' * 64, 'gasLimit': '0x64', 'baseFeePerGas': '0x1'}}
        value = self.overrides.get(method, defaults[method])
        if callable(value): value = value(request)
        reply = {'jsonrpc': '2.0', 'id': request['id'], 'result': value}
        if self.fault == 'id': reply['id'] += 1
        if self.fault == 'boolean-id': reply['id'] = True
        if self.fault == 'version': reply['jsonrpc'] = '1.0'
        if self.fault == 'both': reply['error'] = {'code': -1}
        if self.fault == 'rpc-error':
            reply.pop('result'); reply['error'] = {'code': -32000, 'message': 'PRIVATE_RESPONSE_DO_NOT_LOG', 'data': 'SECRET'}
        body = canonical(reply)
        if self.fault == 'json': body = b'not json'
        if self.fault == 'duplicate': body = b'{"jsonrpc":"2.0","id":1,"id":1,"result":"0xdfe09"}'
        if self.fault == 'large': body = b'x' * 262145
        if self.fault == 'timeout': raise TimeoutError('untrusted details')
        if self.mutate: self.mutate(request)
        return {'status': 503 if self.fault == 'http' else 200, 'body': body,
                'target': self.url if self.fault != 'target' else 'http://127.0.0.1:9999/',
                'peer': ('127.0.0.1', 8545) if self.fault != 'peer' else ('127.0.0.2', 8545)}


class RPCTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='lqc-rpc-binding-test-')
        self.root = pathlib.Path(self.tmp.name)
        self.cfg = contract(self.root)
        self.spec = make_spec(self.cfg)
        self.cfg['binding']['runEvidenceSHA256'] = digest(canonical(self.spec))
        self.observer = ObserverDouble(self.spec)
        self.binding = RunBinding(self.cfg, self.spec, self.observer)
        self.transport = TransportDouble(self.binding.url)
        self.clock = Clock()
        self.rpc = LiveRPC(self.binding, self.transport, enabled=True, clock=self.clock)
        self.journal = None
    def tearDown(self):
        if self.journal: self.journal.close()
        self.tmp.cleanup()
    def coordinator(self, delegate=None):
        self.journal = LiveJournal(self.root / 'journal', self.cfg, self.root, create=True)
        c = LiveCoordinator(self.journal, RPCBoundVerification(self.rpc, delegate), lambda: 101)
        self.rpc.attach_coordinator(c)
        return c

    def test_default_rpc_does_not_exchange(self):
        rpc = LiveRPC(self.binding, self.transport, clock=self.clock)
        with self.assertRaises(Denied): rpc.read_context()
        self.assertEqual(self.transport.requests, [])

    def test_context_and_double_sided_checks(self):
        result = self.rpc.read_context()
        self.assertEqual(result, {k: self.cfg['manifest'][k] for k in ('runId', 'chainId', 'genesisSHA256')})
        self.assertGreaterEqual(self.observer.calls, 3)

    def test_each_non_chain_query_bracketed_by_chain_checks(self):
        self.rpc.request('eth_blockNumber', [])
        self.assertEqual([x['method'] for x in self.transport.requests], ['eth_chainId', 'eth_blockNumber', 'eth_chainId'])
        self.assertEqual([x['id'] for x in self.transport.requests], [1, 2, 3])

    def test_nonce_stable_and_expected(self):
        self.assertEqual(self.rpc.read_nonce('deployer', 0), (0, 0))
        queries = [x['params'][1] for x in self.transport.requests if x['method'] == 'eth_getTransactionCount']
        self.assertEqual(queries, ['latest', 'pending', 'latest'])

    def test_pending_conflict_halts(self):
        self.transport.overrides['eth_getTransactionCount'] = lambda r: '0x1' if r['params'][1] == 'pending' else '0x0'
        with self.assertRaises(Denied): self.rpc.read_nonce('deployer')
        self.assertTrue(self.rpc.halted)

    def test_latest_changes_during_nonce_snapshot(self):
        counts = []
        def nonce(r):
            counts.append(r); return '0x1' if len(counts) == 3 else '0x0'
        self.transport.overrides['eth_getTransactionCount'] = nonce
        with self.assertRaises(Denied): self.rpc.read_nonce('deployer')

    def test_wrong_approved_nonce(self):
        with self.assertRaises(Denied): self.rpc.read_nonce('deployer', 1)

    def test_precheck_identity_failure_sends_nothing(self):
        self.observer.snapshot['genesisSHA256'] = '0' * 64
        with self.assertRaises(Denied): self.rpc.read_context()
        self.assertFalse(self.transport.requests)

    def test_genesis_changes_during_request(self):
        self.transport.mutate = lambda r: self.observer.snapshot.update(genesisSHA256='0' * 64)
        with self.assertRaises(Denied): self.rpc.read_context()
        self.assertEqual(len(self.transport.requests), 1)

    def test_process_changes_during_request(self):
        self.transport.mutate = lambda r: self.observer.snapshot['process'].update(startTicks=501)
        with self.assertRaises(Denied): self.rpc.read_context()

    def test_listener_changes_during_request(self):
        self.transport.mutate = lambda r: self.observer.snapshot['rpc'].update(listenerInode=701)
        with self.assertRaises(Denied): self.rpc.read_context()

    def test_home_changes_during_request(self):
        self.transport.mutate = lambda r: self.observer.snapshot['homeIdentity'].update(inode=3)
        with self.assertRaises(Denied): self.rpc.read_context()

    def test_wrong_chain_id(self):
        self.transport.overrides['eth_chainId'] = '0x61'
        with self.assertRaises(Denied): self.rpc.read_context()

    def test_chain_changes_after_target_query(self):
        def mutate(r):
            if r['method'] == 'eth_blockNumber': self.transport.overrides['eth_chainId'] = '0x61'
        self.transport.mutate = mutate
        with self.assertRaises(Denied): self.rpc.request('eth_blockNumber', [])

    def test_transport_target_mutation(self):
        self.transport.url = 'http://127.0.0.1:8546/'
        with self.assertRaises(Denied): self.rpc.read_context()
        self.assertFalse(self.transport.requests)

    def test_bad_reply_matrix(self):
        for fault in ('id', 'boolean-id', 'version', 'both', 'rpc-error', 'json', 'duplicate', 'large', 'timeout', 'http', 'target', 'peer'):
            with self.subTest(fault=fault):
                binding = RunBinding(self.cfg, self.spec, ObserverDouble(self.spec))
                transport = TransportDouble(binding.url); transport.fault = fault
                rpc = LiveRPC(binding, transport, enabled=True, clock=self.clock)
                with self.assertRaises(Exception): rpc.read_context()
                self.assertTrue(rpc.halted)
                self.assertEqual(len(transport.requests), 1)
                self.assertNotIn('SECRET', str(rpc.diagnostics))
                self.assertNotIn('PRIVATE_RESPONSE', str(rpc.diagnostics))
                with self.assertRaises(Denied): rpc.read_context()
                self.assertEqual(len(transport.requests), 1)

    def test_forbidden_method_and_unknown_address_do_not_probe(self):
        for method, params in [('eth_sendRawTransaction', ['0x00']), ('personal_sign', []),
                               ('eth_call', []), ('eth_getBalance', ['0x' + '9' * 40, 'latest'])]:
            with self.subTest(method=method):
                binding = RunBinding(self.cfg, self.spec, ObserverDouble(self.spec))
                transport = TransportDouble(binding.url)
                rpc = LiveRPC(binding, transport, enabled=True, clock=self.clock)
                with self.assertRaises(Denied): rpc.request(method, params)
                self.assertFalse(transport.requests)

    def test_request_deadline(self):
        self.transport.mutate = lambda r: setattr(self.clock, 'value', 6)
        with self.assertRaises(Denied): self.rpc.read_context()

    def test_run_deadline(self):
        self.clock.value = 240
        with self.assertRaises(Denied): self.rpc.read_context()
        self.assertFalse(self.transport.requests)

    def test_bad_timeout_configuration(self):
        for kwargs in ({'request_timeout': 0}, {'run_timeout': 241}, {'request_timeout': float('nan')}, {'run_timeout': True}):
            with self.subTest(kwargs=kwargs), self.assertRaises(Denied): LiveRPC(self.binding, **kwargs)

    def test_binding_spec_and_contract_mutation(self):
        self.binding.spec['runId'] = '0' * 32
        with self.assertRaises(Denied): self.rpc.read_context()
        self.assertFalse(self.transport.requests)

    def test_unapproved_evidence_rejected(self):
        changed = copy.deepcopy(self.spec); changed['rpc']['url'] = 'http://127.0.0.1:9999/'
        with self.assertRaises(Denied): RunBinding(self.cfg, changed, self.observer)

    def test_empty_code_and_missing_receipt_are_not_deployment_success(self):
        self.assertIsNone(self.rpc.request('eth_getTransactionReceipt', ['0x' + '1' * 64]))
        self.assertEqual(self.rpc.request('eth_getCode', [self.cfg['manifest']['roles']['deployer'], 'latest']), '0x')
        self.assertFalse(self.rpc.status()['executionEnabled'])

    def test_coordinator_default_approval_denies_before_rpc(self):
        c = self.coordinator()
        with self.assertRaises(Denied): c.begin(self.cfg['envelopes'][0])
        self.assertFalse(self.transport.requests)
        self.assertEqual(c.status()['operationalState'], 'HALTED')

    def test_coordinator_success_reaches_only_sign_requested(self):
        c = self.coordinator(VerificationDouble())
        key = c.begin(self.cfg['envelopes'][0])
        self.assertEqual(c.status()['records'][key]['state'], 'SIGN_REQUESTED')
        self.assertIsNone(c.status()['records'][key]['txHash'])

    def test_rpc_failure_durably_halts_existing_reservation(self):
        c = self.coordinator(VerificationDouble()); key = c.begin(self.cfg['envelopes'][0])
        self.transport.overrides['eth_getTransactionCount'] = lambda r: '0x1' if r['params'][1] == 'pending' else '0x0'
        with self.assertRaises(Denied): self.rpc.read_nonce('deployer')
        self.assertEqual(c.status()['records'][key]['state'], 'UNCERTAIN')
        self.assertEqual(c.status()['reserved']['deployer'], 500)
        self.journal.close()
        self.journal = LiveJournal(self.root / 'journal', self.cfg, self.root)
        restarted = LiveCoordinator(self.journal)
        self.assertEqual(restarted.status()['operationalState'], 'HALTED')
        self.assertEqual(restarted.status()['reserved']['deployer'], 500)

    def test_journal_halt_failure_reported(self):
        c = self.coordinator(VerificationDouble()); c.begin(self.cfg['envelopes'][0])
        self.transport.overrides['eth_chainId'] = '0x61'
        with patch.object(c, 'halt', side_effect=OSError('disk failed')):
            with self.assertRaises(Denied): self.rpc.read_context()
        self.assertTrue(self.rpc.status()['haltPersistenceError'])
        self.assertTrue(self.rpc.halted)

    def test_insufficient_balance_blocks_before_reservation(self):
        c = self.coordinator(VerificationDouble()); self.transport.overrides['eth_getBalance'] = '0x1'
        with self.assertRaises(Denied): c.begin(self.cfg['envelopes'][0])
        self.assertFalse(c.status()['records'])

    def test_approval_expires_during_rpc_before_reservation(self):
        c = self.coordinator(VerificationDouble())
        self.transport.mutate = lambda r: setattr(c, 'clock', lambda: 340)
        with self.assertRaises(Denied): c.begin(self.cfg['envelopes'][0])
        self.assertFalse(c.status()['records'])
        self.assertTrue(self.rpc.halted)

    def test_halted_coordinator_blocks_direct_rpc(self):
        c = self.coordinator(VerificationDouble()); c.halt()
        with self.assertRaises(Denied): self.rpc.read_context()
        self.assertFalse(self.transport.requests)

    def test_mutated_contract_address_allowlist(self):
        self.rpc.targets.add('0x' + '9' * 40)
        with self.assertRaises(Denied): self.rpc.read_context()
        self.assertFalse(self.transport.requests)


class FakeSocket:
    def __init__(self, wire, *, peer=('127.0.0.1', 8545), clock=None, trickle=False):
        self.wire, self.peer = io.BytesIO(wire), peer
        self.clock, self.trickle = clock, trickle
        self.connected, self.sent, self.closed, self.timeouts = [], [], False, []
    def settimeout(self, timeout): self.timeouts.append(timeout)
    def connect(self, target): self.connected.append(target)
    def getpeername(self): return self.peer
    def sendall(self, data): self.sent.append(data)
    def recv(self, size):
        if self.trickle: self.clock.value += 0.2
        return self.wire.read(min(size, 1) if self.trickle else size)
    def close(self): self.closed = True


class TransportTests(unittest.TestCase):
    def setUp(self): self.clock = Clock()
    def request(self): return canonical({'jsonrpc': '2.0', 'id': 1, 'method': 'eth_chainId', 'params': []})
    def transport(self, wire, **kwargs):
        fake = FakeSocket(wire, **kwargs)
        transport = LoopbackTransport('http://127.0.0.1:8545/', enabled=True, clock=self.clock, socket_factory=lambda *args: fake)
        return transport, fake
    def test_only_canonical_loopback_allowed(self):
        for url in ('http://localhost:8545/', 'http://0.0.0.0:8545/', 'http://127.0.0.2:8545/',
                    'http://[::1]:8545/', 'http://127.0.0.1:08545/',
                    'http://127.0.0.1:8545/rpc', 'http://127.0.0.1:8545/?x=1',
                    'http://u:p@127.0.0.1:8545/', 'http://127.0.0.1:65536/', 'https://127.0.0.1:8545/'):
            with self.subTest(url=url), self.assertRaises(Denied): endpoint(url)
    def test_default_transport_no_socket_creation(self):
        factory = unittest.mock.Mock(side_effect=AssertionError('must not create socket'))
        t = LoopbackTransport('http://127.0.0.1:8545/', clock=self.clock, socket_factory=factory)
        with self.assertRaises(Denied): t.exchange(self.request(), deadline=5)
        factory.assert_not_called()
    def test_content_length_and_no_proxy(self):
        t, s = self.transport(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}')
        with patch.dict(os.environ, {'HTTP_PROXY': 'http://external.invalid:1234', 'ALL_PROXY': 'socks://external.invalid:1234'}):
            self.assertEqual(t.exchange(self.request(), deadline=5)['body'], b'{}')
        self.assertEqual(s.connected, [('127.0.0.1', 8545)])
        self.assertTrue(s.sent[0].startswith(b'POST / HTTP/1.1\r\n'))
        self.assertTrue(s.closed)
    def test_chunked_supported(self):
        t, s = self.transport(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n')
        self.assertEqual(t.exchange(self.request(), deadline=5)['body'], b'{}')
        self.assertTrue(s.closed)
    def test_wrong_peer_sends_nothing(self):
        t, s = self.transport(b'', peer=('127.0.0.2', 8545))
        with self.assertRaises(Denied): t.exchange(self.request(), deadline=5)
        self.assertFalse(s.sent); self.assertTrue(s.closed)
    def test_transfer_framing_limits(self):
        for headers, body in [(b'Content-Length: 262145', b''),
                              (b'Content-Length: 2\r\nContent-Length: 2', b'{}'),
                              (b'Content-Length: 2\r\nTransfer-Encoding: chunked', b'{}'),
                              (b'Content-Length: 2\r\nContent-Encoding: gzip', b'{}'),
                              (b'Content-Length: 3', b'{}'),
                              (b'X: ok', b'x' * 262145)]:
            with self.subTest(headers=headers):
                t, s = self.transport(b'HTTP/1.1 200 OK\r\n' + headers + b'\r\n\r\n' + body)
                with self.assertRaises(Exception): t.exchange(self.request(), deadline=5)
                self.assertTrue(t.halted); self.assertTrue(s.closed)
    def test_redirect_never_followed(self):
        t, s = self.transport(b'HTTP/1.1 302 Found\r\nLocation: http://example.invalid/\r\nContent-Length: 0\r\n\r\n')
        result = t.exchange(self.request(), deadline=5)
        self.assertEqual(result['status'], 302)
        self.assertEqual(len(s.connected), 1)
    def test_trickled_header_obeys_absolute_deadline(self):
        t, s = self.transport(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n', clock=self.clock, trickle=True)
        with self.assertRaises(Denied): t.exchange(self.request(), deadline=1)
        self.assertLessEqual(self.clock.value, 1.21)
        self.assertTrue(s.closed)
    def test_transport_rejects_write_method(self):
        t, s = self.transport(b'')
        raw = canonical({'jsonrpc': '2.0', 'id': 1, 'method': 'eth_sendRawTransaction', 'params': ['0x00']})
        with self.assertRaises(Denied): t.exchange(raw, deadline=5)
        self.assertFalse(s.connected)

    def test_url_and_target_cannot_be_rebound_together(self):
        t, s = self.transport(b'')
        t.url, t.target = 'http://127.0.0.1:9999/', ('127.0.0.1', 9999)
        with self.assertRaises(Denied): t.exchange(self.request(), deadline=5)
        self.assertFalse(s.connected)


class LocalObservationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='lqc-rpc-binding-test-')
        self.root = pathlib.Path(self.tmp.name)
        self.home, self.proc = self.root / 'home', self.root / 'proc'
        for path in (self.home / 'config', self.home / 'data', self.proc / '1234/ns',
                     self.proc / '1234/net', self.proc / '1234/fd', self.proc / 'self/ns', self.proc / 'sys/kernel/random'):
            path.mkdir(parents=True, exist_ok=True)
        self.cfg = contract(self.root)
        self.spec = make_spec(self.cfg)
        self.genesis = canonical({'chain_id': 'lqc-devnet-test-1', 'lqc_profile': {'Chain': {'EVMChainID': 917001, 'CosmosChainID': 'lqc-devnet-test-1'}}})
        self.identity = canonical({'chain_id': 'lqc-devnet-test-1', 'genesis_sha256': digest(self.genesis), 'node_id': 'synthetic-public-id'})
        (self.home / 'config/genesis.json').write_bytes(self.genesis)
        (self.home / 'data/node.identity.json').write_bytes(self.identity)
        exe = self.root / 'not-a-node-binary'; exe.write_bytes(b'SYNTHETIC EXECUTABLE CONTENT; NEVER EXECUTED')
        (self.proc / '1234/exe').symlink_to(exe)
        cmdline = str(exe).encode() + b'\0start\0--home\0' + str(self.home).encode() + b'\0'
        (self.proc / '1234/cmdline').write_bytes(cmdline)
        (self.proc / '1234/stat').write_text('1234 (fixture process) S ' + '0 ' * 18 + '500 0 0\n')
        uid = os.getuid()
        (self.proc / '1234/status').write_text(f'Name:\tfixture\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n')
        (self.proc / 'sys/kernel/random/boot_id').write_text(self.spec['process']['bootId'] + '\n')
        for path in (self.proc / '1234/ns/net', self.proc / 'self/ns/net'): path.symlink_to('net:[123]')
        (self.proc / '1234/fd/7').symlink_to('socket:[700]')
        (self.proc / '1234/net/tcp').write_text('header\n0: 0100007F:2161 00000000:0000 0A 0:0 00:0 0 0 0 700\n')
        st = self.home.stat()
        self.spec.update(home=str(self.home), homeIdentity={'device': st.st_dev, 'inode': st.st_ino},
                         genesisSHA256=digest(self.genesis), identitySHA256=digest(self.identity))
        self.spec['process'].update(exe=str(exe), exeSHA256=digest(exe.read_bytes()), cmdlineSHA256=digest(cmdline))
        self.cfg['manifest']['genesisSHA256'] = digest(self.genesis)
        for tx in self.cfg['envelopes']: tx['genesisSHA256'] = digest(self.genesis)
        self.cfg['binding']['runEvidenceSHA256'] = digest(canonical(self.spec))
        self.binding = RunBinding(self.cfg, self.spec, LinuxRunObserver(self.proc))
    def tearDown(self): self.tmp.cleanup()
    def test_real_observer_on_fake_proc_and_public_files(self):
        self.assertEqual(self.binding.verify()['genesisSHA256'], digest(self.genesis))
    def test_genesis_bytes_change_even_same_json_rejected(self):
        (self.home / 'config/genesis.json').write_bytes(self.genesis + b'\n')
        with self.assertRaises(Denied): self.binding.verify()
    def test_genesis_wrong_cosmos_id(self):
        g = json.loads(self.genesis); g['chain_id'] = 'wrong'
        (self.home / 'config/genesis.json').write_bytes(canonical(g))
        with self.assertRaises(Denied): self.binding.verify()
    def test_genesis_wrong_evm_id(self):
        g = json.loads(self.genesis); g['lqc_profile']['Chain']['EVMChainID'] = 97
        (self.home / 'config/genesis.json').write_bytes(canonical(g))
        with self.assertRaises(Denied): self.binding.verify()
    def test_db_identity_mismatch(self):
        ident = json.loads(self.identity); ident['genesis_sha256'] = '0' * 64
        (self.home / 'data/node.identity.json').write_bytes(canonical(ident))
        with self.assertRaises(Denied): self.binding.verify()
    def test_pid_reuse_start_ticks(self):
        p = self.proc / '1234/stat'; p.write_text(p.read_text().replace('500', '501'))
        with self.assertRaises(Denied): self.binding.verify()
    def test_reboot_boot_id(self):
        (self.proc / 'sys/kernel/random/boot_id').write_text('99999999-2222-3333-4444-555555555555')
        with self.assertRaises(Denied): self.binding.verify()
    def test_wrong_node_home_argument(self):
        (self.proc / '1234/cmdline').write_bytes(b'lqc\0--home\0/another/home\0')
        with self.assertRaises(Denied): self.binding.verify()
    def test_binary_change(self):
        self.binding.verify()
        (self.root / 'not-a-node-binary').write_bytes(b'OTHER BINARY')
        with self.assertRaises(Denied): self.binding.verify()
    def test_listener_owned_by_other_process(self):
        (self.proc / '1234/fd/7').unlink()
        with self.assertRaises(Denied): self.binding.verify()
    def test_wildcard_listener_denied(self):
        p = self.proc / '1234/net/tcp'; p.write_text(p.read_text().replace('0100007F', '00000000'))
        with self.assertRaises(Denied): self.binding.verify()
    def test_network_namespace_mismatch(self):
        p = self.proc / 'self/ns/net'; p.unlink(); p.symlink_to('net:[999]')
        with self.assertRaises(Denied): self.binding.verify()
    def test_genesis_symlink_denied(self):
        p = self.home / 'config/genesis.json'; p.rename(self.root / 'copy'); p.symlink_to(self.root / 'copy')
        with self.assertRaises(OSError): self.binding.verify()
    def test_home_replacement_denied(self):
        self.home.rename(self.root / 'oldhome')
        import shutil
        shutil.copytree(self.root / 'oldhome', self.home)
        with self.assertRaises(Denied): self.binding.verify()


if __name__ == '__main__': unittest.main(verbosity=2)
