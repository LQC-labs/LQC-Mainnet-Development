"""Read-only, default-disabled JSON-RPC transport and coordinator boundary.

No signing, sendRawTransaction, node startup, retry, redirects, proxy or DNS.
Tests substitute socket/observer seams; actual RPC access is not required.
"""
import copy
import http.client
import io
import math
import socket
import threading
import time
from lqc_live508.rpc_reuse import (need, canonical, digest, strict_json, validate_contract,
                   UnimplementedVerification, OfflineRPCAdapter, validate_rpc_response,
                   quantity, READS)
from lqc_live508.run_binding import endpoint

MAX_RESPONSE = 262144


def remaining(deadline, clock):
    value = deadline - clock()
    need(math.isfinite(value) and value > 0, 'RPC-deadline-expired')
    return value


class DeadlineReader(io.RawIOBase):
    """Absolute deadline on every OS read, including trickled HTTP headers."""
    def __init__(self, sock, deadline, clock):
        super().__init__()
        self.sock, self.deadline, self.clock = sock, deadline, clock
        self.count = 0

    def readable(self):
        return True

    def readinto(self, buffer):
        self.sock.settimeout(remaining(self.deadline, self.clock))
        chunk = self.sock.recv(min(len(buffer), MAX_RESPONSE + 65536 + 1 - self.count))
        self.count += len(chunk)
        need(self.count <= MAX_RESPONSE + 65536, 'HTTP-wire-size-limit')
        buffer[:len(chunk)] = chunk
        return len(chunk)


class ResponseSocket:
    def __init__(self, sock, deadline, clock):
        self.sock, self.deadline, self.clock = sock, deadline, clock

    def makefile(self, mode):
        need(mode == 'rb', 'HTTP-reader-mode')
        return io.BufferedReader(DeadlineReader(self.sock, self.deadline, self.clock))


class LoopbackTransport:
    def __init__(self, approved_url, *, enabled=False, clock=time.monotonic, socket_factory=None):
        self.target = endpoint(approved_url)
        self.url = approved_url
        self._approved_url, self._approved_target = approved_url, self.target
        self.enabled = enabled is True
        self.clock = clock
        self.factory = socket_factory if socket_factory is not None else socket.socket
        self.halted = False

    def _validate_request(self, request):
        need(type(request) is dict and set(request) == {'jsonrpc', 'id', 'method', 'params'} and
             request['jsonrpc'] == '2.0' and type(request['id']) is int and request['id'] > 0 and
             request['method'] in self._allowed_methods() and type(request['params']) is list, 'transport-read-method-only')

    def _allowed_methods(self):
        return READS

    def _before_send(self, request):
        """Subclass boundary; default transport remains read-only."""
        return None

    def exchange(self, raw_request, *, deadline):
        sock, response = None, None
        try:
            need(self.enabled and not self.halted, 'transport-disabled-or-HALTED')
            need(self.url == self._approved_url and endpoint(self.url) == self.target == self._approved_target, 'transport-target-changed')
            need(type(raw_request) is bytes and len(raw_request) <= MAX_RESPONSE, 'request-size')
            request = strict_json(raw_request)
            self._validate_request(request)
            remaining(deadline, self.clock)
            sock = self.factory(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(remaining(deadline, self.clock))
            # Numeric AF_INET address; no resolver or environment proxy handling.
            sock.connect(self.target)
            peer = sock.getpeername()
            need(peer == self.target, 'RPC-peer-mismatch')
            headers = (f'POST / HTTP/1.1\r\nHost: 127.0.0.1:{self.target[1]}\r\n'
                       'Content-Type: application/json\r\nAccept: application/json\r\n'
                       f'Content-Length: {len(raw_request)}\r\nConnection: close\r\n\r\n').encode('ascii')
            sock.settimeout(remaining(deadline, self.clock))
            self._before_send(request)
            sock.settimeout(remaining(deadline, self.clock))
            sock.sendall(headers + raw_request)
            response = http.client.HTTPResponse(ResponseSocket(sock, deadline, self.clock))
            response.begin()
            remaining(deadline, self.clock)
            lengths = response.headers.get_all('Content-Length', [])
            transfers = response.headers.get_all('Transfer-Encoding', [])
            need(len(lengths) <= 1 and len(transfers) <= 1 and not (lengths and transfers), 'ambiguous-HTTP-framing')
            if lengths:
                need(lengths[0].isascii() and lengths[0].isdigit() and int(lengths[0]) <= MAX_RESPONSE, 'HTTP-content-length-limit')
            if transfers:
                need(transfers == ['chunked'], 'unsupported-transfer-encoding')
            need(response.headers.get('Content-Encoding', 'identity') == 'identity', 'compressed-response-disabled')
            body = response.read(MAX_RESPONSE + 1)
            remaining(deadline, self.clock)
            need(len(body) <= MAX_RESPONSE and (not lengths or len(body) == int(lengths[0])), 'HTTP-body-size-or-truncation')
            need(sock.getpeername() == self.target, 'RPC-peer-changed')
            return {'status': response.status, 'body': body, 'target': self.url, 'peer': peer}
        except BaseException:
            self.halted = True
            raise
        finally:
            try:
                if response is not None:
                    response.close()
            finally:
                if sock is not None:
                    sock.close()


class LiveRPC:
    def __init__(self, binding, transport=None, *, enabled=False, request_timeout=5,
                 run_timeout=240, clock=time.monotonic):
        need(type(request_timeout) in (int, float) and math.isfinite(request_timeout) and 0 < request_timeout <= 30,
             'request-timeout-bounds')
        need(type(run_timeout) in (int, float) and math.isfinite(run_timeout) and 0 < run_timeout <= 240, 'run-timeout-bounds')
        self.binding = binding
        self.transport = transport if transport is not None else LoopbackTransport(binding.url)
        self.enabled = enabled is True
        self.clock, self.request_timeout = clock, request_timeout
        self.deadline = clock() + run_timeout
        self.url = binding.url
        self.contract = validate_contract(binding.contract)
        self.pin = digest(canonical(self.contract))
        self.profile = copy.deepcopy(self.contract['manifest'])
        self.targets = {t['to'] for t in self.contract['envelopes'] if t['to'] is not None}
        self.counter, self.diagnostics = 0, []
        self.halted = False
        self.halt_persistence_error = False
        self.coordinator = None
        self.lock = threading.RLock()

    def attach_coordinator(self, coordinator):
        need(self.coordinator is None and digest(canonical(coordinator.journal.contract)) == self.pin and
             getattr(coordinator.verification, 'rpc', None) is self, 'coordinator-binding')
        self.coordinator = coordinator
        if self.halted:
            self._halt()

    def _halt(self):
        self.halted = self.binding.halted = True
        # Also prevent standalone transport reuse after a binding/response failure.
        self.transport.halted = True
        if self.coordinator is not None:
            try:
                self.coordinator.halt()
            except BaseException:
                self.halt_persistence_error = True

    def _guard(self):
        need(self.enabled and not self.halted and not self.binding.halted, 'RPC-disabled-or-HALTED')
        need(digest(canonical(self.contract)) == self.pin == self.binding.contract_pin and
             canonical(self.profile) == canonical(self.contract['manifest']) and self.url == self.binding.url == self.transport.url,
             'RPC-binding-or-target-changed')
        need(self.targets == self._approved_targets(), 'RPC-target-allowlist-changed')
        if self.coordinator is not None:
            c = self.coordinator
            need(not c.halted and not c.journal.poisoned and not c.journal.closed and
                 not c.journal.payload['halted'], 'coordinator-HALTED')
            self._check_read_window(c)
        remaining(self.deadline, self.clock)

    def _approved_targets(self):
        return {t['to'] for t in self.contract['envelopes'] if t['to'] is not None}

    def _check_read_window(self, c):
        now, b = c.clock(), self.contract['binding']
        need(type(now) is int and b['notBefore'] <= now < b['expiresAt'] and
             (c.last_time is None or now >= c.last_time), 'approval-expired-during-RPC')

    def _validate_params(self, method, params):
        OfflineRPCAdapter._params(self, method, params)

    def _validate_response(self, method, params, rid, reply, diagnostic):
        return validate_rpc_response(method, params, rid, reply['status'], reply['body'], diagnostic)

    def _transport_exchange(self, raw_request, *, deadline):
        return self.transport.exchange(raw_request, deadline=deadline)

    def _exchange(self, method, params):
        self._guard()
        # Exact existing method/parameter/address validator, not a duplicate parser.
        self._validate_params(method, params)
        self.binding.verify()
        self._guard()
        self.counter += 1
        rid = self.counter
        diagnostic = {'requestId': rid, 'method': method, 'destination': self.url,
                      'httpStatus': None, 'outcome': 'ERROR_NO_RETRY'}
        try:
            deadline = min(self.deadline, self.clock() + self.request_timeout)
            reply = self._transport_exchange(canonical({'jsonrpc': '2.0', 'id': rid, 'method': method, 'params': params}), deadline=deadline)
            remaining(deadline, self.clock)
            self._guard()
            need(type(reply) is dict and set(reply) == {'status', 'body', 'target', 'peer'} and
                 reply['target'] == self.url and reply['peer'] == endpoint(self.url), 'RPC-response-target-mismatch')
            diagnostic['httpStatus'] = reply['status']
            value = self._validate_response(method, params, rid, reply, diagnostic)
            self.binding.verify()
            self._guard()
            remaining(deadline, self.clock)
            diagnostic['outcome'] = 'MISSING_PENDING_NOT_PASS' if value is None else 'VALIDATED_READ_NOT_DEPLOYMENT_PROOF'
            return value
        finally:
            self.diagnostics.append(diagnostic)
            self.diagnostics = self.diagnostics[-256:]

    def _run(self, fn):
        # Coordinator owns the outer lock during authorize(); preserve lock order
        # when a direct RPC call needs to durably halt that same coordinator.
        outer = self.coordinator.journal.mutex if self.coordinator is not None else self.lock
        with outer, self.lock:
            try:
                return fn()
            except BaseException:
                self._halt()
                raise

    def request(self, method, params):
        def action():
            # Validate BEFORE chain probes: a forbidden method sends nothing.
            self._guard()
            self._validate_params(method, params)
            if method == 'eth_chainId':
                return self._exchange(method, params)
            self._exchange('eth_chainId', [])
            result = self._exchange(method, params)
            self._exchange('eth_chainId', [])
            return result
        return self._run(action)

    def read_context(self):
        def action():
            self.request('eth_chainId', [])
            result = self.binding.verify()
            self._guard()
            return result
        return self._run(action)

    def read_nonce(self, role, expected=None):
        def action():
            need(role in self.profile['roles'], 'unapproved-role')
            address = self.profile['roles'][role]
            latest = quantity(self.request('eth_getTransactionCount', [address, 'latest']))
            pending = quantity(self.request('eth_getTransactionCount', [address, 'pending']))
            latest_after = quantity(self.request('eth_getTransactionCount', [address, 'latest']))
            need(latest == pending == latest_after, 'nonce-conflict-or-changed')
            if expected is not None:
                need(type(expected) is int and expected >= 0 and latest == expected, 'approved-nonce-mismatch')
            return latest, pending
        return self._run(action)

    def check_transaction(self, contract, tx):
        def action():
            need(digest(canonical(contract)) == self.pin and canonical(tx) in
                 [canonical(t) for t in self.contract['envelopes']], 'RPC-exact-contract-envelope')
            self.read_context()
            self.read_nonce(tx['role'], tx['nonce'])
            balance = quantity(self.request('eth_getBalance', [tx['from'], 'latest']))
            need(balance >= tx['gasLimit'] * tx['maxFee'], 'insufficient-observed-balance')
            self.binding.verify()
            self._guard()
            return True
        return self._run(action)

    def status(self):
        return {'operationalState': 'HALTED' if self.halted else 'READ_LAYER_ONLY',
                'haltPersistenceError': self.halt_persistence_error, 'executionEnabled': False,
                'official5.08': 'BLOCKED', 'mainnet': 'NO-GO'}


class RPCBoundVerification:
    """Compose RPC preflight with actual authority/signature/evidence verification.

    The delegate is mandatory for success and defaults to denial. RPC success
    never stands in for approval, signature verification or deployment evidence.
    """
    def __init__(self, rpc, delegate=None):
        self.rpc = rpc
        self.delegate = delegate if delegate is not None else UnimplementedVerification()

    def authorize(self, contract, envelope, phase):
        need(phase in {'before-sign', 'before-signer-dispatch', 'accept-signed-result', 'before-submit', 'before-wire'}, 'unknown-authorization-phase')
        need(self.delegate.authorize(contract, envelope, phase) is True, 'approval-not-verified')
        need(self.rpc.check_transaction(contract, envelope) is True, 'RPC-preflight-not-verified')
        # Authorization delegates must be read-only/idempotent. Detect trust or
        # revocation changes during preflight before allowing the next boundary.
        need(self.delegate.authorize(contract, envelope, phase) is True, 'approval-changed-after-RPC')
        return True

    def verify_signed(self, envelope, raw):
        return self.delegate.verify_signed(envelope, raw)

    def verify_receipt(self, contract, record, evidence):
        return self.delegate.verify_receipt(contract, record, evidence)

    def authorize_recovery(self, contract, snapshot, record, evidence, approval):
        return self.delegate.authorize_recovery(contract, snapshot, record, evidence, approval)
