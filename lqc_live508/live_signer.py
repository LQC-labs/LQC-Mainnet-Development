from lqc_live508.node_runtime import node_executable, codec_path, codec_env
"""Approved signer interface and public EVM verification, with no key backend.

Ed25519 deployment authorization is handled by live_authority_binding, never by
this EIP-1559/secp256k1 decoder. Production signer ports remain unimplemented.
"""
import copy
import pathlib
import re
import subprocess
import time
from collections import OrderedDict
from typing import Protocol
from lqc_live508.authority_reuse import need, canonical, digest
from lqc_live508.shared.durable_journal import strict_json


class EVMTransactionVerifier:
    """Recover supplied bytes using existing ethers. Never generate a signature."""
    def __init__(self):
        self._cache = OrderedDict()

    def decode(self, raw):
        need(type(raw) is bytes and 0 < len(raw) <= 131000, 'signed-raw-size-or-type')
        if raw not in self._cache:
            result = subprocess.run([node_executable(), str(codec_path('evm_transaction_codec.cjs'))],
                                    input=canonical({'rawTransactionHex': '0x' + raw.hex()}), capture_output=True,
                                    timeout=10, check=False, env=codec_env())
            need(result.returncode == 0 and len(result.stdout) <= 270000, 'EVM-signature-decode-recovery-failed')
            decoded = strict_json(result.stdout)
            need(type(decoded) is dict and set(decoded) == {'schema', 'type', 'sender', 'chainId', 'nonce',
                 'to', 'value', 'data', 'gasLimit', 'maxFee', 'maxPriority', 'accessList', 'txHash', 'evmSigningHash'} and
                 decoded['schema'] == 'LQC_EVM_RECOVERY_V1' and type(decoded['type']) is int and
                 decoded['type'] == 2 and decoded['accessList'] == [], 'EVM-codec-result-schema')
            for k in ('chainId', 'nonce', 'value', 'gasLimit', 'maxFee', 'maxPriority'):
                need(type(decoded[k]) is str and re.fullmatch('0|[1-9][0-9]*', decoded[k]) and int(decoded[k]) < 2**256, 'EVM-codec-integer')
            for k in ('txHash', 'evmSigningHash'):
                need(type(decoded[k]) is str and re.fullmatch('0x[0-9a-f]{64}', decoded[k]), 'EVM-codec-hash')
            self._cache[raw] = canonical(decoded)
            if len(self._cache) > 32:
                self._cache.popitem(last=False)
        return strict_json(self._cache[raw])

    def verify(self, envelope, raw):
        decoded = self.decode(raw)
        need(envelope['scope'] == 'DEVNET_TRANSACTION_V1' and type(envelope['chainId']) is int and
             envelope['chainId'] == 917001 and decoded['sender'] == envelope['from'], 'EVM-sender-or-scope-mismatch')
        for key in ('chainId', 'nonce', 'value', 'gasLimit', 'maxFee', 'maxPriority'):
            need(type(envelope[key]) is int and 0 <= envelope[key] < 2**256 and
                 decoded[key] == str(envelope[key]), 'EVM-field-mismatch:' + key)
        for key in ('to', 'data'):
            need(decoded[key] == envelope[key], 'EVM-field-mismatch:' + key)
        return decoded


class SignerPort(Protocol):
    """Trusted integration must honor deadline and return immutable raw bytes.

    It receives a COPY of the exact approved unsigned envelope; never an
    approval private key, RPC URL, arbitrary command, or caller-selected key path.
    No actual port implementation is provided here.
    """
    def request_signature(self, approved_envelope: dict, *, deadline: float) -> bytes: ...


class UnavailableSigner:
    def request_signature(self, approved_envelope, *, deadline):
        need(False, 'real-signer-port-not-implemented')


class LiveSigner:
    def __init__(self, coordinator, authority, port=None, *, enabled=False, timeout=10, clock=time.monotonic):
        need(type(timeout) in (int, float) and 0 < timeout <= 30, 'signer-timeout-bounds')
        self.coordinator, self.authority = coordinator, authority
        self.port = port if port is not None else UnavailableSigner()
        self.enabled = enabled is True
        self.timeout, self.clock = timeout, clock

    def _wiring(self):
        c, a = self.coordinator, self.authority
        rpc = getattr(c.verification, 'rpc', None)
        need(self.enabled and a.coordinator is c and getattr(c.verification, 'delegate', None) is a and
             rpc is not None and rpc.coordinator is c and rpc.binding is a.run_binding and
             a.journal is c.journal, 'signer-disabled-or-unbound')

    def sign_operation(self, approved_envelope):
        """One call after SIGN_REQUESTED commit; no retries or broadcast."""
        c = self.coordinator
        def action():
            self._wiring()
            tx = copy.deepcopy(approved_envelope)
            key = c.begin(tx)
            # Separate boundary immediately before invoking an eventual provider.
            c._check(tx, 'before-signer-dispatch')
            deadline = self.clock() + self.timeout
            raw = self.port.request_signature(copy.deepcopy(tx), deadline=deadline)
            need(self.clock() < deadline, 'signer-result-timeout')
            need(type(raw) is bytes, 'immutable-signer-result-required')
            txhash = c.record_signed(key, raw)
            record = c.journal.recover()['records'][key]
            need(record['state'] == 'SIGNED' and record['txHash'] == txhash, 'signed-result-not-durable')
            return {'journalKey': key, 'txHash': txhash, 'unsignedSHA256': record['unsignedSHA256']}
        try:
            return c._run(action)
        except BaseException:
            self.authority.halt()
            raise

    def prepare_submission(self, key):
        """Persist intent and return bytes; never submit them."""
        c = self.coordinator
        def action():
            self._wiring()
            return c.prepare_submission(key)
        try:
            return c._run(action)
        except BaseException:
            self.authority.halt()
            raise
