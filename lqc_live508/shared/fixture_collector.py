"""Extracted historical fixture collector; NEVER live chain evidence.

Artifact resources are the public compiler fixtures shipped in tests/live508/fixtures.
Only resource locations and the event-only codec plumbing are adapted.
"""
import copy
import pathlib
import re
import subprocess
from .mock_backend import need, canonical, digest, CREATE
from .durable_journal import strict_json
from . import runtime_evidence as EVIDENCE
from lqc_live508.node_runtime import node_executable, codec_path, codec_env

ARTIFACTS = pathlib.Path(__file__).resolve().parents[2] / 'tests/live508/fixtures'

class OfflineCodec:
    """Only the event projection required by FixtureCollector; no plan/live API."""
    def __init__(self, *, fixture=False, live=False):
        need(live is False, 'live-codec-disabled')
        self.enabled = fixture is True

    def exchange(self, request):
        need(self.enabled, 'codec-default-disabled')
        need(request.get('action') == 'events', 'fixture-events-only')
        payload = canonical(dict(request, scope='FIXTURE_ONLY', live=False))
        need(len(payload) <= 4000000, 'codec-input-size')
        result = subprocess.run([node_executable(), str(codec_path('fixture_events.cjs'))],
                                input=payload, capture_output=True, timeout=10,
                                check=False, env=codec_env())
        need(result.returncode == 0 and len(result.stdout) <= 4000000, 'offline-codec-failed')
        return strict_json(result.stdout)

class FixtureCollector:
    """Strict selected evidence projection; fixtures can never become chain proof.

    bundle: operation -> pinned artifact, observed runtime/getters/receipt/block.
    All values are fixture inputs. Real immutable runtime collection is not enabled.
    """
    def __init__(self, profile, packet, bundle, codec, *, fixture=False):
        need(fixture is True and type(codec) is OfflineCodec and codec.enabled, 'collector-default-disabled')
        self.profile = copy.deepcopy(profile)
        self.packet = copy.deepcopy(packet)
        self.bundle = copy.deepcopy(bundle)
        self.pin = digest(canonical(bundle))
        self.codec = codec
        self.proofs = {}

    def verify(self, tx, txid, expected, mock_receipt):
        need(digest(canonical(self.bundle)) == self.pin, 'evidence-input-changed')
        need(tx['scope'] == 'OFFLINE_SIMULATION' and tx['operation'] not in self.proofs, 'fixture-or-duplicate-proof')
        entry = next(e for e in self.packet['entries'] if e['operation'] == tx['operation'])
        need(entry['transaction']['data'] == tx['data'] and entry['senderRole'] == tx['role'] and
             entry['transaction']['from'] == tx['from'] and entry['nonce'] == str(tx['nonce']), 'proof-envelope-link')
        p = self.bundle.get(tx['operation'])
        need(type(p) is dict and set(p) == {'scope', 'artifact', 'runtimeHex', 'getters', 'expectedGetters', 'receipt', 'block', 'requiredEvents'}, 'missing-or-extra-evidence')
        need(p['scope'] == 'SYNTHETIC_NOT_CHAIN_EVIDENCE', 'fixture-classification')
        artifact = p['artifact']
        need(digest(canonical(artifact['abi'])) == entry['abiSHA256'], 'proof-ABI-mismatch')
        # Pin every artifact against the existing compiled artifact, not an expectation
        # supplied by an untrusted RPC response.
        need(type(artifact.get('contractName')) is str and
             re.fullmatch('[A-Za-z][A-Za-z0-9_]*', artifact['contractName']), 'artifact-name-path')
        source = ARTIFACTS / (artifact['contractName'] + '.json')
        need(source.is_file() and not source.is_symlink() and strict_json(source.read_bytes()) == artifact, 'proof-artifact-mismatch')
        receipt = p['receipt']
        wire_hash = '0x' + digest(canonical(tx))  # fixture identifier, NOT Ethereum tx hash
        need(txid == 'MOCK_TX:' + wire_hash[2:] and receipt['transactionHash'] == wire_hash, 'proof-transaction-link')
        need(mock_receipt['blockNumber'] == int(receipt['blockNumber'], 16) and
             mock_receipt['blockHash'] == 'MOCK_BLOCK:' + receipt['blockHash'][2:], 'proof-mock-block-link')
        need(receipt['blockHash'] == p['block']['hash'] and receipt['blockNumber'] == p['block']['number'], 'proof-block-link')
        need(receipt['status'] == '0x1' and int(receipt['gasUsed'], 16) == mock_receipt['gasUsed'], 'proof-receipt-status-gas')
        need(int(receipt['effectiveGasPrice'], 16) == mock_receipt['effectiveGasPrice'], 'proof-fee-link')
        address = entry.get('predictedAddress') or entry['transaction']['to']
        kind = 'CREATE' if tx['operation'] in CREATE else 'CALL'
        need((receipt['contractAddress'] == address) if kind == 'CREATE' else receipt['contractAddress'] is None, 'proof-address-kind')
        runtime = bytes.fromhex(p['runtimeHex'][2:])
        template = bytes.fromhex(artifact['deployedBytecode'][2:])
        need(digest(template) == artifact['runtimeTemplateSHA256'], 'runtime-template-hash')
        # Exact template fixture match; no immutable masking or fabricated live values.
        EVIDENCE.verify_runtime(template, runtime, [], p['expectedGetters'], p['getters'])
        identity = {k: self.profile[k] for k in ('runId', 'chainId', 'genesisSHA256')}
        event_expected = {**identity, 'txHash': wire_hash, 'address': address, 'blockHash': receipt['blockHash'],
                          'blockNumber': int(receipt['blockNumber'], 16), 'requiredEvents': p['requiredEvents']}
        events = self.codec.exchange({'action': 'events', 'kind': kind, 'identity': identity,
                                      'receipt': receipt, 'expected': event_expected, 'abi': artifact['abi']})
        need(events['status'] == 'EVENTS_VERIFIED_ONLY_NOT_DEPLOYMENT_PASS', 'events-incomplete')
        proof = {**identity, 'operation': tx['operation'], 'role': tx['role'], 'nonce': tx['nonce'],
                 'scope': 'FIXTURE_ONLY_NOT_DEPLOYMENT_EVIDENCE', 'mockTxHash': txid,
                 'wireFixtureHash': wire_hash, 'address': address, 'kind': kind,
                 'block': copy.deepcopy(p['block']), 'sourceHashes': artifact['sourceHashes'],
                 'compilerSHA256': artifact['compilerSHA256'], 'abiSHA256': entry['abiSHA256'],
                 'creationSHA256': artifact['creationSHA256'], 'calldataSHA256': entry['dataSHA256'],
                 'runtimeSHA256': digest(runtime), 'receiptSHA256': digest(canonical(receipt)),
                 'eventProjection': events['projection'], 'eventsSHA256': events['eventsSHA256']}
        self.proofs[tx['operation']] = copy.deepcopy(proof)
        return proof


