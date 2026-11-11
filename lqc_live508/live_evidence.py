from lqc_live508.node_runtime import node_executable, codec_path, codec_env
"""Collect block-hash-pinned evidence, reusing ABI/runtime/RPC validators."""
import copy
import pathlib
import subprocess
import time
from contextlib import contextmanager
from lqc_live508.execution_reuse import (need, canonical, digest, quantity, hexdata, public_address,
    validate_rpc_response, validate_rpc_envelope, LiveRPC, verify_runtime, remaining)
from lqc_live508.shared.durable_journal import strict_json


class EvidenceCodec:
    def __init__(self): self.cache = {}
    def call(self, value):
        raw = canonical(value); need(len(raw) <= 4000000, 'evidence-codec-input-limit')
        key = digest(raw)
        if key not in self.cache:
            result = subprocess.run([node_executable(), str(codec_path('evidence_codec.cjs'))],
                                    input=raw, capture_output=True, timeout=10, check=False,
                                    env=codec_env())
            need(result.returncode == 0 and len(result.stdout) <= 4000000, 'evidence-codec-rejected')
            value = strict_json(result.stdout)
            if len(self.cache) >= 32: self.cache.clear()
            self.cache[key] = canonical(value)
        return strict_json(self.cache[key])


class EvidencePolicy:
    def __init__(self, contract, policy, codec=None):
        self.contract, self.document = copy.deepcopy(contract), copy.deepcopy(policy)
        self.pin = digest(canonical(policy))
        need(contract['binding'].get('evidencePolicySHA256') == self.pin, 'unapproved-evidence-policy')
        need(type(policy) is dict and set(policy) == {'schema', 'confirmations', 'pollLimit', 'pollIntervalMs', 'artifacts', 'operations'} and
             policy['schema'] == 'LQC_EVIDENCE_POLICY_V1', 'evidence-policy-schema')
        for k, lo, hi in [('confirmations', 1, 12), ('pollLimit', 1, 100), ('pollIntervalMs', 1, 1000)]:
            need(type(policy[k]) is int and lo <= policy[k] <= hi, 'evidence-policy-limits')
        need(type(policy['artifacts']) is dict and policy['artifacts'], 'missing-artifacts')
        for key, a in policy['artifacts'].items():
            need(key == digest(canonical(a)), 'artifact-content-address')
            need(type(a['abi']) is list and a['abiSHA256'] == digest(canonical(a['abi'])), 'artifact-ABI-pin')
            for data, hash_name in [('bytecode', 'creationSHA256'), ('deployedBytecode', 'runtimeTemplateSHA256')]:
                hexdata(a[data]); need(a[data] != '0x' and digest(bytes.fromhex(a[data][2:])) == a[hash_name], 'artifact-bytecode-pin')
            need(type(a['sourceHashes']) is dict and a['sourceHashes'], 'artifact-source-pins')
            for h in [a['compilerSHA256'], *a['sourceHashes'].values()]:
                need(type(h) is str and len(h) == 64 and bytes.fromhex(h).hex() == h, 'artifact-source-compiler-hash')
        need(set(policy['operations']) == {tx['operation'] for tx in contract['envelopes']}, 'operation-evidence-coverage')
        self.codec = codec if codec is not None else EvidenceCodec()
        self.prepared = {}
        for tx in contract['envelopes']:
            op = policy['operations'][tx['operation']]
            need(set(op) == {'kind', 'target', 'constructorArgs', 'call', 'contracts'}, 'operation-policy-fields')
            public_address(op['target'])
            need(type(op['contracts']) is list and op['contracts'], 'operation-contracts')
            addresses = set()
            for c in op['contracts']:
                need(set(c) == {'address', 'artifactId', 'getters', 'immutableGetters', 'events'}, 'contract-evidence-fields')
                public_address(c['address']); need(c['address'] not in addresses, 'duplicate-contract'); addresses.add(c['address'])
                need(c['artifactId'] in policy['artifacts'], 'unknown-artifact')
                a = policy['artifacts'][c['artifactId']]
                need(type(c['immutableGetters']) is dict and set(c['immutableGetters']) == set(a['immutableReferences']), 'immutable-map-coverage')
                names = set()
                for g in c['getters']:
                    need(set(g) == {'name', 'function', 'args', 'expected', 'gas'} and type(g['name']) is str and g['name'] not in names and
                         type(g['gas']) is int and 0 < g['gas'] <= 10000000, 'getter-policy')
                    names.add(g['name'])
                need(set(c['immutableGetters'].values()) <= names, 'immutable-getter-missing')
            self.prepared[tx['operation']] = self.codec.call({'action': 'plan', 'tx': tx, 'operation': op, 'artifacts': policy['artifacts']})
        self._prepared_pin, self._contract_pin = digest(canonical(self.prepared)), digest(canonical(self.contract))
    def check(self):
        need(digest(canonical(self.document)) == self.pin == self.contract['binding']['evidencePolicySHA256'], 'evidence-policy-mutated')
        need(digest(canonical(self.prepared)) == self._prepared_pin and digest(canonical(self.contract)) == self._contract_pin, 'prepared-policy-mutated')
    def operation(self, name): self.check(); return self.document['operations'][name]


class EvidenceRPC(LiveRPC):
    """Additional reads are scoped to one collected transaction and approved ABI."""
    def __init__(self, binding, policy, *args, **kwargs):
        self.policy, self.observation, self.write_record = policy, None, None
        self.write_attempts = set()
        self._capability_issued = set()
        super().__init__(binding, *args, **kwargs)
        need(digest(canonical(policy.contract)) == self.pin, 'RPC-policy-contract')
        self.targets = self._approved_targets()
    def _approved_targets(self):
        self.policy.check()
        return {c['address'] for op in self.policy.document['operations'].values() for c in op['contracts']}
    def _check_read_window(self, c):
        if self.observation is None: super()._check_read_window(c)
        # Already submitted observation can finish after approval expiry; it
        # cannot use write/preflight methods and still has the global deadline.
    def _validate_params(self, method, params):
        need(type(params) is list, 'RPC-params-list')
        scope = self.observation
        if method == 'eth_sendRawTransaction':
            need(scope is None and self.write_record is not None and params == [self.write_record['rawTransactionHex']], 'unbound-raw-submission')
            return
        if scope is not None:
            need(method in {'eth_chainId', 'eth_getTransactionByHash', 'eth_getTransactionReceipt', 'eth_getBlockByNumber', 'eth_getCode', 'eth_call'}, 'observation-read-only')
        if method in ('eth_getTransactionByHash', 'eth_getTransactionReceipt'):
            need(scope is not None and params == [scope['record']['txHash']], 'transaction-read-scope')
            return
        if method in ('eth_getCode', 'eth_call'):
            need(scope is not None and len(params) == 2 and scope['tag'] is not None and params[1] == scope['tag'], 'receipt-block-hash-required')
            if method == 'eth_getCode':
                need(params[0] in scope['prepared']['contracts'], 'unapproved-code-target')
            else:
                approved = []
                for address, c in scope['prepared']['contracts'].items():
                    for q in c['queries']:
                        approved.append({'from': scope['record']['envelope']['from'], 'to': address, 'value': '0x0', 'data': q['data'], 'gas': q['gas']})
                need(params[0] in approved, 'unapproved-getter-call')
            return
        return super()._validate_params(method, params)
    def _validate_response(self, method, params, rid, reply, diagnostic):
        if method == 'eth_getBlockByNumber' and self.observation is not None:
            if validate_rpc_envelope(rid, reply['status'], reply['body'], diagnostic) is None: return None
        if method in ('eth_getTransactionByHash', 'eth_call', 'eth_sendRawTransaction'):
            value = validate_rpc_envelope(rid, reply['status'], reply['body'], diagnostic)
            if method == 'eth_sendRawTransaction': hexdata(value, 32)
            elif method == 'eth_call': hexdata(value)
            elif value is not None:
                need(type(value) is dict and value.get('hash') == params[0], 'transaction-query-hash')
            return value
        return validate_rpc_response(method, params, rid, reply['status'], reply['body'], diagnostic, allow_revert=True)
    @contextmanager
    def observe(self, record):
        need(self.observation is None and self.write_record is None, 'nested-observation')
        self.observation = {'record': copy.deepcopy(record), 'prepared': self.policy.prepared[record['envelope']['operation']], 'tag': None}
        try: yield self.observation
        finally: self.observation = None
    def _transport_exchange(self, raw_request, *, deadline):
        request = strict_json(raw_request)
        if request['method'] == 'eth_sendRawTransaction':
            return self.transport._dispatch(raw_request, deadline=deadline, capability=self._write_capability)
        return super()._transport_exchange(raw_request, deadline=deadline)
    def send_once(self, record):
        def action():
            need(self.write_record is None and self.observation is None and record['state'] == 'SUBMIT_INTENT', 'write-phase')
            c = self.coordinator
            key = record['envelope']['role'] + ':' + str(record['envelope']['nonce'])
            need(c is not None and getattr(c.verification, 'rpc', None) is self and
                 digest(canonical(c.journal.contract)) == self.pin and key not in self.write_attempts and
                 c.journal.recover()['records'][key] == record, 'write-durable-coordinator-binding')
            self.write_attempts.add(key)
            self.write_record = copy.deepcopy(record)
            try:
                self._write_capability = self.transport._issue_for(self, record)
                return self._exchange('eth_sendRawTransaction', [record['rawTransactionHex']])
            finally:
                self.write_record = None
                self._write_capability = None
        return self._run(action)


class LiveEvidence:
    def __init__(self, rpc, policy, evm_verifier, *, sleeper=time.sleep):
        need(rpc.policy is policy, 'collector-policy-binding')
        self.rpc, self.policy, self.evm, self.sleeper = rpc, policy, evm_verifier, sleeper
        self.tickets = set()
        self.last_cost = None
    def _request(self, method, params): return self.rpc.request(method, params)
    def _cost_and_chain(self, record, tx, receipt, blocks):
        env, h = record['envelope'], record['txHash']
        signed = self.evm.verify(env, bytes.fromhex(record['rawTransactionHex'][2:]))
        need(signed['txHash'] == h and tx['hash'] == h == receipt['transactionHash'], 'transaction-evidence-hash')
        for field, expected in [('chainId', env['chainId']), ('nonce', env['nonce']), ('value', env['value']),
                                ('gas', env['gasLimit']), ('maxFeePerGas', env['maxFee']), ('maxPriorityFeePerGas', env['maxPriority']), ('type', 2)]:
            need(quantity(tx[field]) == expected, 'queried-transaction-field:' + field)
        need(tx['from'] == env['from'] and tx['to'] == env['to'] and tx['input'] == env['data'], 'queried-transaction-envelope')
        need(receipt['from'] == env['from'] and receipt['to'] == env['to'], 'receipt-sender-target')
        height, index, status = quantity(receipt['blockNumber']), quantity(receipt['transactionIndex']), quantity(receipt['status'])
        need(status in (0, 1) and height > 0 and tx['blockHash'] == receipt['blockHash'] and
             tx['blockNumber'] == receipt['blockNumber'] and tx['transactionIndex'] == receipt['transactionIndex'], 'mined-transaction-link')
        need(len(blocks) == self.policy.document['confirmations'], 'confirmation-count')
        for i, block in enumerate(blocks):
            need(quantity(block['number']) == height + i, 'confirmation-height')
            hexdata(block['hash'], 32); hexdata(block['parentHash'], 32)
            if i: need(block['parentHash'] == blocks[i - 1]['hash'], 'confirmation-parent')
        block = blocks[0]
        need(block['hash'] == receipt['blockHash'] and type(block['transactions']) is list and
             index < len(block['transactions']) and block['transactions'][index] == h and block['transactions'].count(h) == 1, 'receipt-block-inclusion')
        op = self.policy.operation(env['operation'])
        expected_address = op['target'] if op['kind'] == 'CREATE' else None
        need(receipt['contractAddress'] == expected_address if status == 1 else
             receipt['contractAddress'] in ((None, expected_address) if op['kind'] == 'CREATE' else (None,)), 'CREATE-CALL-receipt-address')
        used, price, base = quantity(receipt['gasUsed']), quantity(receipt['effectiveGasPrice']), quantity(block['baseFeePerGas'])
        need(0 < used <= env['gasLimit'] and used <= quantity(block['gasLimit']) and base <= env['maxFee'] and
             price == min(env['maxFee'], base + env['maxPriority']), 'actual-cost-or-fee-mismatch')
        logs = receipt['logs']; seen = set()
        need(type(logs) is list and (status == 1 or logs == []), 'revert-must-have-no-logs')
        for log in logs:
            need(log['transactionHash'] == h and log['blockHash'] == receipt['blockHash'] and
                 log['blockNumber'] == receipt['blockNumber'] and log['transactionIndex'] == receipt['transactionIndex'] and
                 log['removed'] is False, 'log-transaction-block-link')
            li = quantity(log['logIndex']); need(li not in seen, 'duplicate-global-log-index'); seen.add(li)
        return {'transactionHash': h, 'blockHash': receipt['blockHash'], 'blockNumber': height,
                'status': status, 'gasUsed': used, 'effectiveGasPrice': price}
    def _runtime(self, c, observation, decoded):
        artifact = self.policy.document['artifacts'][c['artifactId']]
        actual = bytes.fromhex(observation['runtimeCode'][2:]); template = bytes.fromhex(artifact['deployedBytecode'][2:])
        refs, expected, observed = [], {}, {}
        for compiler_id, entries in artifact['immutableReferences'].items():
            name = c['immutableGetters'][compiler_id]; value = decoded[name]
            expected[name], observed[name] = value['expected'], value['value']
            encoded = bytes.fromhex(value['raw'][2:])
            need(len(encoded) == 32, 'immutable-getter-must-be-one-word')
            for ref in entries:
                need(set(ref) == {'start', 'length'} and type(ref['start']) is int and type(ref['length']) is int and ref['length'] == 32,
                     'compiler-immutable-reference-shape')
                need(actual[ref['start']:ref['start'] + 32] == encoded, 'immutable-literal-getter-mismatch')
                refs.append({**ref, 'getter': name})
        verify_runtime(template, actual, refs, expected, observed)
    def verify(self, record, evidence, *, require_ticket=True):
        self.policy.check()
        need(set(evidence) == {'schema', 'identity', 'operation', 'policySHA256', 'transaction', 'receipt', 'blocks', 'observations', 'projection'} and
             evidence['schema'] == 'LQC_LIVE_EVIDENCE_V1' and evidence['policySHA256'] == self.policy.pin and
             evidence['identity'] == {k: record['envelope'][k] for k in ('runId', 'chainId', 'genesisSHA256')} and
             evidence['operation'] == record['envelope']['operation'], 'evidence-context')
        if require_ticket: need(digest(canonical(evidence)) in self.tickets, 'evidence-not-collected-by-bound-reader')
        summary = self._cost_and_chain(record, evidence['transaction'], evidence['receipt'], evidence['blocks'])
        op = self.policy.operation(evidence['operation'])
        if summary['status'] == 1:
            need(set(evidence['observations']) == {c['address'] for c in op['contracts']}, 'runtime-getter-coverage')
            expected_tag = {'blockHash': summary['blockHash'], 'requireCanonical': True}
            for c in op['contracts']:
                obs = evidence['observations'][c['address']]
                need(set(obs) == {'blockSelector', 'runtimeCode', 'getters'} and obs['blockSelector'] == expected_tag and
                     set(obs['getters']) == {g['name'] for g in c['getters']}, 'observation-block-or-getters')
                hexdata(obs['runtimeCode'])
            projection = self.policy.codec.call({'action': 'verify', 'tx': record['envelope'], 'operation': op,
                'artifacts': self.policy.document['artifacts'], 'identity': evidence['identity'],
                'receipt': evidence['receipt'], 'observations': evidence['observations']})
            need(canonical(projection) == canonical(evidence['projection']), 'evidence-projection-changed')
            for c in op['contracts']: self._runtime(c, evidence['observations'][c['address']], projection['getters'][c['address']])
        else:
            need(evidence['observations'] == {} and evidence['projection'] == {}, 'revert-not-success-evidence')
        return summary
    def collect(self, record):
        self.last_cost = None
        self.policy.check()
        with self.rpc.observe(record) as scope:
            self.rpc.binding.verify()
            tx = receipt = None
            for attempt in range(self.policy.document['pollLimit']):
                receipt = self._request('eth_getTransactionReceipt', [record['txHash']])
                tx = self._request('eth_getTransactionByHash', [record['txHash']])
                if receipt is not None and tx is not None and tx.get('blockHash') is not None: break
                if attempt + 1 < self.policy.document['pollLimit']:
                    self.sleeper(self.policy.document['pollIntervalMs'] / 1000)
            need(receipt is not None and tx is not None and tx.get('blockHash') is not None, 'receipt-observation-timeout')
            height = quantity(receipt['blockNumber'])
            blocks = []
            for attempt in range(self.policy.document['pollLimit']):
                blocks = [self._request('eth_getBlockByNumber', [hex(height + i), False]) for i in range(self.policy.document['confirmations'])]
                if all(b is not None for b in blocks): break
                if attempt + 1 < self.policy.document['pollLimit']: self.sleeper(self.policy.document['pollIntervalMs'] / 1000)
            need(all(b is not None for b in blocks), 'confirmation-observation-timeout')
            summary = self._cost_and_chain(record, tx, receipt, blocks)
            identity = {k: record['envelope'][k] for k in ('runId', 'chainId', 'genesisSHA256')}
            self.last_cost = {'summary': summary, 'evidence': {'schema': 'LQC_EXECUTION_COST_ONLY_V1', 'identity': identity,
                'policySHA256': self.policy.pin, 'transaction': tx, 'receipt': receipt, 'blocks': blocks}}
            scope['tag'] = {'blockHash': receipt['blockHash'], 'requireCanonical': True}
            observations, projection = {}, {}
            op = self.policy.operation(record['envelope']['operation'])
            if summary['status'] == 1:
                for c in op['contracts']:
                    address = c['address']; getters = {}
                    code = self._request('eth_getCode', [address, scope['tag']])
                    for q in scope['prepared']['contracts'][address]['queries']:
                        call = {'from': record['envelope']['from'], 'to': address, 'value': '0x0', 'data': q['data'], 'gas': q['gas']}
                        getters[q['name']] = self._request('eth_call', [call, scope['tag']])
                    observations[address] = {'blockSelector': copy.deepcopy(scope['tag']), 'runtimeCode': code, 'getters': getters}
                projection = self.policy.codec.call({'action': 'verify', 'tx': record['envelope'], 'operation': op,
                    'artifacts': self.policy.document['artifacts'], 'identity': identity, 'receipt': receipt, 'observations': observations})
            # Re-read every anchor after code/getter collection. Explicit conflict
            # invalidates even the candidate cost; absence/errors remain uncertain.
            final_receipt = self._request('eth_getTransactionReceipt', [record['txHash']])
            final_tx = self._request('eth_getTransactionByHash', [record['txHash']])
            final_blocks = [self._request('eth_getBlockByNumber', [hex(height + i), False]) for i in range(len(blocks))]
            if canonical([receipt, tx, blocks]) != canonical([final_receipt, final_tx, final_blocks]):
                self.last_cost = None; need(False, 'evidence-anchor-changed')
            evidence = {'schema': 'LQC_LIVE_EVIDENCE_V1', 'identity': identity, 'operation': record['envelope']['operation'],
                        'policySHA256': self.policy.pin, 'transaction': tx, 'receipt': receipt, 'blocks': blocks,
                        'observations': observations, 'projection': projection}
            self.verify(record, evidence, require_ticket=False)
            self.rpc.binding.verify(); self.rpc._guard()
            self.tickets.add(digest(canonical(evidence)))
            return evidence
