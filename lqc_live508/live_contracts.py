"""Data contracts only. Hash bindings do not establish approval or chain identity."""
import copy
import re
from typing import Protocol
from lqc_live508.journal_reuse import need, canonical, digest, allowed
from lqc_live508.shared.mock_backend import CREATE

ROLES = {'deployer', 'owner', 'guardian'}
TX_FIELDS = {'runId', 'chainId', 'genesisSHA256', 'scope', 'operation', 'role',
             'from', 'to', 'data', 'nonce', 'gasLimit', 'maxFee', 'maxPriority', 'value'}


def sha(value):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value), 'SHA256-required')


def uint(value):
    need(type(value) is int and 0 <= value < 2**256, 'uint256-required')


def address(value):
    need(type(value) is str and re.fullmatch('0x[0-9a-f]{40}', value) and int(value, 16), 'address-required')


def validate_contract(contract):
    need(type(contract) is dict and set(contract) == {'schema', 'manifest', 'envelopes', 'binding'}, 'contract-fields')
    need(contract['schema'] == 'LQC_DEVNET_JOURNAL_V1', 'contract-schema')
    m, b = contract['manifest'], contract['binding']
    need(type(m) is dict and set(m) == {'runId', 'chainId', 'genesisSHA256', 'profileSHA256',
         'ABIPlanSHA256', 'roles', 'roleBudgets', 'totalBudget', 'transactions'}, 'manifest-fields')
    need(type(m['chainId']) is int and m['chainId'] == 917001, 'chain-id')
    need(type(m['runId']) is str and re.fullmatch('[0-9a-f]{32}', m['runId']), 'run-id')
    for name in ('genesisSHA256', 'profileSHA256', 'ABIPlanSHA256'):
        sha(m[name])
    need(type(b) is dict and set(b) - {'evidencePolicySHA256'} == {'approvalId', 'approvalSHA256', 'trustSHA256',
         'runEvidenceSHA256', 'journalPathSHA256', 'notBefore', 'expiresAt', 'cosmosChainId'}, 'binding-fields')
    for name in ('approvalId', 'approvalSHA256', 'trustSHA256', 'runEvidenceSHA256', 'journalPathSHA256'):
        sha(b[name])
    if 'evidencePolicySHA256' in b:
        sha(b['evidencePolicySHA256'])
    need(b['cosmosChainId'] == 'lqc-devnet-test-1', 'cosmos-chain-id')
    need(type(b['notBefore']) is int and type(b['expiresAt']) is int and
         0 <= b['notBefore'] < b['expiresAt'] <= b['notBefore'] + 240, 'approval-window')
    need(type(m['roles']) is dict and set(m['roles']) == ROLES and
         type(m['roleBudgets']) is dict and set(m['roleBudgets']) == ROLES, 'roles')
    for a in m['roles'].values():
        address(a)
    need(len(set(m['roles'].values())) == 3, 'role-separation')
    for value in [m['totalBudget'], *m['roleBudgets'].values()]:
        uint(value)
    need(type(contract['envelopes']) is list and contract['envelopes'], 'empty-plan')
    projected, seen, operations, previous_nonce = [], set(), set(), {}
    costs = dict.fromkeys(ROLES, 0)
    for tx in contract['envelopes']:
        need(type(tx) is dict and set(tx) == TX_FIELDS, 'envelope-fields')
        need(tx['scope'] == 'DEVNET_TRANSACTION_V1' and
             all(tx[k] == m[k] for k in ('runId', 'chainId', 'genesisSHA256')), 'envelope-context')
        need(type(tx['chainId']) is int and tx['role'] in ROLES and allowed(tx['role'], tx['operation']), 'role-operation')
        need(tx['from'] == m['roles'][tx['role']], 'sender')
        if tx['to'] is not None:
            address(tx['to'])
        need((tx['to'] is None) == (tx['operation'] in CREATE), 'CREATE-CALL-target')
        need(type(tx['data']) is str and re.fullmatch('0x(?:[0-9a-f]{2})+', tx['data']) and len(tx['data']) <= 262144, 'calldata')
        for k in ('nonce', 'gasLimit', 'maxFee', 'maxPriority', 'value'):
            uint(tx[k])
        need(tx['value'] == 0 and tx['gasLimit'] > 0 and tx['maxFee'] > 0 and tx['maxPriority'] <= tx['maxFee'], 'fees-value')
        role, nonce = tx['role'], tx['nonce']
        need((role, nonce) not in seen and tx['operation'] not in operations, 'duplicate-plan')
        need(role not in previous_nonce or nonce == previous_nonce[role] + 1, 'nonsequential-role-nonce')
        previous_nonce[role] = nonce
        seen.add((role, nonce)); operations.add(tx['operation'])
        cost = tx['gasLimit'] * tx['maxFee']; uint(cost)
        costs[role] += cost
        entry = {k: tx[k] for k in ('operation', 'role', 'from', 'to', 'value', 'nonce', 'gasLimit', 'maxFee', 'maxPriority')}
        entry['dataSHA256'] = digest(bytes.fromhex(tx['data'][2:]))
        projected.append(entry)
    need(canonical(projected) == canonical(m['transactions']), 'exact-approval-manifest')
    need(all(costs[r] <= m['roleBudgets'][r] for r in ROLES) and sum(costs.values()) <= m['totalBudget'], 'plan-budget')
    return copy.deepcopy(contract)


class VerificationBoundary(Protocol):
    """Future adapters MUST verify evidence, never accept caller 'verified' flags.

    authorize: actual approval/trust + Run/Genesis + current nonce/balance and
    phase checks; verify_signed: decode/recover sender and compare every field;
    verify_receipt: receipt/block/events/runtime/getters and finality;
    authorize_recovery: separately signed MANUAL_RECOVERY, exact snapshot and
    independently checked chain evidence, no resubmission permission.
    """
    def authorize(self, contract, envelope, phase): ...
    def verify_signed(self, envelope, raw): ...
    def verify_receipt(self, contract, record, evidence): ...
    def authorize_recovery(self, contract, snapshot_sha256, record, evidence, approval): ...


class UnimplementedVerification:
    def __getattr__(self, name):
        def denied(*args, **kwargs):
            need(False, 'real-verification-not-implemented:' + name)
        return denied
