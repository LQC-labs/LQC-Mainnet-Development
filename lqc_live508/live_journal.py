"""Single authoritative commit journal. No signing, sending, or network support.

Reuses Journal._new_file/_safe_file/_guard/_atomic/close unchanged. A commit is
journal.json replacement followed by directory fsync; no second checkpoint.
Uncommitted .new files are evidence of interruption and fail closed.
"""
import copy
import fcntl
import os
import pathlib
import stat
import threading
from lqc_live508.journal_reuse import Journal, need, canonical, digest, strict_json
from lqc_live508.live_contracts import validate_contract, ROLES, sha, uint
from lqc_live508.live_hash import transaction_hash

TRANSITIONS = {None: {'RESERVED'}, 'RESERVED': {'SIGN_REQUESTED', 'UNCERTAIN'},
               'SIGN_REQUESTED': {'SIGNED', 'UNCERTAIN'}, 'SIGNED': {'SUBMIT_INTENT', 'UNCERTAIN'},
               'SUBMIT_INTENT': {'SUBMITTED', 'UNCERTAIN'},
               'SUBMITTED': {'CONFIRMED', 'REVERTED', 'UNCERTAIN'},
               'UNCERTAIN': {'UNCERTAIN', 'CONFIRMED', 'REVERTED'}, 'CONFIRMED': set(), 'REVERTED': set()}
TERMINAL = {'CONFIRMED', 'REVERTED'}
FIELDS = {'envelope', 'unsignedSHA256', 'state', 'rawTransactionHex', 'rawSHA256',
          'txHash', 'maxReserveAtest', 'reservedAtest', 'spentAtest', 'receipt',
          'evidence', 'evidenceSHA256', 'recoveryAuthorizationSHA256'}


class LiveJournal(Journal):
    def __init__(self, directory, contract, allowed_root, *, create=False):
        self.path, self.root = pathlib.Path(directory), pathlib.Path(allowed_root)
        self.contract = validate_contract(contract)
        self.context = {'scope': 'DEVNET_JOURNAL_V1', 'contractSHA256': digest(canonical(self.contract))}
        self.poisoned = self.closed = False
        self.restored = not create
        self._accepted_snapshot = None
        self.lock_fd = None
        self.mutex = threading.RLock()
        self._hash_cache = {}
        need(self.root.is_absolute() and self.path == self.root / 'journal', 'journal-exact-absolute-path')
        need(digest(str(self.path).encode()) == self.contract['binding']['journalPathSHA256'], 'journal-path-binding')
        for part in [self.root, *self.root.parents]:
            need(not part.is_symlink(), 'journal-ancestor-symlink')
        st = self.root.stat()
        need(stat.S_ISDIR(st.st_mode) and st.st_uid == os.getuid() and stat.S_IMODE(st.st_mode) == 0o700, 'journal-root-owner-mode')
        if create:
            need(not self.path.exists() and not self.path.is_symlink(), 'journal-create-existing')
            self.path.mkdir(mode=0o700)
            # Persist directory creation before storing any transaction reservation.
            fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            self._new_file('owner.json', canonical(self.context))
            self._new_file('lock', b'')
        need(self.path.is_dir() and not self.path.is_symlink(), 'journal-directory-missing')
        st = self.path.stat()
        need(st.st_uid == os.getuid() and stat.S_IMODE(st.st_mode) == 0o700, 'journal-directory-owner-mode')
        self.identity = (st.st_dev, st.st_ino)
        for name in ('owner.json', 'lock'):
            self._safe_file(name)
        need(strict_json((self.path / 'owner.json').read_bytes()) == self.context, 'journal-owner-binding')
        try:
            self.lock_fd = os.open(self.path / 'lock', os.O_RDWR | os.O_NOFOLLOW)
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.lock_identity = os.fstat(self.lock_fd)
            if create:
                self._store({'schema': 2, 'context': self.context, 'generation': 0,
                             'records': {}, 'events': [], 'halted': False})
            self.payload = self._load()
        except BaseException:
            self.close()
            raise

    def _store(self, payload):
        try:
            self._atomic('journal.json', canonical({'payload': payload, 'sha256': digest(canonical(payload))}))
            self._accepted_snapshot = (payload['generation'], digest(canonical(payload)))
        except BaseException:
            self.poisoned = True
            raise

    def _validate_record(self, r, prior):
        need(type(r) is dict and set(r) == FIELDS, 'live-record-fields')
        tx = r['envelope']
        need(canonical(tx) in [canonical(t) for t in self.contract['envelopes']] and
             r['unsignedSHA256'] == digest(canonical(tx)), 'live-envelope-binding')
        need(r['state'] in TRANSITIONS.get(prior['state'] if prior else None, set()), 'live-state-transition')
        max_reserve = tx['gasLimit'] * tx['maxFee']
        for k in ('maxReserveAtest', 'reservedAtest', 'spentAtest'):
            uint(r[k])
        need(r['maxReserveAtest'] == max_reserve, 'live-reserve-binding')
        if prior:
            need(all(r[k] == prior[k] for k in ('envelope', 'unsignedSHA256', 'maxReserveAtest')), 'immutable-envelope')
            if prior['rawTransactionHex'] is not None:
                need(all(r[k] == prior[k] for k in ('rawTransactionHex', 'rawSHA256', 'txHash')), 'immutable-signed-result')
        raw = r['rawTransactionHex']
        if raw is None:
            need(r['rawSHA256'] is None and r['txHash'] is None and r['state'] in
                 {'RESERVED', 'SIGN_REQUESTED', 'UNCERTAIN'}, 'missing-signed-result')
        else:
            need(type(raw) is str and raw.startswith('0x') and 2 < len(raw) <= 262146, 'raw-hex')
            data = bytes.fromhex(raw[2:])
            need('0x' + data.hex() == raw and r['rawSHA256'] == digest(data), 'raw-digest')
            if raw not in self._hash_cache:
                self._hash_cache[raw] = transaction_hash(data)
            need(r['txHash'] == self._hash_cache[raw], 'signed-transaction-hash')
            need(r['state'] not in {'RESERVED', 'SIGN_REQUESTED'}, 'premature-signed-result')
        cost_only = r['state'] == 'UNCERTAIN' and r['receipt'] is not None
        if prior and prior['state'] == r['state'] == 'UNCERTAIN':
            need(prior['receipt'] is None and cost_only, 'only-one-uncertain-cost-annotation')
        if cost_only:
            need(raw is not None, 'cost-requires-signed-transaction')
        if r['state'] in TERMINAL or cost_only:
            receipt = r['receipt']
            need(type(receipt) is dict and set(receipt) == {'transactionHash', 'blockHash', 'blockNumber',
                 'status', 'gasUsed', 'effectiveGasPrice'}, 'receipt-summary-fields')
            need(receipt['transactionHash'] == r['txHash'], 'receipt-transaction')
            need(type(receipt['blockHash']) is str and receipt['blockHash'].startswith('0x'), 'block-hash')
            sha(receipt['blockHash'][2:])
            for k in ('blockNumber', 'gasUsed', 'effectiveGasPrice', 'status'):
                uint(receipt[k])
            need(receipt['blockNumber'] > 0 and receipt['gasUsed'] <= tx['gasLimit'] and
                 receipt['effectiveGasPrice'] <= tx['maxFee'] and receipt['status'] in (0, 1) and
                 (cost_only or receipt['status'] == (1 if r['state'] == 'CONFIRMED' else 0)), 'receipt-limits-status')
            need(r['spentAtest'] == receipt['gasUsed'] * receipt['effectiveGasPrice'] and
                 r['reservedAtest'] == (max_reserve - r['spentAtest'] if cost_only else 0), 'receipt-accounting')
            sha(r['evidenceSHA256'])
            need(type(r['evidence']) is dict and len(canonical(r['evidence'])) <= 4000000 and
                 digest(canonical(r['evidence'])) == r['evidenceSHA256'], 'durable-evidence-binding')
            if cost_only:
                need(r['evidence'].get('schema') == 'LQC_EXECUTION_COST_ONLY_V1' and
                     r['recoveryAuthorizationSHA256'] is None, 'cost-only-not-confirmation')
            if prior and prior['receipt'] is not None:
                need(r['receipt'] == prior['receipt'], 'observed-cost-rewrite-denied')
            if r['recoveryAuthorizationSHA256'] is not None:
                sha(r['recoveryAuthorizationSHA256'])
            if prior and prior['state'] == 'UNCERTAIN' and not cost_only:
                sha(r['recoveryAuthorizationSHA256'])
        else:
            need(r['reservedAtest'] == max_reserve and r['spentAtest'] == 0 and
                 r['receipt'] is None and r['evidence'] is None and r['evidenceSHA256'] is None and
                 r['recoveryAuthorizationSHA256'] is None, 'unresolved-reservation')

    def _load_checked(self):
        self._guard()
        need(digest(canonical(self.contract)) == self.context['contractSHA256'], 'contract-changed')
        need({p.name for p in self.path.iterdir()} == {'owner.json', 'lock', 'journal.json'}, 'incomplete-or-foreign-journal-files')
        self._safe_file('owner.json'); self._safe_file('journal.json')
        need(strict_json((self.path / 'owner.json').read_bytes()) == self.context, 'owner-binding-changed')
        wrapper = strict_json((self.path / 'journal.json').read_bytes())
        payload = self._validate_payload(wrapper)
        observed = (payload['generation'], digest(canonical(payload)))
        need(self._accepted_snapshot is None or observed == self._accepted_snapshot, 'journal-rollback-or-external-replacement')
        self._accepted_snapshot = observed
        return payload

    def _validate_payload(self, wrapper):
        need(type(wrapper) is dict and set(wrapper) == {'payload', 'sha256'}, 'journal-wrapper')
        p = wrapper['payload']
        need(type(p) is dict and set(p) == {'schema', 'context', 'generation', 'records', 'events', 'halted'} and
             type(p['schema']) is int and p['schema'] == 2 and p['context'] == self.context, 'live-schema-context')
        need(wrapper['sha256'] == digest(canonical(p)), 'journal-checksum')
        need(type(p['events']) is list and type(p['records']) is dict and type(p['generation']) is int and
             p['generation'] == len(p['events']) and type(p['halted']) is bool, 'journal-generation')
        records, previous, halted = {}, '0' * 64, False
        for seq, event in enumerate(p['events'], 1):
            need(type(event) is dict and set(event) == {'seq', 'key', 'record', 'previous', 'halted', 'sha256'}, 'event-fields')
            body = {k: v for k, v in event.items() if k != 'sha256'}
            need(type(event['seq']) is int and event['seq'] == seq and event['previous'] == previous and
                 event['sha256'] == digest(canonical(body)) and type(event['halted']) is bool and
                 (not halted or event['halted']), 'event-chain-or-halt-reset')
            key, r = event['key'], event['record']
            if r is None:
                need(key is None and event['halted'], 'halt-event')
            else:
                self._validate_record(r, records.get(key))
                tx = r['envelope']
                need(key == tx['role'] + ':' + str(tx['nonce']), 'record-key')
                if key not in records:
                    need(not halted and len(records) < len(self.contract['envelopes']) and
                         canonical(tx) == canonical(self.contract['envelopes'][len(records)]) and
                         all(v['state'] == 'CONFIRMED' for v in records.values()), 'plan-order-or-unresolved')
                elif halted:
                    need(r['state'] == 'UNCERTAIN' or (r['state'] in TERMINAL and
                         r['recoveryAuthorizationSHA256'] is not None), 'halted-transition')
                if r['state'] in {'UNCERTAIN', 'REVERTED'}:
                    need(event['halted'], 'failure-must-halt')
                need(r['txHash'] is None or not any(other_key != key and other['txHash'] == r['txHash']
                     for other_key, other in records.items()), 'duplicate-signed-transaction-hash')
                records[key] = r
            previous, halted = event['sha256'], event['halted']
        need(records == p['records'] and halted == p['halted'], 'journal-projection')
        return p

    def _commit(self, record=None, *, halt=False):
        with self.mutex:
            self.payload = self._load()
            p = copy.deepcopy(self.payload)
            key = None
            if record is not None:
                tx = record['envelope']; key = tx['role'] + ':' + str(tx['nonce'])
                self._validate_record(record, p['records'].get(key))
                p['records'][key] = record
            event = {'seq': p['generation'] + 1, 'key': key, 'record': record,
                     'previous': p['events'][-1]['sha256'] if p['events'] else '0' * 64,
                     'halted': p['halted'] or halt}
            event['sha256'] = digest(canonical(event))
            p['events'].append(event); p['generation'] += 1; p['halted'] = event['halted']
            self._validate_payload({'payload': p, 'sha256': digest(canonical(p))})
            self._store(p)
            self.payload = self._load()

    def reserve(self, tx):
        with self.mutex:
            p = self._load()
            need(not p['halted'] and all(r['state'] == 'CONFIRMED' for r in p['records'].values()), 'HALTED-or-unresolved')
            need(len(p['records']) < len(self.contract['envelopes']) and
                 canonical(tx) == canonical(self.contract['envelopes'][len(p['records'])]), 'exact-next-envelope')
            reserve = tx['gasLimit'] * tx['maxFee']
            r = dict.fromkeys(FIELDS)
            r.update(envelope=copy.deepcopy(tx), unsignedSHA256=digest(canonical(tx)), state='RESERVED',
                     maxReserveAtest=reserve, reservedAtest=reserve, spentAtest=0)
            self._commit(r)

    def advance(self, key, state, *, raw=None, receipt=None, evidence=None, recovery_sha=None):
        with self.mutex:
            p = self._load()
            need(not p['halted'] or state == 'UNCERTAIN' or recovery_sha is not None, 'HALTED-no-normal-progress')
            r = copy.deepcopy(p['records'][key]); r['state'] = state
            if raw is not None:
                need(state == 'SIGNED' and type(raw) is bytes, 'signed-result-phase')
                r.update(rawTransactionHex='0x' + raw.hex(), rawSHA256=digest(raw), txHash=transaction_hash(raw))
            if state in TERMINAL or (state == 'UNCERTAIN' and receipt is not None):
                r.update(receipt=copy.deepcopy(receipt), evidence=copy.deepcopy(evidence), evidenceSHA256=digest(canonical(evidence)),
                         recoveryAuthorizationSHA256=recovery_sha, reservedAtest=0,
                         spentAtest=receipt['gasUsed'] * receipt['effectiveGasPrice'])
                if state == 'UNCERTAIN':
                    r['reservedAtest'] = r['maxReserveAtest'] - r['spentAtest']
            self._commit(r, halt=state in {'UNCERTAIN', 'REVERTED'})

    def halt(self):
        with self.mutex:
            p = self._load()
            active = [(k, r) for k, r in p['records'].items() if r['state'] not in TERMINAL | {'UNCERTAIN'}]
            if active:
                self.advance(active[0][0], 'UNCERTAIN')
            elif not p['halted']:
                self._commit(halt=True)

    def recover(self):
        with self.mutex:
            self.payload = self._load()
            records = copy.deepcopy(self.payload['records'])
            reserved = {r: sum(x['reservedAtest'] for x in records.values() if x['envelope']['role'] == r) for r in ROLES}
            spent = {r: sum(x['spentAtest'] for x in records.values() if x['envelope']['role'] == r) for r in ROLES}
            m = self.contract['manifest']
            need(all(reserved[r] + spent[r] <= m['roleBudgets'][r] for r in ROLES) and
                 sum(reserved.values()) + sum(spent.values()) <= m['totalBudget'], 'restored-budget-overrun')
            return {'records': records, 'reserved': reserved, 'spent': spent,
                    'leases': sorted(records), 'blocked': self.restored or self.payload['halted'] or
                    any(r['state'] != 'CONFIRMED' for r in records.values()),
                    'snapshotSHA256': digest(canonical(self.payload))}

    # Do not expose the inherited mock transition API under a live schema.
    def transition(self, *args, **kwargs):
        need(False, 'use-live-coordinator')
