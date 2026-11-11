"""Read-only local Run/Genesis/process/listener binding. No node or RPC startup.

Run ID is a label in externally approved launch evidence, not an OS/RPC fact.
The launch evidence digest must be pinned by the existing live data contract.
Linux observation is only performed when verify() is explicitly called.
"""
import copy
import hashlib
import os
import pathlib
import re
import stat
from lqc_live508.rpc_reuse import need, canonical, digest, strict_json, validate_contract


def endpoint(url):
    # Deliberately small supported surface: IPv4 literal, one path, explicit port.
    need(type(url) is str, 'RPC-target-type')
    match = re.fullmatch(r'http://127\.0\.0\.1:([1-9][0-9]{0,4})/?', url)
    need(match is not None and int(match[1]) <= 65535, 'approved-canonical-loopback-required')
    return '127.0.0.1', int(match[1])


def canonical_endpoint(url):
    host, port = endpoint(url)
    return f'http://{host}:{port}/'


def _hash(value):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value), 'SHA256-required')


def _identity(value):
    need(type(value) is dict and set(value) == {'device', 'inode'} and
         all(type(v) is int and v >= 0 for v in value.values()) and value['inode'] > 0, 'file-identity')


def _absolute(path):
    need(type(path) is str and path.startswith('/') and str(pathlib.Path(path)) == path and
         '..' not in pathlib.Path(path).parts and path != '/', 'canonical-absolute-path')


def validate_spec(spec, contract):
    need(type(spec) is dict and set(spec) == {'schema', 'runId', 'chainId', 'cosmosChainId',
         'genesisSHA256', 'home', 'homeIdentity', 'identitySHA256', 'process', 'rpc'}, 'run-spec-fields')
    need(spec['schema'] == 'LQC_RUN_BINDING_V1', 'run-spec-schema')
    m = contract['manifest']
    need(all(spec[k] == m[k] for k in ('runId', 'chainId', 'genesisSHA256')) and
         type(spec['chainId']) is int and spec['chainId'] == 917001 and
         spec['cosmosChainId'] == contract['binding']['cosmosChainId'] == 'lqc-devnet-test-1', 'run-spec-chain-binding')
    need(digest(canonical(spec)) == contract['binding']['runEvidenceSHA256'], 'unapproved-run-evidence')
    _absolute(spec['home']); _identity(spec['homeIdentity'])
    _hash(spec['genesisSHA256']); _hash(spec['identitySHA256'])
    p = spec['process']
    need(type(p) is dict and set(p) == {'pid', 'startTicks', 'uid', 'bootId', 'exe',
         'exeSHA256', 'cmdlineSHA256', 'netNamespace'}, 'process-fields')
    need(all(type(p[k]) is int and p[k] >= 0 for k in ('pid', 'startTicks', 'uid')) and
         p['pid'] > 0 and p['startTicks'] > 0, 'process-integers')
    need(type(p['bootId']) is str and re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', p['bootId']), 'boot-id')
    need(type(p['netNamespace']) is str and re.fullmatch(r'net:\[[0-9]+\]', p['netNamespace']), 'net-namespace')
    _absolute(p['exe']); _hash(p['exeSHA256']); _hash(p['cmdlineSHA256'])
    rpc = spec['rpc']
    need(type(rpc) is dict and set(rpc) == {'url', 'listenerInode'} and
         type(rpc['listenerInode']) is int and rpc['listenerInode'] > 0, 'listener-fields')
    endpoint(rpc['url'])


def directory_fd(path):
    """Walk without following symlinks, including parent components."""
    _absolute(str(path))
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in pathlib.Path(path).parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_at(parent, subdir, name, limit):
    fd = os.open(subdir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    try:
        file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    finally:
        os.close(fd)
    try:
        before = os.fstat(file_fd)
        need(stat.S_ISREG(before.st_mode) and before.st_size <= limit and before.st_nlink == 1, 'unsafe-or-large-public-file')
        with os.fdopen(file_fd, 'rb', closefd=False) as stream:
            raw = stream.read(limit + 1)
        after = os.fstat(file_fd)
        need(len(raw) <= limit and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
             (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'public-file-changed')
        return raw
    finally:
        os.close(file_fd)


class LinuxRunObserver:
    """Reads only public Genesis/identity and proc metadata. Never key files.

    proc_root is injectable for filesystem fixtures. Actual operation uses /proc.
    This is host-local attestation under a trusted OS, not a remote/light-client proof.
    """
    def __init__(self, proc_root='/proc'):
        self.proc = pathlib.Path(proc_root)
        self._exe_cache = {}

    def _read(self, path, limit=1048576):
        with path.open('rb') as stream:
            raw = stream.read(limit + 1)
        need(len(raw) <= limit, 'proc-response-too-large')
        return raw

    def _process(self, expected, home):
        base = self.proc / str(expected['pid'])
        raw_stat = self._read(base / 'stat', 65536)
        need(raw_stat.split(b' ', 1)[0] == str(expected['pid']).encode(), 'process-stat-pid-mismatch')
        tail = raw_stat.rsplit(b')', 1)[1].split()
        need(tail[0] not in (b'Z', b'X', b'x'), 'process-not-running')
        start = int(tail[19])
        status = self._read(base / 'status').decode('ascii')
        uid_lines = [x for x in status.splitlines() if x.startswith('Uid:')]
        need(len(uid_lines) == 1, 'process-uid-missing')
        uids = [int(x) for x in uid_lines[0].split()[1:]]
        need(len(uids) == 4 and all(u == expected['uid'] for u in uids), 'process-uid-mismatch')
        argv_raw = self._read(base / 'cmdline', 65536)
        argv = argv_raw.rstrip(b'\0').decode('utf-8').split('\0')
        homes = [argv[i + 1] for i, arg in enumerate(argv[:-1]) if arg == '--home']
        homes += [arg[len('--home='):] for arg in argv if arg.startswith('--home=')]
        need(homes == [home], 'process-home-argument-mismatch')
        exe_link = os.readlink(base / 'exe')
        need(exe_link == expected['exe'], 'executable-path-changed')
        # /proc/PID/exe is intentionally a kernel-provided symlink.
        with (base / 'exe').open('rb') as stream:
            before = os.fstat(stream.fileno())
            ident = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            need(stat.S_ISREG(before.st_mode) and before.st_size <= 536870912, 'executable-file-size')
            if ident not in self._exe_cache:
                h = hashlib.sha256()
                for block in iter(lambda: stream.read(1048576), b''):
                    h.update(block)
                after = os.fstat(stream.fileno())
                need(ident == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'executable-changed')
                self._exe_cache = {ident: h.hexdigest()}
            exe_hash = self._exe_cache[ident]
        namespace = os.readlink(base / 'ns/net')
        need(namespace == os.readlink(self.proc / 'self/ns/net'), 'different-network-namespace')
        result = {'pid': expected['pid'], 'startTicks': start, 'uid': uids[0],
                  'bootId': self._read(self.proc / 'sys/kernel/random/boot_id', 100).decode('ascii').strip(),
                  'exe': exe_link, 'exeSHA256': exe_hash, 'cmdlineSHA256': digest(argv_raw), 'netNamespace': namespace}
        return result

    def _listener(self, expected, pid):
        _, port = endpoint(expected['url'])
        base = self.proc / str(pid)
        rows = self._read(base / 'net/tcp', 4194304).decode('ascii').splitlines()[1:]
        # Any wildcard/same-port competing listener fails closed.
        candidates = [r.split() for r in rows if len(r.split()) >= 10 and r.split()[3] == '0A' and
                      int(r.split()[1].split(':')[1], 16) == port]
        need(len(candidates) == 1 and candidates[0][1] == f'0100007F:{port:04X}', 'listener-not-exclusive-loopback')
        inode = int(candidates[0][9])
        owned = set()
        children = list((base / 'fd').iterdir())
        need(len(children) <= 16384, 'process-fd-limit')
        for child in children:
            try:
                target = os.readlink(child)
            except FileNotFoundError:
                continue
            if re.fullmatch(r'socket:\[[0-9]+\]', target):
                owned.add(int(target[8:-1]))
        need(inode in owned, 'RPC-listener-not-owned-by-process')
        return {'url': expected['url'], 'listenerInode': inode}

    def observe(self, spec):
        process_before = self._process(spec['process'], spec['home'])
        home_fd = directory_fd(spec['home'])
        try:
            home_stat = os.fstat(home_fd)
            need(home_stat.st_uid == spec['process']['uid'], 'home-owner-mismatch')
            genesis = read_at(home_fd, 'config', 'genesis.json', 16777216)
            identity_raw = read_at(home_fd, 'data', 'node.identity.json', 65536)
            g, identity = strict_json(genesis), strict_json(identity_raw)
            chain = g['lqc_profile']['Chain']
            need(type(chain['EVMChainID']) is int and chain['EVMChainID'] == 917001 and
                 g['chain_id'] == 'lqc-devnet-test-1', 'genesis-chain-identity')
            if 'CosmosChainID' in chain:
                need(chain['CosmosChainID'] == g['chain_id'], 'genesis-profile-cosmos-id')
            genesis_hash = digest(genesis)
            need(identity['chain_id'] == g['chain_id'] and identity['genesis_sha256'] == genesis_hash, 'DB-genesis-identity-mismatch')
            home_identity = {'device': home_stat.st_dev, 'inode': home_stat.st_ino}
        finally:
            os.close(home_fd)
        listener = self._listener(spec['rpc'], spec['process']['pid'])
        process_after = self._process(spec['process'], spec['home'])
        need(process_before == process_after, 'process-changed-during-observation')
        # Reopen the pathname: a renamed/replaced home cannot hide behind our FD.
        check_fd = directory_fd(spec['home'])
        try:
            st = os.fstat(check_fd)
            need(home_identity == {'device': st.st_dev, 'inode': st.st_ino}, 'home-replaced')
        finally:
            os.close(check_fd)
        return {'home': spec['home'], 'homeIdentity': home_identity, 'genesisSHA256': genesis_hash,
                'chainId': chain['EVMChainID'], 'cosmosChainId': g['chain_id'],
                'identitySHA256': digest(identity_raw), 'process': process_after, 'rpc': listener}


class RunBinding:
    def __init__(self, contract, approved_spec, observer=None):
        self.contract = validate_contract(contract)
        self.spec = copy.deepcopy(approved_spec)
        validate_spec(self.spec, self.contract)
        self.pin = digest(canonical(self.spec))
        self.contract_pin = digest(canonical(self.contract))
        self.observer = observer if observer is not None else LinuxRunObserver()
        self.halted = False

    @property
    def url(self):
        return self.spec['rpc']['url']

    def verify(self):
        try:
            need(not self.halted, 'HALTED-run-binding')
            need(digest(canonical(self.spec)) == self.pin and digest(canonical(self.contract)) == self.contract_pin, 'run-binding-mutated')
            actual = self.observer.observe(copy.deepcopy(self.spec))
            expected = {k: v for k, v in self.spec.items() if k not in {'schema', 'runId'}}
            need(canonical(actual) == canonical(expected), 'run-genesis-process-target-mismatch')
            return {'runId': self.spec['runId'], 'chainId': self.spec['chainId'],
                    'genesisSHA256': self.spec['genesisSHA256']}
        except BaseException:
            self.halted = True
            raise
