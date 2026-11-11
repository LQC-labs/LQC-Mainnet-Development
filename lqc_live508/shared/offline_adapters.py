"""RPC codecs and signer validation, using exact memory fixtures ONLY.

No HTTP client, socket, key, real signature or raw-transaction sending implementation.
"""
import copy
import re
from lqc_live508.shared.durable_journal import strict_json
from lqc_live508.shared.mock_backend import MemoryIO, need, canonical, digest, uint, complete, allowed

ENDPOINT = "http://127.0.0.1:8545"  # Request metadata only; never opened.
READS = {"eth_chainId", "eth_blockNumber", "eth_getBalance", "eth_getTransactionCount", "eth_estimateGas",
         "eth_getTransactionReceipt", "eth_getBlockByNumber", "eth_getCode", "eth_gasPrice", "eth_maxPriorityFeePerGas"}


def quantity(value):
    need(type(value) is str and len(value) <= 66 and re.fullmatch("0x(?:0|[1-9a-f][0-9a-f]*)", value), "rpc-quantity-shape")
    return int(value, 16)


def hexdata(value, size=None):
    need(type(value) is str and len(value) <= 262144 and re.fullmatch("0x(?:[0-9a-fA-F]{2})*", value), "rpc-hex-shape")
    need(size is None or len(value) == 2 + size * 2, "rpc-hex-size")
    return value


def public_address(value):
    need(type(value) is str and re.fullmatch("0x[0-9a-f]{40}", value) and int(value, 16) > 0, "adapter-address-UNKNOWN")
    return value


def known_profile(profile):
    need(type(profile) is dict and type(profile.get("chainId")) is int and profile["chainId"] == 917001 and
         profile.get("chainIdHex") == "0xdfe09" and profile.get("cosmosChainId") == "lqc-devnet-test-1" and
         profile.get("denom") == "atest", "adapter-chain-context")
    need(type(profile.get("runId")) is str and re.fullmatch("[a-f0-9]{32}", profile["runId"]) and
         type(profile.get("genesisSHA256")) is str and re.fullmatch("[a-f0-9]{64}", profile["genesisSHA256"]), "adapter-run-genesis-UNKNOWN")
    need(set(profile["roles"]) == {"deployer", "owner", "guardian"} and
         len(set(public_address(a) for a in profile["roles"].values())) == 3, "adapter-role-separation")
    for name in ("roleState", "gas", "vault", "feeds", "oracle", "rate", "market"):
        need(complete(profile.get(name)), "adapter-UNKNOWN-" + name)
    need(set(profile["roleState"]) == set(profile["roles"]), "adapter-role-state-set")
    for role, state in profile["roleState"].items():
        snapshot = state["nonceSnapshot"]
        need(snapshot["address"] == profile["roles"][role] and type(snapshot["chainId"]) is int and
             snapshot["chainId"] == 917001 and snapshot["genesisSHA256"] == profile["genesisSHA256"], "adapter-nonce-snapshot-binding")
        need(uint(snapshot["latestNonce"]) == uint(snapshot["pendingNonce"]), "adapter-nonce-snapshot-conflict")
        uint(snapshot["balanceAtest"])
        uint(state["gas"]["maxBudgetAtest"])
    uint(profile["gas"]["maxTotalBudgetAtest"])


class MockTransport:
    """Memory exchange of JSON-RPC bytes. No connection/open/send method exists."""
    def __init__(self, profile, ledger):
        need(type(ledger) is MemoryIO, "exact-memory-ledger-only")
        self.profile = copy.deepcopy(profile)
        self.ledger = ledger
        self.context = copy.deepcopy(ledger.context)
        self.requests = []
        self.overrides = {}
        self.fault = None

    def exchange(self, raw_request):
        request = strict_json(raw_request)
        method, params, rid = request["method"], request["params"], request["id"]
        self.requests.append({"id": rid, "method": method})
        if self.fault == "timeout":
            raise TimeoutError("mock transport timeout")
        if method in self.overrides:
            value = copy.deepcopy(self.overrides[method])
        elif method == "eth_chainId":
            value = "0x61" if self.fault == "wrong-chain" else "0xdfe09"
        elif method == "eth_getTransactionCount":
            role = next(r for r, a in self.profile["roles"].items() if a == params[0])
            value = hex(self.ledger.nonces[role] + int(params[1] == "pending" and self.ledger.fail == "nonce-conflict"))
        elif method == "eth_getBalance":
            role = next(r for r, a in self.profile["roles"].items() if a == params[0])
            value = hex(uint(self.profile["roleState"][role]["nonceSnapshot"]["balanceAtest"]))
        elif method == "eth_blockNumber":
            value = hex(self.ledger.height)
        elif method in ("eth_gasPrice", "eth_maxPriorityFeePerGas", "eth_estimateGas"):
            value = "0x1"
        elif method == "eth_getCode":
            value = "0x"  # Absence is not deployed-code success.
        elif method == "eth_getTransactionReceipt":
            value = None  # Pending/missing is never a success receipt.
        else:
            height = self.ledger.height if params[0] == "latest" else quantity(params[0])
            value = {"number": hex(height), "hash": "0x" + digest(str(height).encode()), "gasLimit": "0xf4240", "baseFeePerGas": "0x1"}
        reply = {"jsonrpc": "2.0", "id": rid, "result": value}
        if self.fault == "rpc-error":
            reply = {"jsonrpc": "2.0", "id": rid, "error": {"code": -32000, "message": "SECRET-UNTRUSTED", "data": "DO_NOT_LOG"}}
        if self.fault == "wrong-id":
            reply["id"] = rid + 1
        if self.fault == "boolean-id":
            reply["id"] = True
        if self.fault == "both-result-error":
            reply["error"] = {"code": -1, "message": "DO_NOT_LOG"}
        if self.fault == "bad-version":
            reply["jsonrpc"] = "1.0"
        if self.fault == "malformed":
            return 200, b"{"
        if self.fault == "duplicate-id":
            return 200, ('{"jsonrpc":"2.0","id":' + str(rid) + ',"id":' + str(rid) + ',"result":"0xdfe09"}').encode()
        if self.fault == "oversized":
            return 200, b"x" * 262145
        return (503 if self.fault == "http-error" else 200), canonical(reply)


def validate_rpc_envelope(rid, status, raw, record):
    """Shared JSON-RPC framing, without method-specific result interpretation."""
    need(type(raw) is bytes and len(raw) <= 262144, "rpc-response-size")
    try:
        reply = strict_json(raw)
    except Exception:
        need(False, "rpc-invalid-JSON")
    need(type(reply) is dict and reply.get("jsonrpc") == "2.0" and type(reply.get("id")) is int and reply["id"] == rid, "rpc-envelope-id")
    need(("result" in reply) != ("error" in reply), "rpc-result-error-conflict")
    if "error" in reply:
        error = reply["error"]
        need(type(error) is dict and type(error.get("code")) is int and -(2**31) <= error["code"] < 2**31, "rpc-error-shape")
        record["errorCode"] = error["code"]
        need(False, "rpc-error")
    need(type(status) is int and status == 200, "rpc-http-status")
    return reply["result"]


def validate_rpc_response(method, params, rid, status, raw, record, *, allow_revert=False):
    """Original result validation; legacy callers still reject reverted receipts."""
    value = validate_rpc_envelope(rid, status, raw, record)
    if method in ("eth_chainId", "eth_blockNumber", "eth_getBalance", "eth_getTransactionCount", "eth_estimateGas", "eth_gasPrice", "eth_maxPriorityFeePerGas"):
        number = quantity(value)
        if method == "eth_chainId":
            need(number == 917001, "rpc-chain-id-mismatch")
        if method == "eth_estimateGas":
            need(number > 0, "rpc-gas-estimate-zero")
    elif method == "eth_getCode":
        hexdata(value)
    elif method == "eth_getBlockByNumber":
        need(type(value) is dict, "rpc-block-shape")
        quantity(value["number"])
        need(params[0] == "latest" or value["number"] == params[0], "rpc-block-height-mismatch")
        hexdata(value["hash"], 32)
        quantity(value["gasLimit"])
        quantity(value["baseFeePerGas"])
    elif value is not None:
        need(type(value) is dict and value["transactionHash"] == params[0] and value["status"] in (("0x0", "0x1") if allow_revert else ("0x1",)), "rpc-receipt-failed-or-hash")
        hexdata(value["blockHash"], 32)
        need(quantity(value["blockNumber"]) > 0, "rpc-receipt-height")
        quantity(value["gasUsed"])
        if value.get("contractAddress") is not None:
            public_address(value["contractAddress"])
        need(type(value["logs"]) is list, "rpc-receipt-logs")
        seen = set()
        for log in value["logs"]:
            public_address(log["address"])
            need(log["removed"] is False and log["transactionHash"] == value["transactionHash"] and log["blockHash"] == value["blockHash"] and log["blockNumber"] == value["blockNumber"], "rpc-log-link")
            index = quantity(log["logIndex"])
            need(index not in seen and type(log["topics"]) is list, "rpc-log-duplicate-or-topics")
            seen.add(index)
            for topic in log["topics"]:
                hexdata(topic, 32)
            hexdata(log["data"])
    return copy.deepcopy(value)


class OfflineRPCAdapter:
    def __init__(self, profile=None, transport=None, *, simulation=False, live=False, endpoint=ENDPOINT, targets=()):
        need(live is False and endpoint == ENDPOINT, "live-or-external-RPC-disabled")
        self.enabled = simulation is True
        self.profile = copy.deepcopy(profile)
        self.transport = transport
        self.targets = set(targets)
        self.counter = 0
        self.diagnostics = []
        if self.enabled:
            known_profile(self.profile)
            need(type(transport) is MockTransport, "mock-transport-only")
            for target in self.targets:
                public_address(target)

    def _params(self, method, params):
        need(method in READS and type(params) is list, "RPC-method-disabled")
        if method in ("eth_chainId", "eth_blockNumber", "eth_gasPrice", "eth_maxPriorityFeePerGas"):
            need(params == [], "rpc-params")
        elif method in ("eth_getBalance", "eth_getTransactionCount", "eth_getCode"):
            need(len(params) == 2, "rpc-params")
            known = set(self.profile["roles"].values()) | (self.targets if method == "eth_getCode" else set())
            need(public_address(params[0]) in known, "rpc-unapproved-address")
            if params[1] not in ("latest", "pending"):
                quantity(params[1])
        elif method == "eth_getTransactionReceipt":
            need(len(params) == 1, "rpc-params")
            hexdata(params[0], 32)
        elif method == "eth_getBlockByNumber":
            need(len(params) == 2 and params[1] is False, "rpc-block-params")
            if params[0] != "latest":
                quantity(params[0])
        else:
            need(len(params) == 1 and type(params[0]) is dict, "rpc-estimate-params")
            tx = params[0]
            need(set(tx) <= {"from", "to", "data", "value"} and public_address(tx.get("from")) in self.profile["roles"].values() and tx.get("value") == "0x0", "rpc-estimate-caller-value")
            if "to" in tx:
                need(public_address(tx["to"]) in self.targets, "rpc-estimate-target")
            hexdata(tx.get("data"))

    def request(self, method, params):
        need(self.enabled and type(self.transport) is MockTransport, "RPC-default-disabled")
        self._params(method, params)
        if method != "eth_chainId":
            # Every query rechecks identity; never rely on a stale successful chain probe.
            self.request("eth_chainId", [])
        self.counter += 1
        rid = self.counter
        record = {"requestId": rid, "method": method, "destination": "MEMORY_ONLY", "httpStatus": None}
        try:
            try:
                status, raw = self.transport.exchange(canonical({"jsonrpc": "2.0", "id": rid, "method": method, "params": params}))
            except Exception:
                need(False, "mock-RPC-transport-failure")
            record["httpStatus"] = status
            value = validate_rpc_response(method, params, rid, status, raw, record)
            if method == "eth_chainId":
                need(self.transport.context == {k: self.profile[k] for k in ("runId", "chainId", "genesisSHA256")}, "mock-genesis-binding-mismatch")
            record["outcome"] = "MISSING_PENDING_NOT_PASS" if value is None else "PARSED_FIXTURE_NOT_CHAIN_PROOF"
            return copy.deepcopy(value)
        except Exception:
            record["outcome"] = "ERROR_NO_RETRY"
            raise
        finally:
            self.diagnostics.append(record)
            self.diagnostics = self.diagnostics[-256:]

    def read_context(self):
        self.request("eth_chainId", [])
        expected = {k: self.profile[k] for k in ("runId", "chainId", "genesisSHA256")}
        need(self.transport.context == expected, "mock-genesis-binding-mismatch")
        return expected

    def read_nonce(self, role):
        need(self.enabled, "RPC-default-disabled")
        need(role in self.profile["roles"], "rpc-role-UNKNOWN")
        self.read_context()
        address = self.profile["roles"][role]
        return tuple(quantity(self.request("eth_getTransactionCount", [address, tag])) for tag in ("latest", "pending"))


class MockSignerFixture:
    def __init__(self, ledger):
        need(type(ledger) is MemoryIO, "exact-memory-ledger-only")
        self.ledger = ledger

    def request(self, tx):
        return self.ledger.request_signature(copy.deepcopy(tx))


def boundary(backend, tx, state):
    from lqc_live508.shared.authority_binding import AuthorityBoundMockBackend
    need(type(backend) is AuthorityBoundMockBackend and backend.failure is None and not backend.halted, "unbound-or-HALTED-adapter")
    backend.binding.validate(backend)
    gate = backend.gate
    gate.require_enabled()
    gate.authority.verify(gate.record)
    need(gate.record["notBefore"] <= gate.clock.now() < gate.record["expiresAt"], "adapter-approval-expired")
    need(tx == backend.expected_envelope(tx["operation"]), "signer-exact-envelope")
    key = (gate.record["approvalId"], tx["role"], tx["nonce"])
    need(gate.inflight.get(key) == digest(canonical(tx)), "adapter-approval-token")
    if state in ("SUBMIT_INTENT", "SUBMITTED"):
        need(key in gate.used, "adapter-submit-approval-not-consumed")
    records = backend.journal.recover()["records"]
    record = records.get(tx["role"] + ":" + str(tx["nonce"]))
    need(record is not None and record["state"] == state and record["txSHA256"] == digest(canonical(tx)), "adapter-durable-state")
    need(backend.spent[tx["role"]] + backend.reserved[tx["role"]] <= backend.budgets[tx["role"]] and
         sum(backend.spent.values()) + sum(backend.reserved.values()) <= backend.total, "adapter-budget")


class OfflineSignerAdapter:
    def __init__(self, profile=None, packet=None, fixture=None, *, simulation=False, live=False):
        need(live is False, "real-signature-disabled")
        self.enabled = simulation is True
        self.profile = copy.deepcopy(profile)
        self.packet = copy.deepcopy(packet)
        self.fixture = fixture
        self.backend = None
        if self.enabled:
            known_profile(profile)
            need(type(fixture) is MockSignerFixture and packet["profileSHA256"] == digest(canonical(profile)), "mock-signer-fixture-and-ABI-binding-required")

    def request_signature(self, tx):
        need(self.enabled and type(self.fixture) is MockSignerFixture, "signer-default-disabled")
        need(type(tx) is dict and set(tx) == {"runId", "chainId", "genesisSHA256", "scope", "operation", "role", "from", "to", "data", "nonce", "gasLimit", "maxFee", "maxPriority", "value"}, "signer-envelope-fields")
        need(type(tx["chainId"]) is int and tx["chainId"] == 917001 and tx["runId"] == self.profile["runId"] and
             tx["genesisSHA256"] == self.profile["genesisSHA256"] and tx["scope"] == "OFFLINE_SIMULATION", "signer-context")
        need(allowed(tx["role"], tx["operation"]) and tx["from"] == self.profile["roles"][tx["role"]] and tx["value"] == 0, "signer-role-value")
        for k in ("nonce", "gasLimit", "maxFee", "maxPriority", "value"):
            need(type(tx[k]) is int and 0 <= tx[k] < 2**256, "signer-integer-UNKNOWN")
        need(tx["gasLimit"] > 0 and tx["maxFee"] > 0 and tx["maxPriority"] <= tx["maxFee"], "signer-fee-bound")
        hexdata(tx["data"])
        boundary(self.backend, tx, "SIGN_REQUESTED")
        need(self.profile == self.backend.p and self.packet == self.backend.packet, "signer-pinned-profile-ABI-mismatch")
        token = self.fixture.request(tx)
        need(token == {"scope": "NOT_CRYPTOGRAPHIC", "digest": digest(canonical(tx)), "role": tx["role"], "address": tx["from"]}, "signer-fixture-result-binding")
        return token


class AdapterMemoryIO:
    """Coordinator-compatible facade. Submission/receipt remain explicitly memory fixtures."""
    def __init__(self, profile, packet, *, simulation=False, live=False):
        need(live is False, "live-adapter-disabled")
        self.enabled = simulation is True
        self.ledger = MemoryIO(profile)
        self.transport = MockTransport(profile, self.ledger)
        targets = {a for e in packet["entries"] for a in (e.get("predictedAddress"), e["transaction"].get("to")) if a}
        self.rpc = OfflineRPCAdapter(profile, self.transport, simulation=simulation, targets=targets)
        self.signer = OfflineSignerAdapter(profile, packet, MockSignerFixture(self.ledger), simulation=simulation)
        self.backend = None
        self.proof_collector = None
        self.required_proof_collector = None

    @property
    def calls(self):
        return self.ledger.calls

    @property
    def nonces(self):
        return self.ledger.nonces

    @property
    def fail(self):
        return self.ledger.fail

    @fail.setter
    def fail(self, value):
        self.ledger.fail = value

    def bind_backend(self, backend):
        from lqc_live508.shared.authority_binding import AuthorityBoundMockBackend
        need(type(backend) is AuthorityBoundMockBackend and backend.io is self and self.backend is None, "adapter-backend-binding")
        self.backend = backend
        self.signer.backend = backend

    def read_context(self):
        self.ledger.calls.append("mock-context")
        return self.rpc.read_context()

    def read_nonce(self, role):
        self.ledger.calls.append("mock-nonce")
        return self.rpc.read_nonce(role)

    def request_signature(self, tx):
        return self.signer.request_signature(tx)

    def submit(self, tx, token):
        need(self.enabled, "submission-default-disabled")
        boundary(self.backend, tx, "SUBMIT_INTENT")
        self.rpc.read_context()
        need(self.rpc.read_nonce(tx["role"]) == (tx["nonce"], tx["nonce"]), "pre-submit-nonce-conflict")
        need(token == {"scope": "NOT_CRYPTOGRAPHIC", "digest": digest(canonical(tx)), "role": tx["role"], "address": tx["from"]}, "submission-token-binding")
        # Deliberately NOT eth_sendRawTransaction and not serialized Ethereum bytes.
        return self.ledger.submit(copy.deepcopy(tx), token)

    def receipt(self, tx, txid, expected):
        need(self.enabled, "receipt-default-disabled")
        boundary(self.backend, tx, "SUBMITTED")
        self.rpc.read_context()
        receipt = self.ledger.receipt(copy.deepcopy(tx), txid, expected)
        collector = getattr(self, 'proof_collector', None)
        required = getattr(self, 'required_proof_collector', None)
        need(required is None or collector is required, 'required-proof-collector-removed')
        if collector is not None:
            from lqc_live508.shared.fixture_collector import FixtureCollector
            need(type(collector) is FixtureCollector, 'exact-fixture-collector-only')
            proof = collector.verify(tx, txid, expected, receipt)
            receipt['integrationProofSHA256'] = digest(canonical(proof))
        return receipt
