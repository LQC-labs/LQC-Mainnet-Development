"""Offline memory simulation. No network, key, real signer or process implementation."""
import copy
import hashlib
import json
import re


class Denied(ValueError):
    pass


def need(condition, reason):
    if not condition:
        raise Denied(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def uint(value):
    need(type(value) is str and len(value) <= 78 and re.fullmatch(r"0|[1-9][0-9]*", value), "UNKNOWN-or-invalid-integer")
    number = int(value)
    need(number < 2**256, "integer-overflow")
    return number


def complete(value):
    if value is None:
        return False
    if type(value) is dict:
        return all(complete(v) for v in value.values())
    if type(value) is list:
        return all(complete(v) for v in value)
    return True


CREATE = ["Asset18", "Asset6", "Vault", "CollateralPrimaryFeed", "CollateralSecondaryFeed", "DebtPrimaryFeed", "DebtSecondaryFeed", "OracleManager", "RateModel", "MarketRegistry", "InterestIndex", "LendingCore", "LiquidationEngine"]
OWNER = ["ConfigureCollateralOracle", "ConfigureDebtOracle", "ConfigureRate", "InitializeIndex", "SetCore", "ConfigureMarket", "SetLiquidationEngine"]
SAFETY = ["DisableCollateralOracle", "DisableDebtOracle", "DisableRate", "DisableMarket"]


def allowed(role, op):
    return (role == "deployer" and op in CREATE) or (role == "owner" and op in OWNER) or (role in ("owner", "guardian") and op in SAFETY)


class MemoryIO:
    """Synthetic fixtures only; tokens are deliberately NOT Ethereum signatures/transactions."""

    def __init__(self, profile):
        self.context = {k: profile[k] for k in ("runId", "chainId", "genesisSHA256")}
        self.nonces = {r: uint(s["nonceSnapshot"]["pendingNonce"]) for r, s in profile["roleState"].items()}
        self.calls = []
        self.fail = None
        self.height = 1

    def read_context(self):
        self.calls.append("mock-context")
        return copy.deepcopy(self.context)

    def read_nonce(self, role):
        self.calls.append("mock-nonce")
        n = self.nonces[role]
        return n, n + int(self.fail == "nonce-conflict")

    def request_signature(self, tx):
        self.calls.append("mock-signature-request")
        need(self.fail != "signature-refused", "signature-refused")
        return {"scope": "NOT_CRYPTOGRAPHIC", "digest": "BAD" if self.fail == "signature-binding" else digest(canonical(tx)), "role": tx["role"], "address": tx["from"]}

    def submit(self, tx, token):
        self.calls.append("mock-submit")
        need(self.fail != "submission-failed", "submission-failed")
        self.nonces[tx["role"]] += 1
        self.height += 1
        return "MOCK_TX:" + ("BAD" if self.fail == "submission-hash" else digest(canonical(tx)))

    def receipt(self, tx, txid, expected):
        self.calls.append("mock-receipt")
        result = {**{k: tx[k] for k in ("runId", "chainId", "genesisSHA256", "operation", "role", "nonce")}, **copy.deepcopy(expected), "scope": "MOCK_NOT_CHAIN_EVIDENCE", "txHash": txid, "blockNumber": self.height, "blockHash": "MOCK_BLOCK:" + digest(str(self.height).encode()), "status": 1, "gasUsed": 1, "effectiveGasPrice": 1}
        changes = {"failed-receipt": ("status", 0), "event-mismatch": ("events", []), "code-mismatch": ("runtimeSHA256", "0" * 64), "run-mismatch": ("runId", "f" * 32), "receipt-chain": ("chainId", 97), "address-mismatch": ("address", "0x" + "44" * 20), "receipt-nonce": ("nonce", tx["nonce"] + 1), "gas-overrun": ("gasUsed", tx["gasLimit"] + 1), "block-mismatch": ("blockHash", "MOCK_BLOCK:WRONG")}
        if self.fail in changes:
            key, value = changes[self.fail]
            result[key] = value
        return result


class MockBackend:
    def __init__(self, profile, genesis, packet, pinned_packet_sha, io, *, live=False):
        from lqc_live508.shared.offline_adapters import AdapterMemoryIO
        need(live is False and type(io) in (MemoryIO, AdapterMemoryIO), "memory-only-real-execution-disabled")
        need(digest(canonical(packet)) == pinned_packet_sha, "pinned-ABI-plan")
        self.p = copy.deepcopy(profile)
        self.packet = copy.deepcopy(packet)
        self.io = io
        self.failure = None
        self.evidence = []
        self.done = set()
        self.leases = set()
        self.spent = dict.fromkeys(("deployer", "owner", "guardian"), 0)
        self.reserved = self.spent.copy()
        p = self.p
        need(p.get("executionAuthorized") is False and p.get("activationAuthorized") is False, "real-authorization-forbidden")
        need(type(p.get("chainId")) is int and p.get("chainId") == 917001 and p.get("chainIdHex") == "0xdfe09" and p.get("cosmosChainId") == "lqc-devnet-test-1" and p.get("denom") == "atest", "chain-identity")
        need(type(p.get("runId")) is str and re.fullmatch("[a-f0-9]{32}", p["runId"]), "run-id")
        g = json.loads(genesis)
        need(g.get("chain_id") == "lqc-devnet-test-1" and g.get("lqc_profile", {}).get("Chain", {}).get("EVMChainID") == 917001, "genesis-chain")
        need(p.get("genesisSHA256") == digest(genesis), "genesis-hash")
        for key in ("roles", "roleState", "gas", "vault", "feeds", "oracle", "rate", "market", "transactions", "safetyTransactions"):
            need(key in p and complete(p[key]), "UNKNOWN-" + key)
        need(p["market"]["enabled"] is False and p["rate"]["enabled"] is False, "market-activation-forbidden")
        roles = p["roles"]
        need(set(roles) == set(self.spent), "role-set")
        need(all(type(a) is str and re.fullmatch("0x[0-9a-f]{40}", a) and int(a, 16) > 0 for a in roles.values()) and len(set(roles.values())) == 3, "role-separation")
        need(packet.get("scope") == "OFFLINE_UNSIGNED_ROLE_PLAN" and packet.get("executionEnabled") is False, "unsigned-plan-scope")
        need(all(packet[k] == p[k] for k in ("runId", "chainId", "genesisSHA256")) and packet["profileSHA256"] == digest(canonical(p)), "constructor-profile-binding")
        self.entries = {e["operation"]: e for e in packet["entries"]}
        self.plan = {t["operation"]: t for t in p["transactions"] + p["safetyTransactions"]}
        need(len(self.entries) == len(packet["entries"]) == len(self.plan) == len(p["transactions"] + p["safetyTransactions"]), "duplicate-operation")
        need(set(self.entries) == set(self.plan), "operation-set")
        self.budgets, self.balances, cursor = {}, {}, {}
        costs = self.spent.copy()
        for role, state in p["roleState"].items():
            need(role in roles, "unknown-role")
            need(state["authorization"]["scope"] == "DISPOSABLE_917001_TEST_ONLY" and re.fullmatch("[a-f0-9]{64}", state["authorization"]["evidenceSHA256"]), "role-scope")
            s = state["nonceSnapshot"]
            need(s["address"] == roles[role] and s["chainId"] == 917001 and s["genesisSHA256"] == p["genesisSHA256"], "nonce-snapshot-binding")
            cursor[role] = uint(s["pendingNonce"])
            need(uint(s["latestNonce"]) == cursor[role], "pending-nonce-conflict")
            self.budgets[role] = uint(state["gas"]["maxBudgetAtest"])
            self.balances[role] = uint(s["balanceAtest"])
            self.reserved[role] = uint(state["gas"]["reservedAtest"])
        for op, t in self.plan.items():
            e = self.entries[op]
            role = t["senderRole"]
            need(allowed(role, op), "role-operation-denied")
            need(e["senderRole"] == role and e["nonce"] == t["nonce"] and e["transaction"]["from"] == roles[role], "constructor-role-nonce")
            need(uint(t["nonce"]) == cursor[role], "plan-nonce-conflict")
            cursor[role] += 1
            need(0 < uint(t["gasLimit"]) <= uint(p["gas"]["blockGasLimit"]), "gas-limit")
            need(uint(t["maxFeePerGasAtest"]) > 0 and uint(t["maxPriorityFeePerGasAtest"]) <= uint(t["maxFeePerGasAtest"]), "fee-bound")
            need(digest(bytes.fromhex(e["transaction"]["data"][2:])) == e["dataSHA256"], "constructor-calldata")
            costs[role] += uint(t["gasLimit"]) * uint(t["maxFeePerGasAtest"])
        need(all(costs[r] + self.reserved[r] <= min(self.budgets[r], self.balances[r]) for r in costs), "role-plan-budget")
        self.total = uint(p["gas"]["maxTotalBudgetAtest"])
        need(sum(costs.values()) + sum(self.reserved.values()) <= self.total, "total-plan-budget")

    def construct(self, op, role):
        need(self.failure is None, "latched-failure")
        need(allowed(role, op) and op in self.plan and self.plan[op]["senderRole"] == role, "role-operation-denied")
        need(op not in self.done, "already-completed")
        order = list(self.plan)
        need(all(x in self.done for x in order[:order.index(op)]), "dependency-order")
        ctx = self.io.read_context()
        need(type(ctx.get("chainId")) is int and ctx == {k: self.p[k] for k in ("runId", "chainId", "genesisSHA256")}, "context-mismatch")
        t, e = self.plan[op], self.entries[op]
        n = uint(t["nonce"])
        observed = self.io.read_nonce(role)
        need(all(type(x) is int for x in observed) and observed == (n, n) and (role, n) not in self.leases, "nonce-conflict")
        tx = {**ctx, "scope": "OFFLINE_SIMULATION", "operation": op, "role": role, "from": self.p["roles"][role], "to": e["transaction"].get("to"), "data": e["transaction"]["data"], "nonce": n, "gasLimit": uint(t["gasLimit"]), "maxFee": uint(t["maxFeePerGasAtest"]), "maxPriority": uint(t["maxPriorityFeePerGasAtest"]), "value": 0}
        cost = tx["gasLimit"] * tx["maxFee"]
        need(self.spent[role] + self.reserved[role] + cost <= min(self.budgets[role], self.balances[role]), "role-budget")
        need(sum(self.spent.values()) + sum(self.reserved.values()) + cost <= self.total, "total-budget")
        return tx

    def authorize(self, tx, phase):
        raise Denied("approval-gate-required")

    def journal_event(self, tx, stage, evidence=None):
        raise Denied("durable-journal-required")

    def execute_mock(self, op, role):
        try:
            tx = self.construct(op, role)
            self.authorize(tx, "before-sign")
            self.journal_event(tx, "reserve")
            cost = tx["gasLimit"] * tx["maxFee"]
            self.leases.add((role, tx["nonce"]))
            self.reserved[role] += cost
            self.journal_event(tx, "sign-requested")
            token = self.io.request_signature(copy.deepcopy(tx))
            need(token == {"scope": "NOT_CRYPTOGRAPHIC", "digest": digest(canonical(tx)), "role": role, "address": tx["from"]}, "signature-binding")
            self.authorize(tx, "before-submit")
            self.journal_event(tx, "submit-intent")
            txid = self.io.submit(copy.deepcopy(tx), token)
            need(txid == "MOCK_TX:" + digest(canonical(tx)), "submission-hash")
            self.journal_event(tx, "submitted", txid)
            e = self.entries[op]
            proof = {"address": e.get("predictedAddress") or e["transaction"].get("to"), "events": [{"MOCK_EVENT": op, "calldataSHA256": e["dataSHA256"]}], "runtimeSHA256": digest(("SYNTHETIC_NOT_CONTRACT_CODE:" + op).encode())}
            receipt = self.io.receipt(tx, txid, proof)
            need(receipt["scope"] == "MOCK_NOT_CHAIN_EVIDENCE" and all(receipt[k] == tx[k] for k in ("runId", "chainId", "genesisSHA256", "operation", "role", "nonce")), "receipt-binding")
            need(receipt["txHash"] == txid and type(receipt["status"]) is int and receipt["status"] == 1 and receipt["address"] == proof["address"], "failed-receipt-or-address")
            need(type(receipt["blockNumber"]) is int and receipt["blockNumber"] > 0 and receipt["blockHash"] == "MOCK_BLOCK:" + digest(str(receipt["blockNumber"]).encode()), "block-binding")
            need(receipt["events"] == proof["events"] and receipt["runtimeSHA256"] == proof["runtimeSHA256"], "event-code-mismatch")
            need(type(receipt["gasUsed"]) is int and 0 <= receipt["gasUsed"] <= tx["gasLimit"] and type(receipt["effectiveGasPrice"]) is int and 0 <= receipt["effectiveGasPrice"] <= tx["maxFee"], "fee-overrun")
            self.journal_event(tx, "confirm", receipt)
            self.spent[role] += receipt["gasUsed"] * receipt["effectiveGasPrice"]
            self.reserved[role] -= cost
            self.done.add(op)
            self.evidence.append(copy.deepcopy(receipt))
            return copy.deepcopy(receipt)
        except Exception as exc:
            self.failure = self.failure or str(exc)
            raise

    def result(self):
        return {"scope": "OFFLINE_SIMULATION_NOT_DEPLOYMENT_EVIDENCE", "status": "FAIL" if self.failure else "MOCK_ONLY", "failure": self.failure, "executionEnabled": False, "realSignatures": 0, "realSubmissions": 0, "valuationStatus": "UNKNOWN", "mockEvidence": copy.deepcopy(self.evidence), "spent": self.spent.copy(), "reserved": self.reserved.copy()}
