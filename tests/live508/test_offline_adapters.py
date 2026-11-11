import copy
import inspect
import ast
import json
import pathlib
import socket
import sys
import unittest
from unittest.mock import patch
from lqc_live508.shared.mock_backend import MemoryIO, Denied, canonical, digest
from lqc_live508.shared.offline_adapters import MockTransport, OfflineRPCAdapter, OfflineSignerAdapter, AdapterMemoryIO, ENDPOINT
from lqc_live508.shared.authority_binding import ApprovalBinding, AuthorityBoundMockBackend
from lqc_live508.shared.durable_journal import Journal
from lqc_live508.shared.offline_authority import TrustConfig, OfflineApprovalVerifier

# Reuse ONLY the prior fixture setup/teardown. Its old tests are not loaded or executed.
import tests.live508.test_authority_recovery as fixture_module

ROOT = pathlib.Path(__file__).parent / 'fixtures'
TEMP_PATHS = []


def inputs():
    return json.loads((ROOT / "MOCK-PROFILE.json").read_text()), json.loads((ROOT / "MOCK-ABI-PLAN.json").read_text())


def rpc_fixture():
    profile, packet = inputs()
    ledger = MemoryIO(profile)
    transport = MockTransport(profile, ledger)
    rpc = OfflineRPCAdapter(profile, transport, simulation=True)
    return profile, ledger, transport, rpc


class CodecTests(unittest.TestCase):
    def test_default_rpc_and_signer_disabled(self):
        with self.assertRaises(Denied):
            OfflineRPCAdapter().request("eth_chainId", [])
        with self.assertRaises(Denied):
            OfflineSignerAdapter().request_signature({})

    def test_no_live_external_or_custom_transport(self):
        p, packet = inputs()
        for kwargs in [{"live": True}, {"endpoint": "https://example.invalid"}, {"endpoint": "http://0.0.0.0:8545"}]:
            with self.assertRaises(Denied):
                OfflineRPCAdapter(p, **kwargs)
        with self.assertRaises(Denied):
            OfflineRPCAdapter(p, object(), simulation=True)
        with self.assertRaises(Denied):
            OfflineSignerAdapter(p, packet, simulation=True, live=True)

    def test_mock_requests_chain_balance_nonce_and_no_network(self):
        p, ledger, transport, rpc = rpc_fixture()
        with patch.object(socket, "socket", side_effect=AssertionError("NETWORK FORBIDDEN")):
            self.assertEqual(rpc.read_context()["chainId"], 917001)
            self.assertEqual(rpc.read_nonce("deployer"), (0, 0))
            self.assertEqual(rpc.request("eth_getBalance", [p["roles"]["owner"], "0x1"]), "0xf4240")
        self.assertEqual([x["id"] for x in transport.requests], list(range(1, len(transport.requests) + 1)))

    def test_wrong_chain_stops(self):
        p, l, t, r = rpc_fixture()
        t.fault = "wrong-chain"
        with self.assertRaisesRegex(Denied, "chain-id-mismatch"):
            r.read_context()

    def test_genesis_mismatch_stops(self):
        p, l, t, r = rpc_fixture()
        t.context["genesisSHA256"] = "f" * 64
        with self.assertRaisesRegex(Denied, "genesis-binding-mismatch"):
            r.read_context()

    def test_bad_envelopes_errors_http_size_and_timeout_no_retry(self):
        for fault in ["wrong-id", "boolean-id", "both-result-error", "bad-version", "malformed", "duplicate-id", "oversized", "http-error", "timeout", "rpc-error"]:
            p, l, t, r = rpc_fixture()
            t.fault = fault
            with self.subTest(fault=fault), self.assertRaises(Denied):
                r.request("eth_chainId", [])
            self.assertEqual(len(t.requests), 1)
            self.assertEqual(r.diagnostics[-1]["outcome"], "ERROR_NO_RETRY")
            self.assertNotIn("SECRET", str(r.diagnostics))
            self.assertNotIn("DO_NOT_LOG", str(r.diagnostics))

    def test_rpc_error_code_retained_without_body(self):
        p, l, t, r = rpc_fixture()
        t.fault = "rpc-error"
        with self.assertRaises(Denied):
            r.request("eth_chainId", [])
        self.assertEqual(r.diagnostics[-1]["errorCode"], -32000)

    def test_bad_quantity_types(self):
        for value in [None, 1, True, "0x00", "0x-1", "0xDFE09"]:
            p, l, t, r = rpc_fixture()
            t.overrides["eth_blockNumber"] = value
            with self.assertRaises(Denied):
                r.request("eth_blockNumber", [])

    def test_forbidden_methods_and_unknown_params(self):
        p, l, t, r = rpc_fixture()
        for method, params in [("eth_sendRawTransaction", ["0x00"]), ("personal_sign", []), ("eth_chainId", ["SECRET"]),
                               ("eth_getBalance", ["0x" + "44" * 20, "latest"]), ("eth_getBlockByNumber", ["0x1", True])]:
            with self.assertRaises(Denied):
                r.request(method, params)
        self.assertEqual(t.requests, [])

    def test_estimate_validation_and_zero_estimate(self):
        p, l, t, r = rpc_fixture()
        tx = {"from": p["roles"]["deployer"], "data": "0x00", "value": "0x0"}
        self.assertEqual(r.request("eth_estimateGas", [tx]), "0x1")
        t.overrides["eth_estimateGas"] = "0x0"
        with self.assertRaisesRegex(Denied, "estimate-zero"):
            r.request("eth_estimateGas", [tx])
        with self.assertRaises(Denied):
            r.request("eth_estimateGas", [dict(tx, value="0x1")])

    def test_receipt_missing_and_code_empty_not_success(self):
        p, l, t, r = rpc_fixture()
        self.assertIsNone(r.request("eth_getTransactionReceipt", ["0x" + "a" * 64]))
        self.assertEqual(r.diagnostics[-1]["outcome"], "MISSING_PENDING_NOT_PASS")
        self.assertEqual(r.request("eth_getCode", [p["roles"]["owner"], "0x1"]), "0x")

    def test_receipt_parser_links_and_failed_receipt(self):
        p, l, t, r = rpc_fixture()
        txid, block = "0x" + "a" * 64, "0x" + "b" * 64
        receipt = {"transactionHash": txid, "blockHash": block, "blockNumber": "0x1", "status": "0x1", "gasUsed": "0x1",
                   "contractAddress": p["roles"]["owner"], "logs": []}
        t.overrides["eth_getTransactionReceipt"] = receipt
        self.assertEqual(r.request("eth_getTransactionReceipt", [txid])["blockNumber"], "0x1")
        for field, value in [("transactionHash", block), ("status", "0x0"), ("gasUsed", True), ("blockNumber", "0x0")]:
            t.overrides["eth_getTransactionReceipt"] = dict(receipt, **{field: value})
            with self.assertRaises((Denied, ValueError)):
                r.request("eth_getTransactionReceipt", [txid])

    def test_block_height_mismatch(self):
        p, l, t, r = rpc_fixture()
        t.overrides["eth_getBlockByNumber"] = {"number": "0x2", "hash": "0x" + "a" * 64, "gasLimit": "0x1", "baseFeePerGas": "0x1"}
        with self.assertRaises(Denied):
            r.request("eth_getBlockByNumber", ["0x1", False])

    def test_unknown_inputs_block_simulation(self):
        for section in ["vault", "roleState", "gas"]:
            p, packet = inputs()
            p[section] = None
            with self.assertRaises((Denied, ValueError, TypeError)):
                OfflineRPCAdapter(p, MockTransport(p, MemoryIO(inputs()[0])), simulation=True)

    def test_wrong_role_nonce_snapshot_binding_blocks(self):
        for key, value in [("address", "0x" + "44" * 20), ("chainId", 97), ("genesisSHA256", "f" * 64), ("pendingNonce", "1")]:
            p, packet = inputs()
            ledger = MemoryIO(p)
            p["roleState"]["owner"]["nonceSnapshot"][key] = value
            with self.assertRaises(Denied):
                OfflineRPCAdapter(p, MockTransport(p, ledger), simulation=True)

    def test_method_signatures_match_coordinator(self):
        for method in ["read_context", "read_nonce", "request_signature", "submit", "receipt"]:
            self.assertEqual(list(inspect.signature(getattr(AdapterMemoryIO, method)).parameters),
                             list(inspect.signature(getattr(MemoryIO, method)).parameters))

    def test_each_query_rechecks_chain_and_genesis(self):
        for fault in ("chain", "genesis"):
            p, l, t, r = rpc_fixture()
            if fault == "chain":
                t.fault = "wrong-chain"
            else:
                t.context["genesisSHA256"] = "f" * 64
            with self.assertRaises(Denied):
                r.request("eth_getBalance", [p["roles"]["owner"], "latest"])
            self.assertEqual([q["method"] for q in t.requests], ["eth_chainId"])

    def test_receipt_logs_linked_not_removed_not_duplicate(self):
        p, l, t, r = rpc_fixture()
        txid, block = "0x" + "a" * 64, "0x" + "b" * 64
        log = {"address": p["roles"]["owner"], "removed": False, "transactionHash": txid, "blockHash": block,
               "blockNumber": "0x1", "logIndex": "0x0", "topics": ["0x" + "c" * 64], "data": "0x"}
        receipt = {"transactionHash": txid, "blockHash": block, "blockNumber": "0x1", "status": "0x1", "gasUsed": "0x1",
                   "contractAddress": p["roles"]["owner"], "logs": [log]}
        t.overrides["eth_getTransactionReceipt"] = receipt
        self.assertEqual(len(r.request("eth_getTransactionReceipt", [txid])["logs"]), 1)
        for logs in [[dict(log, removed=True)], [log, log], [dict(log, blockHash=txid)]]:
            t.overrides["eth_getTransactionReceipt"] = dict(receipt, logs=logs)
            with self.assertRaises(Denied):
                r.request("eth_getTransactionReceipt", [txid])

    def test_adapter_has_no_network_process_or_private_signer_import(self):
        tree = ast.parse((pathlib.Path(__file__).parents[2] / 'lqc_live508/shared/offline_adapters.py').read_text())
        imports = [n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
        imports += [a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names]
        banned = {"socket", "urllib", "http", "requests", "subprocess", "eth_account", "web3"}
        self.assertFalse(any(name and name.split(".")[0] in banned for name in imports))


class IntegratedTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture_module.AuthorityTests()
        self.f.setUp()
        TEMP_PATHS.append(str(self.f.root))
        self.io = AdapterMemoryIO(self.f.p, self.f.packet, simulation=True)

    def tearDown(self):
        self.f.tearDown()

    def bound(self):
        b = AuthorityBoundMockBackend(self.f.p, self.f.g, self.f.packet, digest(canonical(self.f.packet)), self.io,
                                     journal=self.f.j, gate=self.f.gate, binding=ApprovalBinding(self.f.verifier, self.f.signed, self.f.clock))
        self.io.bind_backend(b)
        return b

    def test_all24_through_adapters_preserves_journal_order(self):
        with patch("lqc_live508.shared.offline_authority.verify_public_signature"), patch.object(socket, "socket", side_effect=AssertionError("NETWORK FORBIDDEN")):
            b = self.bound()
            for op, tx in b.plan.items():
                b.execute_mock(op, tx["senderRole"])
        self.assertEqual(len(b.evidence), 24)
        self.assertEqual(self.f.j.payload["generation"], 120)
        self.assertEqual([e["record"]["state"] for e in self.f.j.payload["events"][:5]], ["RESERVED", "SIGN_REQUESTED", "SUBMIT_INTENT", "SUBMITTED", "CONFIRMED"])
        self.assertFalse(b.result()["realExecutionEnabled"])

    def test_unbound_signer_or_submit_refused(self):
        tx = {"operation": "Asset18"}
        with self.assertRaises((Denied, KeyError)):
            self.io.request_signature(tx)
        with self.assertRaises((Denied, KeyError)):
            self.io.submit(tx, {})
        self.assertNotIn("mock-signature-request", self.io.calls)
        self.assertNotIn("mock-submit", self.io.calls)

    def test_no_real_project_signature_does_not_reach_signer(self):
        with self.assertRaises(Denied):
            self.bound()
        self.assertEqual(self.io.calls, [])

    def test_signer_bad_chain_role_nonce_fee_or_unknown_rejected(self):
        with patch("lqc_live508.shared.offline_authority.verify_public_signature"):
            b = self.bound()
            tx = b.expected_envelope("Asset18")
            for field, value in [("chainId", 97), ("role", "guardian"), ("nonce", None), ("gasLimit", 0), ("maxFee", None), ("value", 1), ("data", "PRIVATE")]:
                with self.subTest(field=field), self.assertRaises((Denied, KeyError, TypeError)):
                    self.io.request_signature(dict(tx, **{field: value}))
        self.assertNotIn("mock-signature-request", self.io.calls)

    def test_nonce_conflict_prevents_signature(self):
        with patch("lqc_live508.shared.offline_authority.verify_public_signature"):
            b = self.bound()
            self.io.fail = "nonce-conflict"
            with self.assertRaises(Denied):
                b.execute_mock("Asset18", "deployer")
        self.assertNotIn("mock-signature-request", self.io.calls)

    def test_wrong_rpc_chain_halts_before_signature(self):
        with patch("lqc_live508.shared.offline_authority.verify_public_signature"):
            b = self.bound()
            self.io.transport.fault = "wrong-chain"
            with self.assertRaises(Denied):
                b.execute_mock("Asset18", "deployer")
        self.assertEqual(b.result()["operationalState"], "HALTED")
        self.assertNotIn("mock-signature-request", self.io.calls)

    def test_submission_uncertain_halts_and_preserves_reservation(self):
        with patch("lqc_live508.shared.offline_authority.verify_public_signature"):
            b = self.bound()
            self.io.fail = "submission-failed"
            with self.assertRaises(Denied):
                b.execute_mock("Asset18", "deployer")
            calls = list(self.io.calls)
            with self.assertRaises(Denied):
                b.execute_mock("Asset18", "deployer")
        self.assertEqual(b.result()["operationalState"], "HALTED")
        self.assertEqual(self.io.calls, calls)
        self.assertEqual(self.f.j.recover()["records"]["deployer:0"]["state"], "UNCERTAIN")

    def test_signature_refused_no_submission(self):
        with patch("lqc_live508.shared.offline_authority.verify_public_signature"):
            b = self.bound()
            self.io.fail = "signature-refused"
            with self.assertRaises(Denied):
                b.execute_mock("Asset18", "deployer")
        self.assertNotIn("mock-submit", self.io.calls)

    def test_mock_signature_digest_mismatch_no_submission(self):
        with patch("lqc_live508.shared.offline_authority.verify_public_signature"):
            b = self.bound()
            self.io.fail = "signature-binding"
            with self.assertRaises(Denied):
                b.execute_mock("Asset18", "deployer")
        self.assertNotIn("mock-submit", self.io.calls)
        self.assertEqual(self.f.j.recover()["records"]["deployer:0"]["state"], "FAILED")

    def test_event_and_code_fixture_failure_not_confirmed(self):
        with patch("lqc_live508.shared.offline_authority.verify_public_signature"):
            b = self.bound()
            self.io.fail = "code-mismatch"
            with self.assertRaises(Denied):
                b.execute_mock("Asset18", "deployer")
        self.assertEqual(self.f.j.recover()["records"]["deployer:0"]["state"], "FAILED")
        self.assertEqual(b.evidence, [])

    def test_gate_revoke_after_mock_signature_blocks_submission(self):
        original = self.io.request_signature
        def sign(tx):
            token = original(tx)
            self.f.gate.authority.revoked.add(self.f.gate.record["approvalId"])
            return token
        with patch("lqc_live508.shared.offline_authority.verify_public_signature"):
            b = self.bound()
            with patch.object(self.io, "request_signature", side_effect=sign), self.assertRaises(Denied):
                b.execute_mock("Asset18", "deployer")
        self.assertNotIn("mock-submit", self.io.calls)

    def test_actual_unknown_approver_config_blocks_all_adapter_actions(self):
        config = json.loads((ROOT / "TRUST-CONFIG-UNKNOWN.json").read_text())
        self.f.verifier = OfflineApprovalVerifier(TrustConfig(config, digest(canonical(config))))
        with self.assertRaisesRegex(Denied, "approver-UNKNOWN"):
            self.bound()
        self.assertEqual(self.io.calls, [])
        self.assertEqual(self.io.transport.requests, [])

    def test_changed_budget_after_mock_signature_no_submission(self):
        with patch("lqc_live508.shared.offline_authority.verify_public_signature"):
            b = self.bound()
            original = self.io.request_signature
            def sign(tx):
                token = original(tx)
                b.budgets["deployer"] = 0
                return token
            with patch.object(self.io, "request_signature", side_effect=sign), self.assertRaises(Denied):
                b.execute_mock("Asset18", "deployer")
        self.assertNotIn("mock-submit", self.io.calls)
        self.assertEqual(b.result()["operationalState"], "HALTED")

    def test_adapter_restart_uncertain_cannot_resubmit(self):
        with patch("lqc_live508.shared.offline_authority.verify_public_signature"):
            b = self.bound()
            self.io.fail = "submission-failed"
            with self.assertRaises(Denied):
                b.execute_mock("Asset18", "deployer")
            self.f.j.close()
            self.f.j = Journal(self.f.root / "journal", self.f.context, self.f.root)
            self.io = AdapterMemoryIO(self.f.p, self.f.packet, simulation=True)
            resumed = self.bound()
            self.assertEqual(resumed.result()["operationalState"], "HALTED")
            with self.assertRaises(Denied):
                resumed.execute_mock("Asset18", "deployer")
        self.assertEqual(self.io.calls, [])
        self.assertEqual(self.io.transport.requests, [])


if __name__ == "__main__":
    unittest.main()
