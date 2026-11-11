import copy
import inspect
import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch
from lqc_live508.shared.mock_backend import MemoryIO, Denied, CREATE, OWNER, SAFETY, canonical, digest
from lqc_live508.shared.approval_gate import GuardedMockBackend, ApprovalGate, FixtureAuthority, FixtureClock, transaction_scope
from lqc_live508.shared.durable_journal import Journal
from lqc_live508.shared.journal_backend import context_for, RealRPCAdapter, RealSignerAdapter
from lqc_live508.shared.offline_authority import TrustConfig, OfflineApprovalVerifier, verify_public_signature, parse_signed_document, DOMAIN
from lqc_live508.shared.authority_binding import ApprovalBinding, AuthorityBoundMockBackend, review_manual_recovery

BASE = pathlib.Path(__file__).parent / 'fixtures'
VECTORS = json.loads((BASE / "RFC8032-PUBLIC-VECTORS.json").read_text())["vectors"]
TEMP_PATHS = []


class CryptoTests(unittest.TestCase):
    def test_existing_rfc_public_signatures_verify(self):
        for v in VECTORS:
            verify_public_signature(v["publicKeyHex"], bytes.fromhex(v["messageHex"]), v["signatureHex"])

    def test_modified_message_fails(self):
        v = VECTORS[1]
        with self.assertRaises(Denied):
            verify_public_signature(v["publicKeyHex"], b"changed", v["signatureHex"])

    def test_modified_signature_fails(self):
        v = VECTORS[1]
        with self.assertRaises(Denied):
            verify_public_signature(v["publicKeyHex"], b"r", "00" + v["signatureHex"][2:])

    def test_wrong_public_key_fails(self):
        with self.assertRaises(Denied):
            verify_public_signature(VECTORS[0]["publicKeyHex"], b"r", VECTORS[1]["signatureHex"])

    def test_invalid_encoding_fails(self):
        for key, sig in [(None, "00" * 64), ("00" * 31, "00" * 64), (VECTORS[1]["publicKeyHex"], "00")]:
            with self.assertRaises(Denied):
                verify_public_signature(key, b"r", sig)


class AuthorityTests(unittest.TestCase):
    """Positive structured approval policy tests MOCK the crypto boundary explicitly.

    No new signature is generated; the existing RFC signature is NOT valid for these JSON bodies.
    """
    def setUp(self):
        self.p = json.loads((BASE / "MOCK-PROFILE.json").read_text())
        self.g = (BASE / "MOCK-GENESIS.json").read_bytes()
        self.packet = json.loads((BASE / "MOCK-ABI-PLAN.json").read_text())
        self.io = MemoryIO(self.p)
        prototype = GuardedMockBackend(self.p, self.g, self.packet, digest(canonical(self.packet)), self.io)
        self.manifest = transaction_scope(prototype)
        self.temp = tempfile.TemporaryDirectory(prefix="lqc-prep05-")
        self.root = pathlib.Path(self.temp.name)
        TEMP_PATHS.append(str(self.root))
        self.config = {"schema": 1, "status": "PINNED_EXTERNAL_IDENTITY_ASSERTIONS", "revision": 1,
                       "validFrom": 0, "validUntil": 1000, "revokedApprovalIds": [], "revokedKeyIds": [],
                       "journalBindings": {self.p["runId"]: {"genesisSHA256": self.p["genesisSHA256"], "approvalId": "e" * 64,
                                                            "pathSHA256": digest(str(self.root / "journal").encode())}},
                       "keys": {"RFC_VECTOR_NOT_REAL_APPROVER": {
                           "issuerId": "TEST_FIXTURE_NOT_A_REAL_IDENTITY", "publicKeyHex": VECTORS[1]["publicKeyHex"],
                           "identityStatus": "VERIFIED_BY_PINNED_EXTERNAL_EVIDENCE", "authorityStatus": "VERIFIED_BY_PINNED_EXTERNAL_EVIDENCE",
                           "identityEvidenceSHA256": "c" * 64, "authorityEvidenceSHA256": "d" * 64,
                           "notBefore": 0, "expiresAt": 1000, "purposes": ["DEPLOYMENT", "MANUAL_RECOVERY"],
                           "chainIds": [917001], "roles": ["deployer", "owner", "guardian"],
                           "operations": CREATE + OWNER + SAFETY, "maximumTotalBudgetAtest": 300000,
                           "maximumRoleBudgetAtest": {"deployer": 100000, "owner": 100000, "guardian": 100000}}}}
        self.signed = {"body": {"schema": "LQC_APPROVAL_V1", "approvalId": "e" * 64,
                                   "issuerId": "TEST_FIXTURE_NOT_A_REAL_IDENTITY", "purpose": "DEPLOYMENT",
                                   "issuedAt": 90, "notBefore": 100, "expiresAt": 200,
                                   "manifest": copy.deepcopy(self.manifest), "recovery": None},
                       "signature": {"algorithm": "Ed25519", "keyId": "RFC_VECTOR_NOT_REAL_APPROVER", "signatureHex": VECTORS[1]["signatureHex"]}}
        self.trust = TrustConfig(self.config, digest(canonical(self.config)))
        self.verifier = OfflineApprovalVerifier(self.trust)
        self.clock = FixtureClock()
        self.gate = self.make_gate()
        self.context = context_for(prototype, self.gate)
        self.j = Journal(self.root / "journal", self.context, self.root, create=True)

    def tearDown(self):
        self.j.close()
        self.temp.cleanup()
        self.assertFalse(self.root.exists())

    def make_gate(self):
        record = {"approvalId": "e" * 64, "scope": "OFFLINE_GATE_TEST_ONLY", "issuer": "FIXTURE_NOT_REAL_APPROVER",
                  "realExecutionEnabled": False, "issuedAt": 90, "notBefore": 100, "expiresAt": 200,
                  "manifest": copy.deepcopy(self.manifest), "externalApprovalSHA256": digest(canonical(self.signed)),
                  "externalTrustSHA256": self.trust.pin}
        return ApprovalGate(enabled=True, authority=FixtureAuthority([record]), record=record, clock=self.clock)

    def bound(self, io=None, gate=None):
        binding = ApprovalBinding(self.verifier, self.signed, self.clock)
        return AuthorityBoundMockBackend(self.p, self.g, self.packet, digest(canonical(self.packet)), io or self.io,
                                         journal=self.j, gate=gate or self.gate, binding=binding)

    def verify(self, signed=None, config=None, expected=None):
        verifier = self.verifier if config is None else OfflineApprovalVerifier(TrustConfig(config, digest(canonical(config))))
        return verifier.verify(signed or self.signed, expected or self.manifest, self.clock.now())

    def test_real_default_unknown_blocks(self):
        config = json.loads((BASE / "TRUST-CONFIG-UNKNOWN.json").read_text())
        with self.assertRaisesRegex(Denied, "approver-UNKNOWN"):
            self.verify(config=config)

    def test_rfc_signature_cannot_approve_new_json(self):
        with self.assertRaisesRegex(Denied, "signature-invalid"):
            self.verify()

    def test_crypto_receives_exact_domain_and_complete_body(self):
        with patch("lqc_live508.shared.offline_authority.verify_public_signature") as crypto:
            result = self.verify()
        self.assertEqual(crypto.call_args.args[1], DOMAIN + canonical(self.signed["body"]))
        self.assertFalse(result["executionEnabled"])

    def test_unknown_identity_authority_or_missing_evidence(self):
        for field, value in [("identityStatus", "UNKNOWN"), ("authorityStatus", "UNKNOWN"), ("authorityEvidenceSHA256", None)]:
            config = copy.deepcopy(self.config)
            config["keys"]["RFC_VECTOR_NOT_REAL_APPROVER"][field] = value
            with self.assertRaises(Denied):
                self.verify(config=config)

    def test_untrusted_key_and_issuer(self):
        for field, value in [("issuerId", "OTHER"), ("issuerId", None)]:
            signed = copy.deepcopy(self.signed)
            signed["body"][field] = value
            with self.assertRaises(Denied):
                self.verify(signed=signed)
        signed = copy.deepcopy(self.signed)
        signed["signature"]["keyId"] = "OTHER"
        with self.assertRaises(Denied):
            self.verify(signed=signed)

    def test_trust_pin_tamper(self):
        self.trust.document["revision"] = 2
        with self.assertRaisesRegex(Denied, "trust-config-integrity"):
            self.verify()

    def test_revoked_approval_and_key(self):
        for field, value in [("revokedApprovalIds", ["e" * 64]), ("revokedKeyIds", ["RFC_VECTOR_NOT_REAL_APPROVER"])]:
            config = copy.deepcopy(self.config)
            config[field] = value
            with self.assertRaisesRegex(Denied, "revoked"):
                self.verify(config=config)

    def test_expiry_and_trust_key_expiry(self):
        self.clock.time = 200
        with self.assertRaises(Denied):
            self.verify()
        self.clock.time = 100
        config = copy.deepcopy(self.config)
        config["keys"]["RFC_VECTOR_NOT_REAL_APPROVER"]["expiresAt"] = 100
        with self.assertRaises(Denied):
            self.verify(config=config)

    def test_scope_run_chain_genesis_list_mutation(self):
        for field, value in [("chainId", 97), ("runId", "f" * 32), ("genesisSHA256", "f" * 64), ("totalBudget", 1)]:
            signed = copy.deepcopy(self.signed)
            signed["body"]["manifest"][field] = value
            with self.assertRaises(Denied):
                self.verify(signed=signed)
        signed = copy.deepcopy(self.signed)
        signed["body"]["manifest"]["transactions"].reverse()
        with self.assertRaises(Denied):
            self.verify(signed=signed)

    def test_narrowed_role_operation_or_budget_authority(self):
        for field, value in [("roles", ["deployer"]), ("operations", CREATE), ("maximumTotalBudgetAtest", 1)]:
            config = copy.deepcopy(self.config)
            config["keys"]["RFC_VECTOR_NOT_REAL_APPROVER"][field] = value
            with self.assertRaises(Denied):
                self.verify(config=config)

    def test_unknown_role_address(self):
        signed = copy.deepcopy(self.signed)
        signed["body"]["manifest"]["roles"]["owner"] = None
        with self.assertRaises(Denied):
            self.verify(signed=signed, expected=signed["body"]["manifest"])

    def test_canonical_float_rejected(self):
        signed = copy.deepcopy(self.signed)
        signed["body"]["manifest"]["transactions"][0]["gasLimit"] = 1000.0
        with self.assertRaises(Denied):
            self.verify(signed=signed)

    def test_adapter_interfaces_compatible_and_stubs_disabled(self):
        for name in ["read_context", "read_nonce", "submit", "receipt"]:
            self.assertEqual(list(inspect.signature(getattr(RealRPCAdapter, name)).parameters),
                             list(inspect.signature(getattr(MemoryIO, name)).parameters))
        self.assertEqual(list(inspect.signature(RealSignerAdapter.request_signature).parameters),
                         list(inspect.signature(MemoryIO.request_signature).parameters))
        for adapter in (RealRPCAdapter, RealSignerAdapter):
            with self.assertRaises(Denied):
                adapter(enabled=True)

    def test_unsigned_real_input_never_invented(self):
        data = json.loads((BASE / "REAL-INPUTS-UNKNOWN.json").read_text())
        self.assertFalse(data["executionEnabled"])
        self.assertTrue(all(v is None for k, v in data.items() if k not in ("scope", "executionEnabled")))

    def test_policy_mock_normal_bound_transaction(self):
        with patch("lqc_live508.shared.offline_authority.verify_public_signature"):
            b = self.bound()
            b.execute_mock("Asset18", "deployer")
        self.assertEqual(b.result()["operationalState"], "OFFLINE_MOCK_ONLY")
        self.assertFalse(b.result()["realExecutionEnabled"])

    def test_restart_rechecks_expiry_without_journal_change(self):
        with patch("lqc_live508.shared.offline_authority.verify_public_signature"):
            self.bound().execute_mock("Asset18", "deployer")
        self.j.close()
        self.j = Journal(self.root / "journal", self.context, self.root)
        before = (self.j.path / "journal.json").read_bytes()
        self.clock.time = 200
        with patch("lqc_live508.shared.offline_authority.verify_public_signature"), self.assertRaises(Denied):
            self.bound()
        self.assertEqual((self.j.path / "journal.json").read_bytes(), before)

    def test_restart_revocation_without_journal_change(self):
        with patch("lqc_live508.shared.offline_authority.verify_public_signature"):
            self.bound().execute_mock("Asset18", "deployer")
        before = (self.j.path / "journal.json").read_bytes()
        self.trust.document["revokedApprovalIds"] = ["e" * 64]
        with patch("lqc_live508.shared.offline_authority.verify_public_signature"), self.assertRaises(Denied):
            self.bound()
        self.assertEqual((self.j.path / "journal.json").read_bytes(), before)

    def test_uncertain_restart_halted_no_resubmit_preserves_reserve(self):
        with patch("lqc_live508.shared.offline_authority.verify_public_signature"):
            b = self.bound()
            self.io.fail = "submission-failed"
            with self.assertRaises(Denied):
                b.execute_mock("Asset18", "deployer")
            self.assertEqual(b.result()["operationalState"], "HALTED")
            self.j.close()
            self.j = Journal(self.root / "journal", self.context, self.root)
            before = (self.j.path / "journal.json").read_bytes()
            io = MemoryIO(self.p)
            resumed = self.bound(io=io, gate=self.make_gate())
            self.assertEqual(resumed.result()["operationalState"], "HALTED")
            with self.assertRaises(Denied):
                resumed.execute_mock("Asset18", "deployer")
        self.assertEqual(io.calls, [])
        self.assertEqual((self.j.path / "journal.json").read_bytes(), before)
        self.assertEqual(self.j.recover()["reserved"]["deployer"], 1000)

    def test_signed_document_mutates_after_mock_signature_no_submit(self):
        with patch("lqc_live508.shared.offline_authority.verify_public_signature"):
            b = self.bound()
            original = self.io.request_signature
            def sign(tx):
                token = original(tx)
                self.signed["body"]["expiresAt"] = 201
                return token
            with patch.object(self.io, "request_signature", side_effect=sign), self.assertRaises(Denied):
                b.execute_mock("Asset18", "deployer")
        self.assertNotIn("mock-submit", self.io.calls)
        self.assertEqual(b.result()["operationalState"], "HALTED")

    def test_existing_approval_replay_rejected_after_restart(self):
        with patch("lqc_live508.shared.offline_authority.verify_public_signature"):
            self.bound().execute_mock("Asset18", "deployer")
            self.j.close()
            self.j = Journal(self.root / "journal", self.context, self.root)
            io = MemoryIO(self.p)
            resumed = self.bound(io=io, gate=self.make_gate())
            with self.assertRaises(Denied):
                resumed.execute_mock("Asset18", "deployer")
        self.assertEqual(io.calls, [])

    def recovery_document(self):
        evidence = {"scope": "SYNTHETIC_NOT_REAL_CHAIN_EVIDENCE"}
        signed = copy.deepcopy(self.signed)
        signed["body"].update(approvalId="f" * 64, purpose="MANUAL_RECOVERY", recovery={
            "journalSHA256": digest(canonical(self.j.payload)), "chainEvidenceSHA256": digest(canonical(evidence)), "noResubmission": True})
        return signed, evidence

    def test_deployment_approval_cannot_authorize_recovery(self):
        with patch("lqc_live508.shared.offline_authority.verify_public_signature"), self.assertRaises(Denied):
            review_manual_recovery(self.verifier, self.signed, self.manifest, 100, self.j)

    def test_recovery_approval_cannot_authorize_deployment(self):
        signed, evidence = self.recovery_document()
        with patch("lqc_live508.shared.offline_authority.verify_public_signature"), self.assertRaises(Denied):
            self.verify(signed=signed)

    def test_manual_recovery_missing_actual_chain_proof_halted(self):
        signed, evidence = self.recovery_document()
        before = (self.j.path / "journal.json").read_bytes()
        with patch("lqc_live508.shared.offline_authority.verify_public_signature"):
            with self.assertRaises(Denied):
                review_manual_recovery(self.verifier, signed, self.manifest, 100, self.j)
            with self.assertRaisesRegex(Denied, "REAL_CHAIN_EVIDENCE_UNVERIFIED"):
                review_manual_recovery(self.verifier, signed, self.manifest, 100, self.j, evidence)
        self.assertEqual((self.j.path / "journal.json").read_bytes(), before)

    def test_manual_recovery_wrong_snapshot_or_evidence_hash(self):
        signed, evidence = self.recovery_document()
        signed["body"]["recovery"]["journalSHA256"] = "0" * 64
        with patch("lqc_live508.shared.offline_authority.verify_public_signature"), self.assertRaises(Denied):
            review_manual_recovery(self.verifier, signed, self.manifest, 100, self.j, evidence)

    def test_candidates_still_unapproved(self):
        value = json.loads((BASE / "TRANSACTION-ALLOWLIST-CANDIDATE.json").read_text())
        self.assertEqual(len(value["operations"]), 24)
        self.assertFalse(value["executionEnabled"])
        self.assertTrue(all(op["approved"] is False for op in value["operations"]))

    def test_raw_document_duplicate_fields_or_size_rejected(self):
        for raw in [b'{"body":{},"body":{}}', b"NaN", b"x" * 262145]:
            with self.assertRaises((Denied, ValueError)):
                parse_signed_document(raw)

    def test_approval_cannot_replay_into_new_empty_journal_path(self):
        before = (self.j.path / "journal.json").read_bytes()
        with tempfile.TemporaryDirectory(prefix="lqc-prep05-") as other:
            TEMP_PATHS.append(other)
            other_journal = Journal(pathlib.Path(other) / "journal", self.context, other, create=True)
            try:
                binding = ApprovalBinding(self.verifier, self.signed, self.clock)
                io = MemoryIO(self.p)
                with patch("lqc_live508.shared.offline_authority.verify_public_signature"), self.assertRaisesRegex(Denied, "rebound-journal"):
                    AuthorityBoundMockBackend(self.p, self.g, self.packet, digest(canonical(self.packet)), io,
                                              journal=other_journal, gate=self.make_gate(), binding=binding)
                self.assertEqual(io.calls, [])
            finally:
                other_journal.close()
        self.assertEqual((self.j.path / "journal.json").read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
