"""Public-key verification only. No key generation, signing or live execution API."""
import copy
import re
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from lqc_live508.shared.mock_backend import need, canonical, digest, allowed
from lqc_live508.shared.durable_journal import strict_json

DOMAIN = b"LQC_APPROVAL_V1\n"
BODY_FIELDS = {"schema", "approvalId", "issuerId", "purpose", "issuedAt", "notBefore", "expiresAt", "manifest", "recovery"}


def parse_signed_document(raw):
    need(type(raw) is bytes and len(raw) <= 262144, "approval-input-size-or-type")
    document = strict_json(raw)
    no_float(document)
    return document


def hex_bytes(value, length):
    need(type(value) is str and re.fullmatch("[0-9a-f]{" + str(2 * length) + "}", value), "public-signature-encoding")
    return bytes.fromhex(value)


def verify_public_signature(public_key, message, signature):
    """Ed25519 verify only; accepts already supplied public bytes, never a private key."""
    try:
        Ed25519PublicKey.from_public_bytes(hex_bytes(public_key, 32)).verify(hex_bytes(signature, 64), message)
    except (InvalidSignature, ValueError):
        need(False, "approval-signature-invalid")


def no_float(value):
    need(type(value) in (dict, list, str, int, bool, type(None)), "approval-noncanonical-type")
    if type(value) is dict:
        need(all(type(key) is str for key in value), "approval-noncanonical-key")
        for v in value.values():
            no_float(v)
    elif type(value) is list:
        for v in value:
            no_float(v)


class TrustConfig:
    """Explicit operator-pinned trust assertion; signature does not itself prove legal identity."""
    def __init__(self, document, externally_pinned_digest):
        self.document = copy.deepcopy(document)
        self.pin = externally_pinned_digest
        self.check_pin()

    def check_pin(self):
        need(type(self.pin) is str and re.fullmatch("[0-9a-f]{64}", self.pin) and digest(canonical(self.document)) == self.pin,
             "trust-config-integrity")


class OfflineApprovalVerifier:
    def __init__(self, trust):
        need(type(trust) is TrustConfig, "explicit-trust-config-required")
        self.trust = trust

    def verify(self, signed, expected_manifest, now, *, purpose="DEPLOYMENT"):
        self.trust.check_pin()
        trust = self.trust.document
        need(trust.get("schema") == 1 and trust.get("status") == "PINNED_EXTERNAL_IDENTITY_ASSERTIONS", "approver-UNKNOWN")
        need(type(trust.get("revision")) is int and trust["revision"] >= 1 and type(now) is int, "trust-revision-or-time")
        need(type(trust.get("validFrom")) is int and type(trust.get("validUntil")) is int and
             trust["validFrom"] <= now < trust["validUntil"], "trust-config-expired")
        need(type(signed) is dict and set(signed) == {"body", "signature"}, "approval-envelope")
        no_float(signed)
        body, signature = signed["body"], signed["signature"]
        need(type(body) is dict and set(body) == BODY_FIELDS and body["schema"] == "LQC_APPROVAL_V1", "approval-schema")
        need(type(signature) is dict and set(signature) == {"algorithm", "keyId", "signatureHex"} and
             signature["algorithm"] == "Ed25519", "approval-signature-schema")
        need(type(body["issuerId"]) is str and body["issuerId"] and type(signature["keyId"]) is str and signature["keyId"], "approver-id-UNKNOWN")
        need(type(body["approvalId"]) is str and re.fullmatch("[0-9a-f]{64}", body["approvalId"]), "approval-id")
        need(body["approvalId"] not in trust["revokedApprovalIds"] and signature["keyId"] not in trust["revokedKeyIds"], "approval-or-key-revoked")
        key = trust["keys"].get(signature["keyId"])
        need(type(key) is dict and key.get("issuerId") == body["issuerId"], "unknown-issuer-key")
        need(key.get("identityStatus") == "VERIFIED_BY_PINNED_EXTERNAL_EVIDENCE" and
             key.get("authorityStatus") == "VERIFIED_BY_PINNED_EXTERNAL_EVIDENCE", "approver-identity-authority-UNKNOWN")
        for field in ("identityEvidenceSHA256", "authorityEvidenceSHA256"):
            need(type(key.get(field)) is str and re.fullmatch("[0-9a-f]{64}", key[field]), "authority-evidence-missing")
        need(type(key.get("notBefore")) is int and type(key.get("expiresAt")) is int and key["notBefore"] <= now < key["expiresAt"], "approver-key-expired")
        need(purpose in ("DEPLOYMENT", "MANUAL_RECOVERY") and body["purpose"] == purpose and purpose in key["purposes"], "approval-purpose-denied")
        times = [body[k] for k in ("issuedAt", "notBefore", "expiresAt")]
        need(all(type(t) is int for t in times) and times[0] <= times[1] <= now < times[2] and
             0 < times[2] - times[0] <= 240, "approval-expired-or-not-yet-valid")
        manifest = body["manifest"]
        need(type(manifest) is dict and manifest == expected_manifest and type(manifest.get("chainId")) is int and
             manifest["chainId"] == 917001 and 917001 in key["chainIds"], "approval-exact-run-scope")
        need(type(manifest.get("runId")) is str and re.fullmatch("[a-f0-9]{32}", manifest["runId"]) and
             type(manifest.get("genesisSHA256")) is str and re.fullmatch("[a-f0-9]{64}", manifest["genesisSHA256"]), "approval-run-genesis")
        need(type(manifest.get("totalBudget")) is int and 0 <= manifest["totalBudget"] <= key["maximumTotalBudgetAtest"], "approval-budget-authority")
        need(type(manifest.get("roles")) is dict and set(manifest["roles"]) == {"deployer", "owner", "guardian"} and
             all(type(a) is str and re.fullmatch("0x[0-9a-f]{40}", a) and int(a, 16) > 0 for a in manifest["roles"].values()) and
             len(set(manifest["roles"].values())) == 3, "approval-role-address-UNKNOWN")
        need(set(manifest["roleBudgets"]) == set(manifest["roles"]), "approval-role-budget-set")
        for field in ("profileSHA256", "ABIPlanSHA256"):
            hex_bytes(manifest[field], 32)
        for role, budget in manifest["roleBudgets"].items():
            need(role in key["roles"] and type(budget) is int and 0 <= budget <= key["maximumRoleBudgetAtest"].get(role, -1), "approval-role-budget-authority")
        operations = manifest["transactions"]
        need(type(operations) is list and operations, "approval-transaction-list")
        seen_nonce, seen_operation = set(), set()
        costs = dict.fromkeys(manifest["roles"], 0)
        for tx in operations:
            need(tx["role"] in key["roles"] and tx["operation"] in key["operations"] and allowed(tx["role"], tx["operation"]), "approval-role-operation-authority")
            need(tx["from"] == manifest["roles"][tx["role"]] and tx["value"] == 0, "approval-caller-value")
            for field in ("nonce", "gasLimit", "maxFee", "maxPriority"):
                need(type(tx[field]) is int and 0 <= tx[field] < 2**256, "approval-transaction-integer")
            need(tx["gasLimit"] > 0 and tx["maxFee"] > 0 and tx["maxPriority"] <= tx["maxFee"] and
                 type(tx["dataSHA256"]) is str and re.fullmatch("[a-f0-9]{64}", tx["dataSHA256"]), "approval-transaction-limits")
            nonce_key = (tx["role"], tx["nonce"])
            need(nonce_key not in seen_nonce and tx["operation"] not in seen_operation, "approval-duplicate-nonce-operation")
            seen_nonce.add(nonce_key)
            seen_operation.add(tx["operation"])
            costs[tx["role"]] += tx["gasLimit"] * tx["maxFee"]
        need(all(costs[r] <= manifest["roleBudgets"][r] for r in costs) and sum(costs.values()) <= manifest["totalBudget"], "approval-plan-budget")
        if purpose == "DEPLOYMENT":
            need(body["recovery"] is None, "recovery-authority-not-deployment-authority")
        else:
            recovery = body["recovery"]
            need(type(recovery) is dict and set(recovery) == {"journalSHA256", "chainEvidenceSHA256", "noResubmission"} and
                 recovery["noResubmission"] is True, "separate-manual-recovery-scope-required")
            hex_bytes(recovery["journalSHA256"], 32)
            hex_bytes(recovery["chainEvidenceSHA256"], 32)
        verify_public_signature(key["publicKeyHex"], DOMAIN + canonical(body), signature["signatureHex"])
        return {"status": "SIGNATURE_AND_PINNED_SCOPE_VERIFIED", "approvalId": body["approvalId"],
                "documentSHA256": digest(canonical(signed)), "trustSHA256": self.trust.pin,
                "identityMeaning": "PINNED_EXTERNAL_ASSERTION_NOT_INDEPENDENT_LEGAL_PROOF", "executionEnabled": False}
