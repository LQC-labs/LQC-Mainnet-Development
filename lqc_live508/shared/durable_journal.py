"""Crash-detecting JSON journal for private offline test directories only; no chain DB."""
import copy
import fcntl
import json
import os
import pathlib
import re
import stat
from lqc_live508.shared.mock_backend import Denied, need, canonical, digest, allowed


TRANSITIONS = {None: {"RESERVED"}, "RESERVED": {"SIGN_REQUESTED", "FAILED"},
               "SIGN_REQUESTED": {"SUBMIT_INTENT", "FAILED"},
               "SUBMIT_INTENT": {"SUBMITTED", "UNCERTAIN"},
               "SUBMITTED": {"CONFIRMED", "FAILED"}, "CONFIRMED": set(), "FAILED": set(), "UNCERTAIN": set()}
FIELDS = {"runId", "chainId", "genesisSHA256", "approvalId", "role", "operation", "nonce", "txSHA256",
          "txHash", "maxReserveAtest", "reservedAtest", "spentAtest", "state", "receiptSHA256", "reason"}


def strict_json(raw):
    def pairs(items):
        value = {}
        for key, entry in items:
            need(key not in value, "journal-duplicate-field")
            value[key] = entry
        return value
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(Denied("journal-number")))


class Journal:
    def __init__(self, directory, context, allowed_root, *, create=False):
        self.path = pathlib.Path(directory)
        self.root = pathlib.Path(allowed_root)
        self.context = copy.deepcopy(context)
        self.poisoned = False
        self.closed = False
        self.lock_fd = None
        need(self.root.is_absolute() and self.root.parent == pathlib.Path("/tmp") and
             re.fullmatch("lqc-prep05-[a-z0-9_]+", self.root.name), "journal-approved-temp-root")
        need(self.path == self.root / "journal", "journal-exact-path")
        for part in [self.root, *self.root.parents]:
            need(not part.is_symlink(), "journal-ancestor-symlink")
        root_stat = self.root.stat()
        need(root_stat.st_uid == os.getuid() and stat.S_IMODE(root_stat.st_mode) == 0o700, "journal-root-owner-mode")
        need(set(context) == {"scope", "runId", "chainId", "genesisSHA256", "approvalId", "approvalSHA256", "manifestSHA256"}, "journal-context-fields")
        need(context["scope"] == "OFFLINE_FIXTURE_JOURNAL_ONLY" and type(context["chainId"]) is int and context["chainId"] == 917001, "journal-context-scope")
        for key, length in [("runId", 32), ("genesisSHA256", 64), ("approvalId", 64), ("approvalSHA256", 64), ("manifestSHA256", 64)]:
            need(type(context[key]) is str and re.fullmatch("[a-f0-9]{" + str(length) + "}", context[key]), "journal-context-value")
        if create:
            need(not self.path.exists() and not self.path.is_symlink(), "journal-create-existing")
            self.path.mkdir(mode=0o700)
            self._new_file("owner.json", canonical({"contextSHA256": digest(canonical(context))}))
            self._new_file("lock", b"")
        need(self.path.is_dir() and not self.path.is_symlink(), "journal-directory-missing")
        need(self.path.stat().st_uid == os.getuid() and stat.S_IMODE(self.path.stat().st_mode) == 0o700, "journal-directory-owner-mode")
        self.identity = (self.path.stat().st_dev, self.path.stat().st_ino)
        for child in self.path.iterdir():
            need(not child.is_symlink(), "journal-child-symlink")
        for name in ["owner.json", "lock"]:
            self._safe_file(name)
        need(strict_json((self.path / "owner.json").read_bytes()) == {"contextSHA256": digest(canonical(context))}, "journal-owner-binding")
        try:
            self.lock_fd = os.open(self.path / "lock", os.O_RDWR | os.O_NOFOLLOW)
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.lock_identity = os.fstat(self.lock_fd)
            if create:
                self.payload = {"schema": 1, "context": self.context, "generation": 0, "records": {}, "events": []}
                self._store(self.payload)
            self.payload = self._load()
        except Exception:
            self.close()
            raise

    def _new_file(self, name, content):
        fd = os.open(self.path / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
        except Exception:
            raise

    def _safe_file(self, name):
        p = self.path / name
        need(p.exists() and not p.is_symlink() and p.is_file(), "journal-file-missing-or-symlink")
        st = p.stat()
        need(st.st_uid == os.getuid() and stat.S_IMODE(st.st_mode) == 0o600 and st.st_nlink == 1, "journal-file-owner-mode")

    def _guard(self):
        need(not self.closed and not self.poisoned, "journal-closed-or-poisoned")
        need(not self.path.is_symlink() and (self.path.stat().st_dev, self.path.stat().st_ino) == self.identity, "journal-directory-replaced")
        need(self.path.stat().st_uid == os.getuid() and stat.S_IMODE(self.path.stat().st_mode) == 0o700, "journal-directory-owner-mode")
        self._safe_file("lock")
        st = (self.path / "lock").stat()
        need((st.st_dev, st.st_ino) == (self.lock_identity.st_dev, self.lock_identity.st_ino), "journal-lock-replaced")

    def _atomic(self, name, content):
        # Temp+fsync+rename+directory fsync. Leftover temp or checkpoint mismatch fails closed.
        temp = name + ".new"
        self._new_file(temp, content)
        os.replace(self.path / temp, self.path / name)
        fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _store(self, payload):
        checksum = digest(canonical(payload))
        try:
            self._atomic("journal.json", canonical({"payload": payload, "sha256": checksum}))
            self._atomic("checkpoint.json", canonical({"generation": payload["generation"], "sha256": checksum}))
        except Exception:
            self.poisoned = True
            raise

    def _validate_record(self, record, prior):
        need(type(record) is dict and set(record) == FIELDS, "journal-record-schema")
        need(all(record[k] == self.context[k] for k in ("runId", "chainId", "genesisSHA256", "approvalId")), "journal-record-binding")
        need(type(record["operation"]) is str and allowed(record["role"], record["operation"]), "journal-role-operation")
        for key in ("nonce", "maxReserveAtest", "reservedAtest", "spentAtest"):
            need(type(record[key]) is int and 0 <= record[key] < 2**256, "journal-record-integer")
        need(record["maxReserveAtest"] > 0 and record["txHash"] == "MOCK_TX:" + record["txSHA256"] and
             re.fullmatch("[0-9a-f]{64}", record["txSHA256"]), "journal-transaction-hash")
        old = prior["state"] if prior else None
        need(record["state"] in TRANSITIONS.get(old, set()), "journal-state-transition")
        if prior:
            immutable = FIELDS - {"state", "reservedAtest", "spentAtest", "receiptSHA256", "reason"}
            need(all(record[k] == prior[k] for k in immutable), "journal-immutable-record")
        if record["state"] == "CONFIRMED":
            need(record["reservedAtest"] == 0 and record["spentAtest"] <= record["maxReserveAtest"] and
                 type(record["receiptSHA256"]) is str and re.fullmatch("[0-9a-f]{64}", record["receiptSHA256"]), "journal-confirmation")
        else:
            need(record["reservedAtest"] == record["maxReserveAtest"] and record["spentAtest"] == 0 and
                 record["receiptSHA256"] is None, "journal-reservation-state")
        need(record["reason"] in (None, "ADAPTER_OR_GATE_FAILURE", "SUBMISSION_UNCERTAIN"), "journal-reason-allowlist")
        expected_reason = "SUBMISSION_UNCERTAIN" if record["state"] == "UNCERTAIN" else "ADAPTER_OR_GATE_FAILURE" if record["state"] == "FAILED" else None
        need(record["reason"] == expected_reason, "journal-state-reason")

    def _load(self):
        try:
            return self._load_checked()
        except Exception:
            self.poisoned = True
            raise

    def _load_checked(self):
        self._guard()
        need({p.name for p in self.path.iterdir()} == {"owner.json", "lock", "journal.json", "checkpoint.json"}, "journal-missing-or-uncommitted-file")
        for name in ("journal.json", "checkpoint.json"):
            self._safe_file(name)
        envelope = strict_json((self.path / "journal.json").read_bytes())
        checkpoint = strict_json((self.path / "checkpoint.json").read_bytes())
        need(set(envelope) == {"payload", "sha256"}, "journal-envelope")
        payload = envelope["payload"]
        need(set(payload) == {"schema", "context", "generation", "records", "events"} and type(payload["schema"]) is int and payload["schema"] == 1 and
             payload["context"] == self.context, "journal-schema-context")
        checksum = digest(canonical(payload))
        need(type(checkpoint) is dict and type(checkpoint.get("generation")) is int and envelope["sha256"] == checksum and checkpoint == {"generation": payload["generation"], "sha256": checksum}, "journal-checkpoint-integrity")
        need(type(payload["events"]) is list and type(payload["records"]) is dict and
             type(payload["generation"]) is int and payload["generation"] == len(payload["events"]), "journal-generation")
        records, previous = {}, "0" * 64
        for index, event in enumerate(payload["events"], 1):
            need(set(event) == {"seq", "key", "record", "previous", "sha256"}, "journal-event-schema")
            raw = {k: event[k] for k in ("seq", "key", "record", "previous")}
            need(type(event["seq"]) is int and event["seq"] == index and event["previous"] == previous and digest(canonical(raw)) == event["sha256"], "journal-event-chain")
            record, key = event["record"], event["key"]
            self._validate_record(record, records.get(key))
            need(key == record["role"] + ":" + str(record["nonce"]), "journal-nonce-key")
            if key not in records:
                need(not any(x["operation"] == record["operation"] or x["txHash"] == record["txHash"] for x in records.values()), "journal-duplicate-operation-or-hash")
            records[key] = record
            previous = event["sha256"]
        need(records == payload["records"], "journal-state-projection")
        return payload

    def _append(self, record):
        self.payload = self._load()
        payload = copy.deepcopy(self.payload)
        key = record["role"] + ":" + str(record["nonce"])
        self._validate_record(record, payload["records"].get(key))
        if key not in payload["records"]:
            need(not any(x["operation"] == record["operation"] or x["txHash"] == record["txHash"] for x in payload["records"].values()), "journal-duplicate-operation-or-hash")
        event = {"seq": payload["generation"] + 1, "key": key, "record": record,
                 "previous": payload["events"][-1]["sha256"] if payload["events"] else "0" * 64}
        event["sha256"] = digest(canonical(event))
        payload["events"].append(event)
        payload["records"][key] = record
        payload["generation"] += 1
        self._store(payload)
        self.payload = self._load()

    def reserve(self, tx):
        need(type(tx) is dict and set(tx) == {"runId", "chainId", "genesisSHA256", "scope", "operation", "role", "from", "to", "data", "nonce", "gasLimit", "maxFee", "maxPriority", "value"}, "journal-transaction-fields")
        need(tx["scope"] == "OFFLINE_SIMULATION" and type(tx["chainId"]) is int and
             all(tx[k] == self.context[k] for k in ("runId", "chainId", "genesisSHA256")), "journal-transaction-context")
        need(allowed(tx["role"], tx["operation"]), "journal-transaction-operation")
        need(all(type(tx[k]) is int and 0 <= tx[k] < 2**256 for k in ("nonce", "gasLimit", "maxFee", "maxPriority", "value")) and
             tx["gasLimit"] > 0 and tx["maxFee"] > 0 and tx["maxPriority"] <= tx["maxFee"] and tx["value"] == 0, "journal-transaction-fees")
        self.payload = self._load()
        key = tx["role"] + ":" + str(tx["nonce"])
        need(key not in self.payload["records"], "journal-duplicate-nonce")
        record = {k: self.context[k] for k in ("runId", "chainId", "genesisSHA256", "approvalId")}
        fingerprint = digest(canonical(tx))
        reserve = tx["gasLimit"] * tx["maxFee"]
        record.update(role=tx["role"], operation=tx["operation"], nonce=tx["nonce"], txSHA256=fingerprint,
                      txHash="MOCK_TX:" + fingerprint, maxReserveAtest=reserve, reservedAtest=reserve,
                      spentAtest=0, state="RESERVED", receiptSHA256=None, reason=None)
        self._append(record)

    def transition(self, role, nonce, state, *, receipt=None):
        self.payload = self._load()
        record = copy.deepcopy(self.payload["records"][role + ":" + str(nonce)])
        record["state"] = state
        if state == "CONFIRMED":
            record.update(reservedAtest=0, spentAtest=receipt["gasUsed"] * receipt["effectiveGasPrice"], receiptSHA256=digest(canonical(receipt)))
        if state in ("FAILED", "UNCERTAIN"):
            record["reason"] = "SUBMISSION_UNCERTAIN" if state == "UNCERTAIN" else "ADAPTER_OR_GATE_FAILURE"
        self._append(record)

    def recover(self):
        self.payload = self._load()
        records = copy.deepcopy(self.payload["records"])
        return {"records": records, "blocked": any(r["state"] != "CONFIRMED" for r in records.values()),
                "reserved": {role: sum(r["reservedAtest"] for r in records.values() if r["role"] == role) for role in ("deployer", "owner", "guardian")},
                "spent": {role: sum(r["spentAtest"] for r in records.values() if r["role"] == role) for role in ("deployer", "owner", "guardian")}}

    def close(self):
        if self.lock_fd is not None:
            try:
                fcntl.flock(self.lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(self.lock_fd)
                self.lock_fd = None
        self.closed = True
