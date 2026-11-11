from pathlib import Path
WORKSPACE = Path(__file__).resolve().parent.parent
"""Reuse the preserved implementation without copying or enabling its mock path."""
import pathlib

from lqc_live508.shared.durable_journal import Journal, strict_json
from lqc_live508.shared.mock_backend import need, canonical, digest, allowed, Denied
from lqc_live508.shared.journal_backend import JournaledMockBackend
from lqc_live508.shared.approval_gate import transaction_scope


def plan_from_backend(backend):
    """Reuse the exact existing envelope builder, never execute_mock or MemoryIO.

    The caller supplies the existing pinned plan/entries/profile view. Scope is
    changed explicitly; signatures, synthetic hashes and receipts are not copied.
    """
    manifest = transaction_scope(backend)
    envelopes = []
    for operation in backend.plan:
        tx = JournaledMockBackend.expected_envelope(backend, operation)
        tx['scope'] = 'DEVNET_TRANSACTION_V1'
        envelopes.append(tx)
    return manifest, envelopes
