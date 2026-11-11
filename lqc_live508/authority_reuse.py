from pathlib import Path
WORKSPACE = Path(__file__).resolve().parent.parent
"""Reuse existing live and approval implementations; no activation on import."""
import pathlib

from lqc_live508.rpc_reuse import need, canonical, digest, Denied, validate_contract
from lqc_live508.shared.offline_authority import OfflineApprovalVerifier, TrustConfig, parse_signed_document
from lqc_live508.shared.authority_binding import ApprovalBinding
from lqc_live508.live_journal import LiveJournal

