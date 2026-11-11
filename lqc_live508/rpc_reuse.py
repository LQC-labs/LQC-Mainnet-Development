from pathlib import Path
WORKSPACE = Path(__file__).resolve().parent.parent
"""Import existing journal/contracts and the shared RPC parser, never execute them."""
import pathlib

from lqc_live508.journal_reuse import need, canonical, digest, strict_json, Denied
from lqc_live508.live_contracts import validate_contract, UnimplementedVerification
from lqc_live508.shared.offline_adapters import OfflineRPCAdapter, validate_rpc_response, quantity, READS
