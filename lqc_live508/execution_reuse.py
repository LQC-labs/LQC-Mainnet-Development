from pathlib import Path
WORKSPACE = Path(__file__).resolve().parent.parent
"""Import existing execution/verification code; never activate it on import."""
import pathlib

from lqc_live508.authority_reuse import need, canonical, digest, Denied, validate_contract
from lqc_live508.shared.offline_adapters import validate_rpc_response, validate_rpc_envelope, quantity, hexdata, public_address, READS
from lqc_live508.live_rpc import LiveRPC, LoopbackTransport, RPCBoundVerification, remaining
from lqc_live508.live_authority_binding import LiveAuthorityBinding, approval_scope
from lqc_live508.shared.offline_authority import parse_signed_document

from lqc_live508.shared.runtime_evidence import verify_runtime
