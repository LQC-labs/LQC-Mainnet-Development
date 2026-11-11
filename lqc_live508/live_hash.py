from lqc_live508.node_runtime import node_executable, codec_path, codec_env
"""Ethereum Keccak of supplied bytes; does not construct or sign a transaction."""
import pathlib
import re
import subprocess
from lqc_live508.journal_reuse import need


def transaction_hash(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 131072, 'raw-transaction-size')
    result = subprocess.run([node_executable(), str(codec_path('transaction_hash.cjs'))],
                            input=raw, capture_output=True, timeout=10, check=False,
                            env=codec_env())
    need(result.returncode == 0 and re.fullmatch(b'0x[0-9a-f]{64}', result.stdout), 'transaction-hash-codec')
    return result.stdout.decode('ascii')
