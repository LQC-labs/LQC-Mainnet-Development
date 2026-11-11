"""Use setup-node/PATH's executable, never a workspace-specific node_modules path."""
import os
import pathlib
import shutil
from .shared.mock_backend import need

def node_executable():
    path = shutil.which('node')
    need(path is not None and pathlib.Path(path).is_absolute(), 'Node-required-on-PATH')
    return path

def codec_path(name):
    need(name in {'transaction_hash.cjs', 'evm_transaction_codec.cjs', 'evidence_codec.cjs', 'test_process_guard.cjs', 'fixture_events.cjs'}, 'codec-allowlist')
    return pathlib.Path(__file__).resolve().parent / 'codecs' / name

def codec_env():
    return {'PATH': os.environ.get('PATH', ''), 'LANG': 'C.UTF-8', 'NODE_OPTIONS': '--max-old-space-size=256'}
