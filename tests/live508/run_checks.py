"""Bounded Linux-only synthetic suite. Results go to a NEW external directory."""
import argparse
import ast
from functools import lru_cache
import hashlib
import importlib
import importlib.metadata
import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import ec
from lqc_live508.node_runtime import node_executable, codec_path
from lqc_live508 import live_journal

ROOT=pathlib.Path(__file__).resolve().parents[2]

def run(output):
    output=pathlib.Path(output).absolute()
    if output==ROOT or ROOT in output.parents: raise ValueError('results must be outside source checkout')
    output.mkdir(mode=0o700,parents=True,exist_ok=False)
    node=node_executable()
    version=subprocess.run([node,'--version'],capture_output=True,text=True,check=True,timeout=10).stdout.strip()
    if version!='v22.16.0' or sys.version_info[:3]!=(3,12,3): raise RuntimeError('Python 3.12.3 / Node 22.16.0 required')
    actual_deps={name:importlib.metadata.version(name) for name in ['cryptography','cffi','pycparser']}
    if actual_deps!={'cryptography':'41.0.7','cffi':'1.17.1','pycparser':'2.22'}:raise RuntimeError('locked Python environment required')
    source_files=[*ROOT.glob('lqc_live508/**/*.py'),*ROOT.glob('tests/live508/**/*.py')]
    for p in source_files:ast.parse(p.read_text(),filename=str(p))
    manifest=json.loads((ROOT/'verification/live508/SOURCE-SHA256.json').read_text())
    mismatches=[n for n,h in manifest.items() if hashlib.sha256((ROOT/n).read_bytes()).hexdigest()!=h]
    if mismatches:raise RuntimeError('current integration source integrity failed: '+','.join(mismatches))
    allowed={str(codec_path(n)) for n in ['transaction_hash.cjs','evm_transaction_codec.cjs','evidence_codec.cjs','fixture_events.cjs']}
    real=subprocess.Popen;counts={'localCodecs':0,'forbiddenProcess':0};results={}
    before=set(pathlib.Path('/tmp').glob('lqc*-test-*'))|set(pathlib.Path('/tmp').glob('lqc508-rollback-*'))
    with tempfile.TemporaryDirectory(prefix='lqc508-guard-') as d:
        guard=pathlib.Path(d)/'attempts.log'
        def popen(args,*rest,**kw):
            if not(type(args) is list and len(args)==2 and args[0]==node and args[1] in allowed):
                counts['forbiddenProcess']+=1;raise AssertionError('only pinned local codecs permitted')
            counts['localCodecs']+=1
            env=dict(kw.get('env',os.environ));env['LQC_TEST_GUARD_LOG']=str(guard);kw['env']=env
            return real([node,'--require',str(codec_path('test_process_guard.cjs')),args[1]],*rest,**kw)
        with patch.object(live_journal,'transaction_hash',new=lru_cache(maxsize=128)(live_journal.transaction_hash)), \
             patch.object(socket,'socket',side_effect=AssertionError('REAL SOCKET FORBIDDEN')) as sockets, \
             patch.object(socket,'getaddrinfo',side_effect=AssertionError('DNS FORBIDDEN')) as dns, \
             patch.object(subprocess,'Popen',side_effect=popen), \
             patch.object(Ed25519PrivateKey,'generate',side_effect=AssertionError('KEY FORBIDDEN')) as edgen, \
             patch.object(Ed25519PrivateKey,'from_private_bytes',side_effect=AssertionError('KEY FORBIDDEN')) as edload, \
             patch.object(ec,'generate_private_key',side_effect=AssertionError('KEY FORBIDDEN')) as ecgen:
            modules={n:importlib.import_module('tests.live508.'+n) for n in ['test_live_journal','test_live_rpc','test_live_authority_signer','test_live_execution','test_security_boundary','test_offline_adapters','test_authority_recovery','test_fixture_collector']}
            suites=[(n,unittest.defaultTestLoader.loadTestsFromModule(modules[n])) for n in ['test_security_boundary','test_live_journal','test_live_rpc','test_live_authority_signer','test_live_execution','test_fixture_collector']]
            suites += [('RPCParserRegression',unittest.defaultTestLoader.loadTestsFromTestCase(modules['test_offline_adapters'].CodecTests)),('PublicEd25519Vectors',unittest.defaultTestLoader.loadTestsFromTestCase(modules['test_authority_recovery'].CryptoTests))]
            suites += [('ApprovalBindingRegression',unittest.TestSuite(modules['test_authority_recovery'].AuthorityTests(n) for n in [
                'test_policy_mock_normal_bound_transaction','test_restart_rechecks_expiry_without_journal_change','test_restart_revocation_without_journal_change',
                'test_signed_document_mutates_after_mock_signature_no_submit','test_approval_cannot_replay_into_new_empty_journal_path']))]
            with (output/'tests.log').open('x') as log:
                for label,suite in suites:
                    result=unittest.TextTestRunner(stream=log,verbosity=2).run(suite)
                    results[label]={'tests':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'skipped':len(result.skipped),'success':result.wasSuccessful()}
                    print(label,json.dumps(results[label]),flush=True)
            attempts={'socket':sockets.call_count,'DNS':dns.call_count,'Ed25519Generate':edgen.call_count,'privateKeyImport':edload.call_count,'ECGenerate':ecgen.call_count,'forbiddenProcess':counts['forbiddenProcess']}
        node_attempts=guard.read_text().splitlines() if guard.exists() else []
    remaining=sorted(str(p) for p in (set(pathlib.Path('/tmp').glob('lqc*-test-*'))|set(pathlib.Path('/tmp').glob('lqc508-rollback-*')))-before)
    unchanged=all(hashlib.sha256((ROOT/n).read_bytes()).hexdigest()==h for n,h in manifest.items())
    ok=all(x['success'] for x in results.values()) and not any(attempts.values()) and not node_attempts and not remaining and unchanged
    total=sum(x['tests'] for x in results.values());fail=sum(x['failures'] for x in results.values());err=sum(x['errors'] for x in results.values());skip=sum(x['skipped'] for x in results.values())
    report={'suites':results,'PASS':total-fail-err-skip,'FAIL':fail,'ERROR':err,'SKIP':skip,'Python':sys.version.split()[0],'Node':version,'nodeExecutable':node,'pythonDependencies':actual_deps,'forbiddenAPIAttempts':attempts,'nodeGuardAttempts':node_attempts,'localCodecCalls':counts['localCodecs'],'remainingOwnedTemporaryPaths':remaining,'sourceUnchanged':unchanged,'approvalPositiveTests':'structured JSON Ed25519 seam mocked; public RFC signatures independently verified','actualRPC':'NOT RUN','actualFlowE2E':'UNVERIFIED','official5.08':'BLOCKED','mainnet':'NO-GO','exitCode':0 if ok else 1}
    (output/'TEST-RESULT.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:report[k] for k in ['PASS','FAIL','ERROR','SKIP','exitCode']}))
    return report['exitCode']
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output',required=True);args=parser.parse_args();raise SystemExit(run(args.output))
