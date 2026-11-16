#!/usr/bin/env python3
"""Offline reproducibility check; never downloads or overwrites artifacts."""
import argparse,pathlib,json,hashlib,subprocess
p=argparse.ArgumentParser();p.add_argument('--solc',required=True);args=p.parse_args()
root=pathlib.Path(__file__).resolve().parents[1];fixture=root/'node/testdata/flow-minimal'
meta=json.loads((fixture/'SOURCE.json').read_text());compiler=pathlib.Path(args.solc).resolve()
assert hashlib.sha256(compiler.read_bytes()).hexdigest()==meta['compilerProof']['compiler_sha256'],'compiler SHA-256 mismatch'
version=subprocess.check_output([str(compiler),'--version'],text=True,timeout=10)
assert '0.8.30+commit.73712a01' in version
for name,record in meta['original_sources'].items():
 data=(fixture/name).read_bytes()
 assert hashlib.sha256(data).hexdigest()==record['sha256'],'pinned source modified'
 assert hashlib.sha1(b'blob '+str(len(data)).encode()+bytes([0])+data).hexdigest()==record['gitBlobSha']
for name,record in meta.get('patched_sources',{}).items():
 data=(fixture/name).read_bytes();upstream=(fixture/record['upstreamCopy']).read_bytes()
 assert hashlib.sha256(data).hexdigest()==record['sha256'],'local Router patch changed'
 assert hashlib.sha256(upstream).hexdigest()==record['upstreamSha256'],'upstream Router copy changed'
 assert hashlib.sha1(b'blob '+str(len(upstream)).encode()+bytes([0])+upstream).hexdigest()==record['upstreamGitBlobSha']
for name,record in meta['localFixtures'].items():assert hashlib.sha256((fixture/name).read_bytes()).hexdigest()==record['sha256']
sources={str(f.relative_to(fixture)):{'content':f.read_text()} for f in sorted((fixture/'contracts').rglob('*.sol'))}
settings={**meta['settings'],'outputSelection':{'*':{'*':['abi','evm.bytecode.object','evm.deployedBytecode.object','evm.deployedBytecode.immutableReferences']}}}
r=subprocess.run([str(compiler),'--standard-json'],input=json.dumps({'language':'Solidity','sources':sources,'settings':settings}).encode(),capture_output=True,timeout=90)
assert r.returncode==0,r.stderr.decode();out=json.loads(r.stdout);assert not [e for e in out.get('errors',[]) if e['severity']=='error']
checked=[]
for source,contracts in out['contracts'].items():
 for name,a in contracts.items():
  if name not in meta['compiledArtifacts']:continue
  artifact={'contractName':name,'sourceName':source,'compiler':'0.8.30+commit.73712a01','abi':a['abi'],'bytecode':'0x'+a['evm']['bytecode']['object'],'deployedBytecode':'0x'+a['evm']['deployedBytecode']['object'],'immutableReferences':a['evm']['deployedBytecode']['immutableReferences']}
  expected=(json.dumps(artifact,indent=2)+'\n').encode();stored=(fixture/'artifacts'/(name+'.json')).read_bytes()
  assert expected==stored,'non-reproducible artifact '+name
  assert hashlib.sha256(stored).hexdigest()==meta['compiledArtifacts'][name]['sha256'];checked.append(name)
assert len(checked)==7
print(json.dumps({'compiler':'0.8.30+commit.73712a01','original_sources':len(meta['original_sources']),'patched_sources':len(meta.get('patched_sources',{})),'reproducible_artifacts':checked,'network':'none','files_modified':0}))
