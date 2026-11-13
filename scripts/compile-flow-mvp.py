#!/usr/bin/env python3
"""Offline Solidity compilation only. No node, wallet, RPC or deployment."""
import pathlib,json,hashlib,subprocess,argparse
p=argparse.ArgumentParser();p.add_argument('--solc',required=True);args=p.parse_args();root=pathlib.Path(__file__).resolve().parents[1];fixture=root/'node/testdata/flow-minimal';tool=root/'tools/flow-mvp';meta=json.loads((fixture/'SOURCE.json').read_text());compiler=pathlib.Path(args.solc)
def sh(b):return hashlib.sha256(b).hexdigest()
assert sh(compiler.read_bytes())==meta['compilerProof']['compiler_sha256'],'compiler hash mismatch'
version=subprocess.check_output([str(compiler),'--version'],text=True,timeout=10);assert '0.8.30+commit.73712a01' in version
sources={};sourceHashes={}
for n,r in {**meta['original_sources'],**meta['patched_sources']}.items():
 b=(fixture/n).read_bytes();assert sh(b)==r['sha256'],n;sources[n]={'content':b.decode()};sourceHashes[n]=sh(b)
assert len(sources)==11;assert 'amountADesired < amountAMin || amountBDesired < amountBMin' in sources['contracts/LQCFlowRouter.sol']['content']
settings={'optimizer':{'enabled':True,'runs':200},'viaIR':True,'evmVersion':'shanghai'};inputs={'language':'Solidity','sources':sources,'settings':{**settings,'outputSelection':{'*':{'':['ast'],'*':['abi','evm.bytecode.object','evm.deployedBytecode.object','evm.deployedBytecode.immutableReferences']}}}}
raw=json.dumps(inputs).encode();r=subprocess.run([str(compiler),'--standard-json'],input=raw,capture_output=True,timeout=120);assert r.returncode==0;output=json.loads(r.stdout);assert not [e for e in output.get('errors',[]) if e['severity']=='error'],output.get('errors')
builddir=tool/'artifacts';builddir.mkdir(exist_ok=True);(tool/'compiler-input.json').write_bytes(raw);(tool/'compiler-output.json').write_bytes(r.stdout)
immutableNames={}
def visit(o):
 if isinstance(o,dict):
  if o.get('nodeType')=='VariableDeclaration' and o.get('mutability')=='immutable':immutableNames[str(o['id'])]=o['name']
  for v in o.values():visit(v)
 elif isinstance(o,list):
  for v in o:visit(v)
for src in output['sources'].values():visit(src.get('ast'))
names=['LQCTestToken','MockWBNB','LQCFlowFactory','LQCFlowPair','LQCFlowRouter'];records={};registry={'schemaVersion':1,'interfaceFamily':'mvp','flowCommit':'013d159f05ed6a924ee965ec41ef193a069da122','contracts':{}}
for source,contracts in output['contracts'].items():
 for n,a in contracts.items():
  if n not in names:continue
  refs=a['evm']['deployedBytecode']['immutableReferences'];artifact={'contractName':n,'sourceName':source,'compiler':'0.8.30+commit.73712a01','abi':a['abi'],'bytecode':'0x'+a['evm']['bytecode']['object'],'deployedBytecode':'0x'+a['evm']['deployedBytecode']['object'],'immutableReferences':refs,'immutableNames':{k:immutableNames[k] for k in refs}}
  data=(json.dumps(artifact,indent=2)+'\n').encode();(builddir/(n+'.json')).write_bytes(data);abiHash=sh(json.dumps(a['abi'],separators=(',',':'),ensure_ascii=False).encode());records[n]={'artifactSha256':sh(data),'abiSha256':abiHash,'creationSha256':sh(bytes.fromhex(artifact['bytecode'][2:])),'runtimeTemplateSha256':sh(bytes.fromhex(artifact['deployedBytecode'][2:]))};version='mvp.'+n+'-0.8.30'+('-min-guard' if n=='LQCFlowRouter' else '')+'-v1';registry['contracts'][n]={'version':version,'abi':a['abi'],'abiSha256':abiHash}
assert set(records)==set(names);build={'compiler':'0.8.30+commit.73712a01','compilerSha256':sh(compiler.read_bytes()),'flowCommit':registry['flowCommit'],'productionApproved':False,'settings':settings,'sources':sourceHashes,'inputSha256':sh(raw),'artifacts':records};(tool/'build-manifest.json').write_text(json.dumps(build,indent=2)+'\n');(root/'config/flow/mvp/abi-registry.json').write_text(json.dumps(registry,indent=2)+'\n');print(json.dumps({'compiledSources':len(sources),'artifacts':len(records),'settings':settings,'deployments':0,'network':'none','sourceHashes':sourceHashes,'artifactHashes':records},indent=2))
