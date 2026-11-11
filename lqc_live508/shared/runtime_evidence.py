class EvidenceError(ValueError): pass

def shape(value,keys):
    if not isinstance(value,dict) or set(value)-set(keys): raise EvidenceError("unknown or sensitive fields")

def verify_runtime(template,actual,references,expected_getters,observed_getters):
    # Port of flowHarness.checkCode: only compiler-declared immutables are masked;
    # constructor-dependent getter evidence remains mandatory.
    if not isinstance(template,bytes) or not isinstance(actual,bytes) or not template or len(template)!=len(actual): raise EvidenceError("runtime length/absence")
    left,right=bytearray(template),bytearray(actual);covered=set()
    for ref in references:
        shape(ref,("start","length","getter"))
        start,size=ref.get("start"),ref.get("length")
        if type(start) is not int or type(size) is not int or start<0 or size<1 or start+size>len(actual): raise EvidenceError("immutable bounds")
        getter=ref.get("getter")
        if not isinstance(getter,str) or getter not in expected_getters or getter not in observed_getters: raise EvidenceError("immutable getter evidence missing")
        points=set(range(start,start+size))
        if points&covered: raise EvidenceError("immutable overlap")
        covered|=points;left[start:start+size]=bytes(size);right[start:start+size]=bytes(size)
    if left!=right: raise EvidenceError("runtime mismatch")
    allowed={"asset","owner","guardian","registry","interestIndex","oracle","rateModel","core","decimals","totalAssets","totalSupply","strategyDebt","accountedAssets"}
    if set(expected_getters)-allowed or set(observed_getters)-allowed: raise EvidenceError("unapproved getter")
    for key,value in expected_getters.items():
        if key not in observed_getters or observed_getters[key]!=value: raise EvidenceError("constructor/getter mismatch")
    return True
