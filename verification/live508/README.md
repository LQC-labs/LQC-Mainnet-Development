# Live 5.08 PR integration candidate

Official 5.08 BLOCKED / mainnet NO-GO. No production signer, key, approval, node
launcher, deployment CLI or untrusted-client broker is included. Imports are inert.

Package: lqc_live508. Tests: tests.live508. Reused common modules are namespaced
under lqc_live508.shared; codecs require the root npm dependency ethers. No sys.path
insertion, date-directory runtime dependency or preinstalled node_modules path.
ORIGIN-PROVENANCE.json records original file hashes; HISTORICAL-SHA256.json preserves
prior evidence references without declaring old hashes to be current hashes.
SOURCE-SHA256.json is the separate current integrated source/fixture/dependency/CI
baseline. Original evidence remains outside this checkout and is never regenerated.

## Linux checks

Use x86_64 Linux, CPython 3.12.3, Node 22.16.0 selected by setup-node/PATH.
Python versions/transitive wheel hashes are fixed in requirements-linux.lock;
ethers 6.17.0/transitive integrity is fixed by package-lock.json. These versions
preserve the preceding verification baseline; this is not an assertion that every
dependency is the latest version or free of advisories.

    python -m pip install --only-binary=:all: --require-hashes -r requirements-linux.lock
    npm ci --ignore-scripts --no-audit --no-fund
    python -B -m tests.live508.run_checks --output /tmp/lqc508-new-results

The output directory must not exist and must be outside the checkout. Tests never
write historical TEST-RESULT.json or preserved logs. All four prior Live suites and
selected RPC/approval regressions plus security boundary tests are run with real
socket/DNS/key operations forbidden and only the local verification codecs allowed.

The dedicated workflow has a ten-minute job limit, six-minute test limit, minimal
contents:read permission, pinned Actions, CPU/descriptor limits and no secrets,
services, schedule, daemon, consensus node, mining, real signer or transaction.
It is a bounded software verification job, not a server substitute. No workflow
has been triggered by this local preparation.

Preserved Core/Flow files are not replaced. Actual Flow E2E, live RPC/node semantics,
production signer integration and independent finality remain unverified. See
SECURITY.md for supported API guarantees and same-process Python limitations.
