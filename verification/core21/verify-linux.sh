#!/usr/bin/env bash
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
root="${LQC_VERIFY_ROOT:?}"
evidence="$root/evidence"
manifest="$script_dir/source.sha256"
mkdir -p "$evidence" "$root/source"
exec > >(tee "$evidence/verification.log") 2>&1
finish() {
  rc=$?
  trap - EXIT
  if [[ -f "$evidence/source-before.txt" ]]; then
    set +e
    (cd "$root/source" && sha256sum --check "$manifest") > "$evidence/source-after.txt" 2>&1
    hash_rc=$?
    printf 'source-after\t%s\n' "$hash_rc" >> "$evidence/exit-codes.tsv"
    if ((hash_rc != 0)); then rc=1; fi
  fi
  printf '%s\n' "$rc" > "$evidence/final-exit-code.txt"
  exit "$rc"
}
trap finish EXIT
printf 'check\texit_code\n' > "$evidence/exit-codes.tsv"
printf '%s\n' "commit=$GITHUB_SHA" "run=$GITHUB_RUN_ID" "attempt=$GITHUB_RUN_ATTEMPT" > "$evidence/run-identity.txt"
[[ "$GITHUB_RUN_ATTEMPT" == 1 ]]
printf '%s  %s\n' e91b22f37f836b5810377e7671a8bb11e5af5da87b6d11cfc5ed88630bbfbadd "$script_dir/source.tar" | sha256sum --check
printf '%s  %s\n' 53597dcfd4b188eeccd274b53dfbfab34a9eb4f1f227f0a64f3137b552abe7b2 "$manifest" | sha256sum --check
tar -xf "$script_dir/source.tar" -C "$root/source"
cp "$manifest" "$evidence/source.sha256"
cd "$root/source"
[[ $(wc -l < "$manifest") == 24 ]]
sha256sum --check "$manifest" | tee "$evidence/source-before.txt"
run() {
  local label="$1"; shift
  cp go.sum "$evidence/$label.go.sum.before"
  cp go.mod "$evidence/$label.go.mod.before"
  sha256sum go.mod go.sum > "$evidence/$label.hashes.before"
  set +e
  "$@" 2>&1 | tee "$evidence/$label.log"
  local rc=${PIPESTATUS[0]}
  set -e
  printf '%s\t%s\n' "$label" "$rc" >> "$evidence/exit-codes.tsv"
  cp go.sum "$evidence/$label.go.sum.after"
  cp go.mod "$evidence/$label.go.mod.after"
  sha256sum go.mod go.sum > "$evidence/$label.hashes.after"
  if ! cmp -s "$evidence/$label.hashes.before" "$evidence/$label.hashes.after"; then
    diff -u "$evidence/$label.go.sum.before" go.sum > "$evidence/$label.go.sum.diff" || true
    diff -u "$evidence/$label.go.mod.before" go.mod > "$evidence/$label.go.mod.diff" || true
    printf '%s\n' "$label" > "$evidence/first-mutation.txt"
    echo 'FAIL: dependency inputs changed; no baseline update permitted'
    return 1
  fi
  return "$rc"
}
{
  uname -a
  go version
  go env
  gcc --version
  g++ --version
  node --version
} | tee "$evidence/toolchain.txt"
[[ "$(go version)" == 'go version go1.25.9 linux/amd64' ]]
[[ "$(go env CGO_ENABLED)" == 1 ]]
printf '#include <stdio.h>\nint main(void){puts("C compiler PASS");return 0;}\n' > "$root/probe.c"
run c-compiler gcc "$root/probe.c" -o "$root/probe"
run c-execution "$root/probe"
printf 'int main(){return 0;}\n' > "$root/probe.cpp"
run cxx-compiler g++ "$root/probe.cpp" -o "$root/probe-cxx"
run cxx-execution "$root/probe-cxx"
run go-mod-download go mod download
run go-mod-verify go mod verify
run go-test go test -mod=readonly ./...
run go-build go build -mod=readonly ./cmd/lqcd
run cli-help ./lqcd --help
run cli-version ./lqcd version
grep -q 'lqcd' "$evidence/cli-help.log"
grep -Fxq 'lqcd 0.0.0-core2.1-dev' "$evidence/cli-version.log"
run javascript node --test scripts/flow-quote-adapter.test.mjs
grep -Eq '^# tests 25$' "$evidence/javascript.log"
grep -Eq '^# fail 0$' "$evidence/javascript.log"
run devnet-regression go test -mod=readonly -count=1 ./chain/config
sha256sum lqcd > "$evidence/binary.sha256"
go version -m ./lqcd > "$evidence/binary-build-info.txt"
echo 'All validation commands passed'
