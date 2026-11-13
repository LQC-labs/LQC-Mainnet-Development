#!/usr/bin/env bash
set -uo pipefail

source_dir="$1"
manifest="$2"
evidence="$3"
mkdir -p "$evidence"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)" || exit 1
cd "$source_dir" || exit 1
printf 'command\texit_code\n' > "$evidence/exit-codes.tsv"
overall=0
run_logged() {
  local label="$1"
  shift
  printf '\n>>> %s\n' "$*"
  "$@" 2>&1 | tee "$evidence/$label.log"
  local statuses=("${PIPESTATUS[@]}")
  local rc="${statuses[0]}"
  printf '%s\t%s\n' "$label" "$rc" | tee -a "$evidence/exit-codes.tsv"
  if (( rc != 0 || statuses[1] != 0 )); then overall=1; fi
}
# Evidence collection never changes source hashes or treats mutations as PASS.
printf 'command\tphase\tsha256\n' > "$evidence/go-sum-hashes.tsv" || exit 1
first_change=''
snapshot_sum() {
  local label="$1" phase="$2"
  local copy="$evidence/$label.$phase.go.sum"
  cp -- go.sum "$copy" || return 1
  local hash
  hash="$(sha256sum -- "$copy")" || return 1
  hash="${hash%% *}"
  printf '%s\t%s\t%s\n' "$label" "$phase" "$hash" | tee -a "$evidence/go-sum-hashes.tsv"
}
run_sum_logged() {
  local label="$1"
  shift
  if ! snapshot_sum "$label" before; then
    printf 'Evidence capture failed before %s\n' "$label" >&2
    overall=1
    return
  fi
  run_logged "$label" "$@"
  if ! snapshot_sum "$label" after; then
    printf 'Evidence capture failed after %s\n' "$label" >&2
    overall=1
    return
  fi
  local before="$evidence/$label.before.go.sum"
  local after="$evidence/$label.after.go.sum"
  cmp --silent -- "$before" "$after"
  local compare_rc=$?
  if (( compare_rc == 0 )); then return; fi
  overall=1
  if (( compare_rc != 1 )); then
    printf 'Evidence comparison failed for %s\n' "$label" >&2
    return
  fi
  diff -u -- "$before" "$after" > "$evidence/$label.go.sum.diff"
  local diff_rc=$?
  if (( diff_rc != 1 )); then printf 'Diff capture failed for %s\n' "$label" >&2; fi
  run_logged "$label.sum-classification" node "$script_dir/classify-go-sum.mjs" "$before" "$after"
  if [[ -z "$first_change" ]]; then
    first_change="$label"
    printf '%s\n' "$label" > "$evidence/first-change-command.txt" || overall=1
    cp -- "$evidence/go.sum.original" "$evidence/first-change.original.go.sum" || overall=1
    cp -- "$before" "$evidence/first-change.before.go.sum" || overall=1
    cp -- "$after" "$evidence/first-change.after.go.sum" || overall=1
    diff -u -- "$evidence/go.sum.original" "$after" > "$evidence/first-change.original-to-after.diff"
    diff_rc=$?
    if (( diff_rc > 1 )); then printf 'Original diff capture failed\n' >&2; fi
  fi
}
run_logged source-before sha256sum --check "$manifest"
if (( overall != 0 )); then exit 1; fi
run_logged environment bash -c 'uname -a; go version; go env GOOS GOARCH GOMODCACHE GOCACHE GOPROXY GOSUMDB GOTOOLCHAIN; test "$(go env GOVERSION)" = go1.25.9 && test "$(go env GOOS)" = linux'
if (( overall != 0 )); then exit 1; fi
cp -- go.sum "$evidence/go.sum.original" || exit 1
run_sum_logged download go mod download
run_sum_logged verify go mod verify
run_sum_logged test go test -mod=readonly ./...
run_sum_logged build go build -mod=readonly ./...
run_logged source-after sha256sum --check "$manifest"
cp "$manifest" "$evidence/source-expected.sha256"
while IFS= read -r line; do
  file="${line:66}"
  sha256sum -- "$file"
done < "$manifest" > "$evidence/source-after.sha256"
# Record the exact whitespace in filenames, without changing the module cache.
run_logged cometbft-paths bash -c 'find "$GOMODCACHE/github.com/cometbft/cometbft@v0.39.3/.github/workflows" -maxdepth 1 -name "*38x*" -print0 | od -An -tx1c'
{
  printf '## LQC Core 1/2 Linux verification\n\n'
  printf '```text\n'
  cat "$evidence/exit-codes.tsv"
  cat "$evidence/go-sum-hashes.tsv"
  if [[ -n "$first_change" ]]; then printf "First go.sum mutation: %s\n" "$first_change"; fi
  printf '```\n\n'
  if (( overall == 0 )); then
    printf 'All checks passed for the archived source snapshot.\n'
  else
    printf 'Verification failed. Inspect individual logs; do not mark Core 1/2 PASS.\n'
  fi
} > "$evidence/summary.md"
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then cat "$evidence/summary.md" >> "$GITHUB_STEP_SUMMARY"; fi
exit "$overall"
