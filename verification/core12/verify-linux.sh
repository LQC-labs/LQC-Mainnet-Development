#!/usr/bin/env bash
set -uo pipefail

source_dir="$1"
manifest="$2"
evidence="$3"
mkdir -p "$evidence"
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
run_logged source-before sha256sum --check "$manifest"
if (( overall != 0 )); then exit 1; fi
run_logged environment bash -c 'uname -a; go version; go env GOOS GOARCH GOMODCACHE GOCACHE GOPROXY GOSUMDB GOTOOLCHAIN; test "$(go env GOVERSION)" = go1.25.9 && test "$(go env GOOS)" = linux'
if (( overall != 0 )); then exit 1; fi
run_logged download go mod download
run_logged verify go mod verify
run_logged test go test -mod=readonly ./...
run_logged build go build -mod=readonly ./...
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
  printf '```\n\n'
  if (( overall == 0 )); then
    printf 'All checks passed for the archived source snapshot.\n'
  else
    printf 'Verification failed. Inspect individual logs; do not mark Core 1/2 PASS.\n'
  fi
} > "$evidence/summary.md"
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then cat "$evidence/summary.md" >> "$GITHUB_STEP_SUMMARY"; fi
exit "$overall"
