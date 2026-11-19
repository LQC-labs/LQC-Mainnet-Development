#!/usr/bin/env bash
# Copyright 2026 MMXlabs & LQC LLC
# SPDX-License-Identifier: Apache-2.0
#
# MN-001 isolated runner host capability inventory ONLY.
# Does not start namespaces, containers, nodes, or candidate tests.
# A PASS here is NOT execution authorization or proof of isolation.
set -euo pipefail
if [[ "$(uname -s)" != Linux ]]; then
  printf '%s\n' 'BLOCKED: Linux host required.' >&2
  exit 1
fi
printf '%s\n' 'MN-001 isolation capability inventory (no execution)'
printf 'kernel=%s\n' "$(uname -r)"
printf 'uid=%s\n' "$(id -u)"
printf 'architecture=%s\n' "$(uname -m)"
for tool in unshare bwrap timeout prlimit sha256sum go; do
  if command -v "$tool" >/dev/null 2>&1; then
    printf '%s=present\n' "$tool"
  else
    printf '%s=missing\n' "$tool"
  fi
done
for feature in /proc/self/ns/user /proc/self/ns/net /proc/self/ns/mnt /sys/fs/cgroup/cgroup.controllers; do
  if [[ -e "$feature" ]]; then
    printf 'feature:%s=present\n' "$feature"
  else
    printf 'feature:%s=missing\n' "$feature"
  fi
done
printf '%s\n' 'RESULT=INVENTORY_ONLY'
printf '%s\n' 'BLOCKED: no isolated runner, OS-level network-denial proof, credential isolation proof, or user approval.'
exit 0
