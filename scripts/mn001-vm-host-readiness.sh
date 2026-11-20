#!/usr/bin/env bash
# Copyright 2026 MMXlabs & LQC LLC
# SPDX-License-Identifier: Apache-2.0
# READ-ONLY host readiness check for a separately authorized MN-001 VM.
# No VM, container, namespace, network traffic, Go or candidate tests.
set -euo pipefail
printf '%s\n' 'MN001_HOST_READINESS=INVENTORY_ONLY'
printf '%s\n' 'MN001_GATE=NO_GO'
printf '%s\n' 'MAINNET=NO_GO'
if [[ "$(uname -s)" != Linux ]]; then
  printf '%s\n' 'BLOCKER=NON_LINUX_HOST'
  exit 1
fi
if [[ "$(id -u)" == 0 ]]; then
  printf '%s\n' 'BLOCKER=ROOT_IDENTITY_NOT_PERMITTED'
  exit 1
fi
blocked=0
for tool in qemu-system-x86_64 qemu-img timeout sha256sum findmnt prlimit python3; do
  if command -v "$tool" >/dev/null 2>&1; then
    printf 'TOOL=%s STATUS=AVAILABLE\n' "$tool"
  else
    printf 'TOOL=%s STATUS=MISSING\n' "$tool"
    blocked=1
  fi
done
if [[ ! -e /dev/kvm ]]; then
  printf '%s\n' 'KVM_DEVICE=MISSING'
  blocked=1
elif [[ ! -c /dev/kvm ]]; then
  printf '%s\n' 'KVM_DEVICE=NOT_CHARACTER_DEVICE'
  blocked=1
elif [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
  printf '%s\n' 'KVM_DEVICE=ACCESS_DENIED_FOR_CURRENT_USER'
  blocked=1
else
  printf '%s\n' 'KVM_DEVICE=ACCESS_BITS_ALLOW_CURRENT_USER'
fi
# Access bits are only hints, not proof that KVM works.
# No guest start or KVM device access during this inventory.
if [[ "$blocked" -ne 0 ]]; then
  printf '%s\n' 'HOST_PREREQUISITES=BLOCKED'
  printf '%s\n' 'BLOCKED: acquire a suitable independently owned Linux VM host.'
  exit 1
fi
printf '%s\n' 'HOST_PREREQUISITES=AVAILABLE_UNVERIFIED'
printf '%s\n' 'BLOCKED: VM, network denial, credentials, immutable source, resource enforcement and approval remain unverified.'
exit 0
