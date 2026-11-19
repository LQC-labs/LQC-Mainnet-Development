#!/usr/bin/env bash
# Copyright 2026 MMXlabs & LQC LLC
# SPDX-License-Identifier: Apache-2.0
# Independent Linux VM host capability inventory only.
# No VM provisioning, privileged operations, Go tests, or node execution.
set -euo pipefail
if [[ "$(uname -s)" != Linux ]]; then
  printf '%s\n' 'BLOCKED: Linux required.'
  exit 1
fi
if [[ "$(id -u)" == 0 ]]; then
  printf '%s\n' 'BLOCKED: root host execution prohibited.'
  exit 1
fi
printf '%s\n' 'MN-001 independent VM host inventory'
printf 'kernel=%s\n' "$(uname -r)"
printf 'architecture=%s\n' "$(uname -m)"
for tool in qemu-system-x86_64 qemu-img timeout sha256sum findmnt prlimit; do
  if command -v "$tool" >/dev/null 2>&1; then
    printf 'tool:%s=present\n' "$tool"
  else
    printf 'tool:%s=missing\n' "$tool"
  fi
done
if [[ -e /dev/kvm ]]; then
  printf '%s\n' 'device:/dev/kvm=present'
else
  printf '%s\n' 'device:/dev/kvm=missing'
fi
printf '%s\n' 'RESULT=HOST_INVENTORY_ONLY'
printf '%s\n' 'BLOCKED: no verified VM boundary, network denial, credential isolation, immutable source, resource limits, or explicit approval.'
exit 0
