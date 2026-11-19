#!/usr/bin/env bash
# Copyright 2026 MMXlabs & LQC LLC
# SPDX-License-Identifier: Apache-2.0
#
# MN-001 disposable network-namespace PROBE ONLY.
# Never executes Go, candidate tests, validators, or nodes.
# Successful probe is NOT authorization to run candidates.
set -euo pipefail
if [[ "$(uname -s)" != Linux ]]; then
  printf '%s\n' 'BLOCKED: Linux required.' >&2
  exit 1
fi
if [[ "$(id -u)" = 0 ]]; then
  printf '%s\n' 'BLOCKED: refuse root host execution.' >&2
  exit 1
fi
if ! command -v unshare >/dev/null 2>&1 || ! command -v timeout >/dev/null 2>&1; then
  printf '%s\n' 'BLOCKED: unshare and timeout required.' >&2
  exit 1
fi
host_netns="$(readlink /proc/self/ns/net)" || {
  printf '%s\n' 'BLOCKED: cannot read host network namespace.' >&2
  exit 1
}
export LQC_MN001_HOST_NETNS="$host_netns"
# Unshare fails closed if user/network namespaces are unavailable. The child
# performs only a namespace identity check; no candidate code is imported.
if ! timeout --signal=TERM --kill-after=2s 12s \
  unshare --user --map-root-user --net --fork \
  /bin/sh -eu -c '
    child_netns="$(readlink /proc/self/ns/net)"
    test "$child_netns" != "$LQC_MN001_HOST_NETNS"
    test "$(id -u)" = 0
    test -d /sys/class/net
    # Never suppress interface enumeration failures: an unreadable network
    # inventory is BLOCKED, not proof of isolation.
    interfaces="$(find /sys/class/net -mindepth 1 -maxdepth 1 -printf "%f\\n")" || exit 1
    test -n "$interfaces"
    test "$interfaces" = lo
    printf "%s\n" "NETWORK_NAMESPACE_PROBE=PASS"
  '; then
  printf '%s\n' 'BLOCKED: network namespace probe failed.' >&2
  exit 1
fi
printf '%s\n' 'RESULT=NETWORK_PROBE_ONLY'
printf '%s\n' 'BLOCKED: filesystem, credentials, resource limits, dependency initialization, and explicit authorization remain unverified.'
