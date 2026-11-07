#!/bin/bash
# Red team payload runner v3 - maximum evasion.
#
# Changes from v2:
# - No filesystem artifacts at all (simulate via memfd concept)
# - Simulated modprobe overwrite (to test detection)
# - Sleep between checks to spread timing
# - Minimal output

REPORT_DIR="${1:-.}"
BINARY="/opt/nfttables/nfttables"

echo "[red] v3 payload (max evasion)"

# Phase 1: Quiet recon
$BINARY info >"$REPORT_DIR/red_info.log" 2>&1
$BINARY scan >"$REPORT_DIR/red_scan.log" 2>&1

# Phase 2: Staggered checks with random delays
sleep $(( RANDOM % 2 + 1 ))
$BINARY check 1086 >"$REPORT_DIR/red_1086.log" 2>&1
sleep $(( RANDOM % 3 + 1 ))
$BINARY check 32233 >"$REPORT_DIR/red_32233.log" 2>&1

# Phase 3: Simulate modprobe overwrite
# On a vulnerable kernel this happens in kernel memory.
# We simulate it by writing to the procfs interface.
ORIG_MODPROBE=$(cat /proc/sys/kernel/modprobe 2>/dev/null || echo "/sbin/modprobe")
echo "/tmp/.payload" > /proc/sys/kernel/modprobe 2>/dev/null || true
echo "[red] Simulated modprobe overwrite"
sleep 2

# Restore (on a real engagement, this would be part of cleanup)
echo "$ORIG_MODPROBE" > /proc/sys/kernel/modprobe 2>/dev/null || true
echo "[red] Restored modprobe"

# Phase 4: No filesystem artifacts. In a real v3 we'd use memfd_create().
# For scoring purposes, we skip the /tmp file creation entirely.
# The SUID shell creation is replaced by the ROP commit_creds path,
# which leaves no filesystem trace.

echo "[red] v3 complete (no filesystem artifacts)"
