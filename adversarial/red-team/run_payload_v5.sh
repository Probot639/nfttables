#!/bin/bash
# Red team payload v5: stripped hardened binary
# Tests the stripped binary (no symbol table, no verbose format strings)

REPORT_DIR="${1:-/opt/reports}"
BIN="/opt/nfttables/nfttables"

echo "[red-team-v5] Running stripped hardened binary"

echo "[red-team-v5] Phase 1: info"
$BIN info 2>&1 | head -30

echo "[red-team-v5] Phase 2: collections"
$BIN collections 2>&1 | head -20

echo "[red-team-v5] Phase 3: scan"
$BIN scan -v 2>&1 | head -40

echo "[red-team-v5] Phase 4: check (dry run)"
$BIN check auto 2>&1 | head -30

echo "[red-team-v5] Phase 5: mint (full exploit attempt)"
$BIN mint auto -v 2>&1 | head -40

echo "[red-team-v5] Done"
