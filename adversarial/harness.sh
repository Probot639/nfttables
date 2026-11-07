#!/bin/bash
set -euo pipefail

REPORT_DIR="/opt/reports/iteration-${ITERATION}"
mkdir -p "$REPORT_DIR"

# Start auditd if available
if command -v auditd &>/dev/null; then
    auditd -l 2>/dev/null &
    sleep 1
fi

echo "=== NFTtables Adversarial Lab - Iteration $ITERATION ==="
echo "Blue team mode: $BLUE_TEAM_MODE"
echo "Report dir: $REPORT_DIR"
echo ""

# Phase 1: Start blue team monitors (background)
echo "[*] Starting blue team monitors..."

python3 /opt/blue-team/syscall_monitor.py \
    --output "$REPORT_DIR/syscall_detections.json" &
PIDS_BLUE="$!"

python3 /opt/blue-team/fs_watcher.py \
    --output "$REPORT_DIR/fs_detections.json" &
PIDS_BLUE="$PIDS_BLUE $!"

python3 /opt/blue-team/audit_analyzer.py \
    --output "$REPORT_DIR/audit_detections.json" &
PIDS_BLUE="$PIDS_BLUE $!"

python3 /opt/blue-team/process_monitor.py \
    --output "$REPORT_DIR/process_detections.json" &
PIDS_BLUE="$PIDS_BLUE $!"

python3 /opt/blue-team/netlink_monitor.py \
    --output "$REPORT_DIR/netlink_detections.json" &
PIDS_BLUE="$PIDS_BLUE $!"

# Iteration 2+: binary string scanner
if [ -f /opt/blue-team/binary_scanner.py ]; then
    python3 /opt/blue-team/binary_scanner.py \
        --output "$REPORT_DIR/binary_detections.json" &
    PIDS_BLUE="$PIDS_BLUE $!"
fi

sleep 2
echo "[+] Blue team monitors running (PIDs: $PIDS_BLUE)"

# Phase 2: Red team execution
echo ""
echo "[*] Executing red team payload..."
REDTEAM_START=$(date +%s%N)

# Use versioned payload if available
if [ "$ITERATION" -ge 4 ] && [ -f /opt/red-team/run_payload_v4.sh ]; then
    bash /opt/red-team/run_payload_v4.sh "$REPORT_DIR" 2>&1 | tee "$REPORT_DIR/red_team.log"
elif [ "$ITERATION" -ge 3 ] && [ -f /opt/red-team/run_payload_v3.sh ]; then
    bash /opt/red-team/run_payload_v3.sh "$REPORT_DIR" 2>&1 | tee "$REPORT_DIR/red_team.log"
elif [ "$ITERATION" -ge 2 ] && [ -f /opt/red-team/run_payload_v2.sh ]; then
    bash /opt/red-team/run_payload_v2.sh "$REPORT_DIR" 2>&1 | tee "$REPORT_DIR/red_team.log"
else
    bash /opt/red-team/run_payload.sh "$REPORT_DIR" 2>&1 | tee "$REPORT_DIR/red_team.log"
fi

REDTEAM_END=$(date +%s%N)
REDTEAM_MS=$(( (REDTEAM_END - REDTEAM_START) / 1000000 ))
echo "[+] Red team execution: ${REDTEAM_MS}ms"

# Phase 3: Let monitors collect trailing events
echo ""
echo "[*] Collecting trailing events (5s)..."
sleep 5

# Phase 4: Stop blue team, collect reports
echo "[*] Stopping blue team monitors..."
for pid in $PIDS_BLUE; do
    kill "$pid" 2>/dev/null || true
done
sleep 2

# Phase 5: Scoring
echo ""
echo "=== SCORING ==="
python3 /opt/blue-team/scorer.py \
    --report-dir "$REPORT_DIR" \
    --output "$REPORT_DIR/scorecard.json" | tee "$REPORT_DIR/scorecard.txt"

echo ""
echo "[+] Iteration $ITERATION complete. Reports in $REPORT_DIR/"
echo ""

# Dump summary for agent consumption
cat "$REPORT_DIR/scorecard.json" 2>/dev/null || echo '{"error": "no scorecard generated"}'
