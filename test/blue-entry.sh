#!/bin/bash
cat <<'BANNER'
=======================================
  NFTtables Blue Team Station
=======================================

Monitors auto-started. Detections land in /reports/

Commands:
  score.sh                    run scorer against current detections
  tail -f /reports/*.json     watch detections live
  ls /reports/                list detection files

BANNER

mkdir -p /reports

python3 ~/blue-team/syscall_monitor.py \
    --output /reports/syscall_detections.json &

python3 ~/blue-team/fs_watcher.py \
    --output /reports/fs_detections.json &

python3 ~/blue-team/audit_analyzer.py \
    --output /reports/audit_detections.json &

python3 ~/blue-team/process_monitor.py \
    --output /reports/process_detections.json &

python3 ~/blue-team/netlink_monitor.py \
    --output /reports/netlink_detections.json &

python3 ~/blue-team/binary_scanner.py \
    --output /reports/binary_detections.json &

echo "[+] All monitors started."
echo ""

exec bash
