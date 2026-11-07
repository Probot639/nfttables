#!/bin/bash
# find the blue-team dir wherever it lives
BT="${HOME}/blue-team"
[ -d "$BT" ] || BT="/root/blue-team"
[ -d "$BT" ] || { echo "scorer not found"; exit 1; }

python3 "$BT/scorer.py" \
    --report-dir /reports \
    --output /reports/scorecard.json
