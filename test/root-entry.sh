#!/bin/bash
cat <<'BANNER'
=======================================
  NFTtables Root Observer
=======================================

Full root access. Both binaries and monitors available.

Useful commands:
  cat /proc/sys/kernel/modprobe
  strings ./nfttables | less
  readelf -S ./nfttables
  nft list tables
  auditctl -l
  ps auxf
  score.sh

BANNER

exec bash
