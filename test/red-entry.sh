#!/bin/bash
cat <<'BANNER'
=======================================
  NFTtables Red Team Station
=======================================

Tools:
  ./nfttables              debug build
  ./nfttables-release      stripped/hardened build

Quick start:
  ./nfttables info
  ./nfttables collections
  ./nfttables scan -v
  ./nfttables check auto
  ./nfttables mint auto

BANNER

exec bash
