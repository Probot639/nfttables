#!/usr/bin/env python3
"""
Blue Team Agent 5: Netlink/nftables monitor.
Watches for nftables table/chain/set operations via /proc/net/nf_tables
and ss/ip command outputs. Generic netfilter monitoring.
"""

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import time
from datetime import datetime

DETECTIONS = []
running = True
known_tables = set()

def handle_signal(signum, frame):
    global running
    running = False

signal.signal(signal.SIGTERM, handle_signal)
signal.signal(signal.SIGINT, handle_signal)

def detect(category, severity, description, evidence):
    DETECTIONS.append({
        "timestamp": datetime.now().isoformat(),
        "agent": "netlink_monitor",
        "category": category,
        "severity": severity,
        "description": description,
        "evidence": evidence
    })

def check_nftables():
    """List nftables ruleset and detect changes."""
    global known_tables

    try:
        result = subprocess.run(
            ["nft", "list", "tables"],
            capture_output=True, text=True, timeout=5
        )
        current_tables = set()
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("table"):
                current_tables.add(line)

        # New tables
        new = current_tables - known_tables
        for table in new:
            detect(
                "nftables_new_table",
                "high",
                f"New nftables table created: {table}",
                {"table": table}
            )

            # Get full table details
            parts = table.split()
            if len(parts) >= 3:
                family = parts[1]
                name = parts[2]
                try:
                    detail = subprocess.run(
                        ["nft", "list", "table", family, name],
                        capture_output=True, text=True, timeout=5
                    )
                    if detail.stdout:
                        # Check for suspicious patterns
                        content = detail.stdout

                        # Verdict maps (used in CVE-2024-1086)
                        if "type verdict" in content or "vmap" in content.lower():
                            detect(
                                "nftables_verdict_map",
                                "high",
                                f"Table {name} contains a verdict map",
                                {"table": name, "family": family}
                            )

                        # Anonymous sets (used in CVE-2023-32233)
                        if "__set" in content:
                            detect(
                                "nftables_anonymous_set",
                                "high",
                                f"Table {name} contains anonymous set(s)",
                                {"table": name, "family": family}
                            )

                        # Base chains with hooks
                        chain_count = content.count("chain ")
                        if chain_count > 2:
                            detect(
                                "nftables_many_chains",
                                "medium",
                                f"Table {name} has {chain_count} chains (unusual)",
                                {"table": name, "chain_count": chain_count}
                            )

                except (subprocess.TimeoutExpired, FileNotFoundError):
                    pass

        # Deleted tables (appeared then disappeared)
        removed = known_tables - current_tables
        for table in removed:
            detect(
                "nftables_table_deleted",
                "medium",
                f"nftables table deleted: {table}",
                {"table": table}
            )

        known_tables = current_tables

    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

def check_netlink_sockets():
    """Monitor netlink sockets via /proc/net/netlink."""
    try:
        with open("/proc/net/netlink", "r") as f:
            lines = f.readlines()

        nfnetlink_count = 0
        for line in lines[1:]:
            parts = line.split()
            if len(parts) >= 3:
                protocol = int(parts[1])
                pid = int(parts[2])
                # NETLINK_NETFILTER = 12
                if protocol == 12 and pid != 0:
                    nfnetlink_count += 1

        if nfnetlink_count > 2:
            detect(
                "excessive_netfilter_sockets",
                "medium",
                f"Multiple NETLINK_NETFILTER sockets open ({nfnetlink_count})",
                {"count": nfnetlink_count}
            )

    except (FileNotFoundError, PermissionError):
        pass

def check_conntrack():
    """Check for unusual conntrack/netfilter state."""
    try:
        result = subprocess.run(
            ["cat", "/proc/sys/net/netfilter/nf_conntrack_count"],
            capture_output=True, text=True, timeout=2
        )
        count = int(result.stdout.strip()) if result.stdout.strip() else 0
        # Not directly exploit-related but context
    except (FileNotFoundError, subprocess.TimeoutExpired, ValueError):
        pass

def check_network_namespaces():
    """Check for new network namespaces."""
    try:
        result = subprocess.run(
            ["ip", "netns", "list"],
            capture_output=True, text=True, timeout=5
        )
        if result.stdout.strip():
            for ns in result.stdout.strip().splitlines():
                detect(
                    "new_network_namespace",
                    "medium",
                    f"Named network namespace detected: {ns}",
                    {"namespace": ns}
                )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Also check for unnamed namespaces via /proc
    try:
        my_netns = os.readlink("/proc/1/ns/net")
        for pid_str in os.listdir("/proc"):
            if not pid_str.isdigit():
                continue
            try:
                ns = os.readlink(f"/proc/{pid_str}/ns/net")
                if ns != my_netns:
                    try:
                        with open(f"/proc/{pid_str}/cmdline", "rb") as f:
                            cmd = f.read().replace(b"\x00", b" ").decode(errors="replace").strip()
                    except (FileNotFoundError, PermissionError):
                        cmd = "?"
                    detect(
                        "unnamed_network_namespace",
                        "high",
                        f"Process {pid_str} in different network namespace",
                        {"pid": pid_str, "cmdline": cmd[:200], "ns": ns}
                    )
            except (FileNotFoundError, PermissionError):
                pass
    except (FileNotFoundError, PermissionError):
        pass

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    try:
        while running:
            check_nftables()
            check_netlink_sockets()
            check_network_namespaces()
            time.sleep(1)
    finally:
        with open(args.output, "w") as f:
            json.dump(DETECTIONS, f, indent=2)
        print(f"[netlink_monitor] Wrote {len(DETECTIONS)} detections to {args.output}")

if __name__ == "__main__":
    main()
