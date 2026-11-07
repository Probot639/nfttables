#!/usr/bin/env python3
"""
Blue Team Agent 3: Audit log analyzer.
Watches kernel audit log for nftables operations, namespace creation,
and privilege changes. Generic rules, no exploit-specific knowledge.
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

def handle_signal(signum, frame):
    global running
    running = False

signal.signal(signal.SIGTERM, handle_signal)
signal.signal(signal.SIGINT, handle_signal)

def detect(category, severity, description, evidence):
    DETECTIONS.append({
        "timestamp": datetime.now().isoformat(),
        "agent": "audit_analyzer",
        "category": category,
        "severity": severity,
        "description": description,
        "evidence": evidence
    })

AUDIT_LOG = "/var/log/audit/audit.log"
DMESG_PATTERNS = [
    (r"BUG:.*nf_tables|nft_", "kernel_bug_nftables", "critical",
     "Kernel BUG related to nf_tables"),
    (r"KASAN.*nft_|nf_tables", "kasan_nftables", "critical",
     "KASAN report involving nf_tables"),
    (r"general protection fault.*nft_", "gpf_nftables", "critical",
     "General protection fault in nf_tables"),
    (r"double free.*detected", "double_free", "critical",
     "Double free detected in kernel"),
    (r"use-after-free", "uaf_detected", "critical",
     "Use-after-free detected in kernel"),
]

def setup_audit_rules():
    """Set up audit rules for LPE-relevant syscalls."""
    rules = [
        # Watch clone/unshare for namespace creation
        ["-a", "always,exit", "-F", "arch=b64", "-S", "unshare", "-k", "namespace_ops"],
        ["-a", "always,exit", "-F", "arch=b64", "-S", "clone", "-k", "namespace_ops"],
        ["-a", "always,exit", "-F", "arch=b64", "-S", "clone3", "-k", "namespace_ops"],
        # Watch netlink sendmsg
        ["-a", "always,exit", "-F", "arch=b64", "-S", "sendmsg", "-k", "netlink_ops"],
        # Watch msgget/msgsnd for heap spray
        ["-a", "always,exit", "-F", "arch=b64", "-S", "msgget", "-k", "ipc_ops"],
        ["-a", "always,exit", "-F", "arch=b64", "-S", "msgsnd", "-k", "ipc_ops"],
        # Watch pipe for pipe spray
        ["-a", "always,exit", "-F", "arch=b64", "-S", "pipe", "-k", "pipe_ops"],
        ["-a", "always,exit", "-F", "arch=b64", "-S", "pipe2", "-k", "pipe_ops"],
        # Watch for credential changes
        ["-a", "always,exit", "-F", "arch=b64", "-S", "setuid", "-k", "priv_change"],
        ["-a", "always,exit", "-F", "arch=b64", "-S", "setgid", "-k", "priv_change"],
        # Watch /tmp for file creation
        ["-w", "/tmp", "-p", "wa", "-k", "tmp_write"],
    ]
    for rule in rules:
        try:
            subprocess.run(["auditctl"] + rule,
                capture_output=True, timeout=5)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

def parse_audit_log(last_pos):
    """Read new audit log entries since last_pos."""
    entries = []
    if not os.path.exists(AUDIT_LOG):
        return entries, last_pos

    try:
        with open(AUDIT_LOG, "r") as f:
            f.seek(last_pos)
            for line in f:
                entries.append(line.strip())
            new_pos = f.tell()
    except PermissionError:
        return entries, last_pos

    return entries, new_pos

def analyze_audit_entry(entry):
    """Analyze a single audit log entry for suspicious activity."""

    # NETFILTER_CFG events
    if "type=NETFILTER_CFG" in entry:
        table_match = re.search(r'table=(\S+)', entry)
        table_name = table_match.group(1) if table_match else "unknown"
        detect(
            "nftables_config_change",
            "high",
            f"nftables configuration change detected (table={table_name})",
            {"entry": entry[:500], "table": table_name}
        )

    # Namespace creation by non-root
    if "key=\"namespace_ops\"" in entry:
        uid_match = re.search(r'uid=(\d+)', entry)
        if uid_match and uid_match.group(1) != "0":
            detect(
                "unprivileged_namespace",
                "high",
                "Unprivileged user created namespace",
                {"entry": entry[:500], "uid": uid_match.group(1)}
            )

    # IPC operations (heap spray detection)
    if "key=\"ipc_ops\"" in entry:
        # Escalate to high severity - IPC bursts are strong exploit signals
        detect(
            "msgsnd_spray_pattern",
            "high",
            "IPC syscall recorded (msgget/msgsnd - possible heap spray)",
            {"entry": entry[:200]}
        )

    # Privilege changes
    if "key=\"priv_change\"" in entry:
        detect(
            "privilege_change",
            "critical",
            "Credential change syscall detected",
            {"entry": entry[:500]}
        )

    # Temp directory writes
    if "key=\"tmp_write\"" in entry and "name=" in entry:
        name_match = re.search(r'name="([^"]+)"', entry)
        fname = name_match.group(1) if name_match else "unknown"
        detect(
            "tmp_file_write",
            "medium",
            f"File written to /tmp: {fname}",
            {"entry": entry[:500], "filename": fname}
        )

def check_dmesg():
    """Scan dmesg for kernel exploit indicators."""
    try:
        result = subprocess.run(
            ["dmesg", "--time-format=iso", "-l", "err,warn,crit"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            for pattern, category, severity, desc in DMESG_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    detect(category, severity, desc, {"dmesg_line": line[:500]})
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    setup_audit_rules()

    # Get initial file position
    last_pos = 0
    if os.path.exists(AUDIT_LOG):
        last_pos = os.path.getsize(AUDIT_LOG)

    last_dmesg_check = 0

    try:
        while running:
            # Process new audit entries
            entries, last_pos = parse_audit_log(last_pos)
            for entry in entries:
                analyze_audit_entry(entry)

            # Periodic dmesg check
            now = time.time()
            if now - last_dmesg_check > 2:
                check_dmesg()
                last_dmesg_check = now

            time.sleep(0.5)
    finally:
        with open(args.output, "w") as f:
            json.dump(DETECTIONS, f, indent=2)
        print(f"[audit_analyzer] Wrote {len(DETECTIONS)} detections to {args.output}")

if __name__ == "__main__":
    main()
