#!/usr/bin/env python3
"""
Blue Team Agent 6: Binary analysis scanner.
Scans executables for kernel exploit indicators using multiple techniques:
  1. String pattern matching (catches unencrypted operational strings)
  2. Format string analysis (catches diagnostic messages referencing exploit terms)
  3. Section entropy analysis (detects encrypted/packed data blobs)
  4. Symbol and import analysis
"""

import argparse
import json
import math
import os
import re
import signal
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime

DETECTIONS = []
running = True
scanned_pids = set()

def handle_signal(signum, frame):
    global running
    running = False

signal.signal(signal.SIGTERM, handle_signal)
signal.signal(signal.SIGINT, handle_signal)

def detect(category, severity, description, evidence):
    DETECTIONS.append({
        "timestamp": datetime.now().isoformat(),
        "agent": "binary_scanner",
        "category": category,
        "severity": severity,
        "description": description,
        "evidence": evidence
    })

# --- Technique 1: Direct string patterns ---
# These catch unencrypted operational strings. Against a hardened binary,
# most of these won't fire. That's the point of this iteration.
DIRECT_PATTERNS = [
    (rb"modprobe_path", "kernel_exploit_string", "critical",
     "References modprobe_path (kernel exploit technique)"),
    (rb"prepare_kernel_cred", "kernel_exploit_string", "critical",
     "References prepare_kernel_cred (privilege escalation)"),
    (rb"commit_creds", "kernel_exploit_string", "critical",
     "References commit_creds (privilege escalation)"),
    (rb"core_pattern", "kernel_exploit_string", "high",
     "References core_pattern (kernel exploit technique)"),
    (rb"dirty.pagetable", "exploit_technique_string", "critical",
     "References dirty pagetable technique"),
    (rb"heap.spray", "heap_spray_string", "high",
     "References heap spray"),
]

# --- Technique 2: Format string / log message patterns ---
# Exploit tools that encrypt operational strings usually leave their
# printf format strings and log messages in plaintext. These contain
# contextual references to exploit techniques.
FORMAT_PATTERNS = [
    (rb"modprobe_path\s*@\s*0x%", "format_string_exploit_indicator", "high",
     "Format string reveals modprobe_path address logging"),
    (rb"kallsyms.*resolved", "format_string_exploit_indicator", "high",
     "Format string reveals kallsyms resolution logging"),
    (rb"prepare_kernel_cred=0x%", "format_string_exploit_indicator", "critical",
     "Format string reveals cred function address logging"),
    (rb"commit_creds=0x%", "format_string_exploit_indicator", "critical",
     "Format string reveals cred function address logging"),
    (rb"overwrite.*modprobe", "format_string_exploit_indicator", "critical",
     "Log message about modprobe overwrite"),
    (rb"(pipe|heap|PTE)\s*spray", "format_string_exploit_indicator", "high",
     "Log message about spray technique"),
    (rb"dirty.pagetable", "format_string_exploit_indicator", "critical",
     "Log message about dirty pagetable"),
    (rb"nft_chain.*obj=", "format_string_exploit_indicator", "high",
     "Format string reveals nftables slab profiling"),
    (rb"nft_set.*obj=", "format_string_exploit_indicator", "high",
     "Format string reveals nftables slab profiling"),
    (rb"KASLR.*base.*0x%", "format_string_exploit_indicator", "high",
     "Format string reveals KASLR bypass logging"),
    (rb"kallsyms.*(lookup|failed|blocking)", "format_string_exploit_indicator", "high",
     "Format string about kallsyms access"),
    (rb"smart.contract", "format_string_exploit_indicator", "medium",
     "Log message with unusual 'smart contract' theme in system binary"),
    (rb"(mint|rug\s*pull|floor.price|gas.price|wallet)", "format_string_exploit_indicator", "medium",
     "Crypto/NFT themed strings in system binary (possible themed exploit tool)"),
    (rb"CVE-20\d\d-\d+", "cve_reference", "high",
     "Contains CVE identifier"),
    (rb"Bored.Ape", "format_string_exploit_indicator", "high",
     "Contains themed exploit identifier"),
]

# --- Technique 3: ptrace indicators ---
PTRACE_PATTERNS = [
    (rb"PTRACE_ATTACH", "ptrace_suspicious", "high",
     "Binary references PTRACE_ATTACH (possible process injection)"),
    (rb"ptrace_attach", "ptrace_suspicious", "medium",
     "Binary references ptrace attach"),
    (rb"inject.*syscall", "ptrace_inject", "high",
     "Binary references syscall injection"),
    (rb"victim.*process", "ptrace_suspicious", "medium",
     "Binary references victim process selection"),
]

def scan_strings(exe_path):
    """Run strings on the binary and check all pattern sets."""
    try:
        result = subprocess.run(
            ["strings", "-a", exe_path],
            capture_output=True, timeout=10
        )
        content = result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return

    for patterns_list in [DIRECT_PATTERNS, FORMAT_PATTERNS, PTRACE_PATTERNS]:
        for pattern, category, severity, desc in patterns_list:
            if re.search(pattern, content, re.IGNORECASE):
                detect(
                    category, severity,
                    f"Binary {exe_path}: {desc}",
                    {"exe": exe_path}
                )

def entropy(data):
    """Shannon entropy of a byte sequence. Returns 0-8."""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    ent = 0.0
    for count in counts.values():
        p = count / total
        if p > 0:
            ent -= p * math.log2(p)
    return ent

def scan_entropy(exe_path):
    """Check for high-entropy sections that suggest encrypted/packed data."""
    try:
        with open(exe_path, "rb") as f:
            raw = f.read()
    except (FileNotFoundError, PermissionError):
        return

    if len(raw) < 4096:
        return

    # Slide a 1KB window and find regions with entropy > 7.5
    # (random/encrypted data is ~7.9-8.0, normal code is 5-6.5)
    window = 1024
    high_entropy_runs = 0
    max_entropy = 0.0
    total_high = 0

    for i in range(0, len(raw) - window, window):
        chunk = raw[i:i+window]
        e = entropy(chunk)
        if e > max_entropy:
            max_entropy = e
        if e > 7.5:
            high_entropy_runs += 1
            total_high += window

    # Flag if we found substantial high-entropy regions
    # Small binaries can have incidental high entropy from compression
    if total_high > 512 and high_entropy_runs >= 1:
        pct = (total_high / len(raw)) * 100
        if pct > 1.0:
            detect(
                "high_entropy_section", "medium",
                f"Binary {exe_path}: {total_high} bytes ({pct:.1f}%) above entropy threshold 7.5 (max {max_entropy:.2f})",
                {"exe": exe_path, "high_entropy_bytes": total_high,
                 "max_entropy": round(max_entropy, 2),
                 "pct_high_entropy": round(pct, 1)}
            )

    # Check for a distinct encrypted blob pattern:
    # a contiguous region of high entropy surrounded by normal entropy
    if high_entropy_runs >= 1:
        # count longest contiguous run
        longest_run = 0
        current_run = 0
        for i in range(0, len(raw) - window, window):
            chunk = raw[i:i+window]
            e = entropy(chunk)
            if e > 7.0:
                current_run += 1
                longest_run = max(longest_run, current_run)
            else:
                current_run = 0

        if longest_run >= 1 and total_high < len(raw) * 0.5:
            detect(
                "encrypted_data_blob", "high",
                f"Binary {exe_path}: isolated high-entropy blob ({longest_run}KB contiguous), "
                f"suggests encrypted string table or packed payload",
                {"exe": exe_path, "blob_size_kb": longest_run}
            )

def scan_binary(pid, exe_path):
    """Full analysis of a binary."""
    scan_strings(exe_path)
    scan_entropy(exe_path)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    # Pre-scan known binary locations
    for static_path in ["/opt/nfttables/nfttables", "/opt/nfttables", "/bin/nfttables"]:
        if os.path.isfile(static_path):
            scan_binary(0, static_path)

    try:
        while running:
            for pid_str in os.listdir("/proc"):
                if not pid_str.isdigit():
                    continue
                pid = int(pid_str)
                if pid in scanned_pids:
                    continue
                scanned_pids.add(pid)

                try:
                    exe_path = os.readlink(f"/proc/{pid}/exe")
                except (FileNotFoundError, PermissionError):
                    continue

                is_system = any(exe_path.startswith(p) for p in [
                    "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/",
                    "/usr/lib/", "/lib/"
                ])
                is_temp = any(d in exe_path for d in ["/tmp", "/dev/shm", "/var/tmp"])
                is_opt = exe_path.startswith("/opt/")

                if not is_system or is_temp or is_opt:
                    scan_binary(pid, exe_path)

            time.sleep(0.5)
    finally:
        with open(args.output, "w") as f:
            json.dump(DETECTIONS, f, indent=2)
        print(f"[binary_scanner] Wrote {len(DETECTIONS)} detections to {args.output}")

if __name__ == "__main__":
    main()
