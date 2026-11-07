#!/usr/bin/env python3
"""
Blue Team Agent 1: Syscall pattern monitor.
Watches for suspicious syscall bursts and sequences indicative of kernel exploitation.
No knowledge of nfttables internals. Pure behavioral detection.
"""

import argparse
import json
import os
import signal
import subprocess
import sys
import time
import re
from collections import defaultdict
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
        "agent": "syscall_monitor",
        "category": category,
        "severity": severity,
        "description": description,
        "evidence": evidence
    })

def monitor_proc_syscalls():
    """Watch /proc for new processes and sample their syscall patterns."""
    seen_pids = set()
    syscall_counts = defaultdict(lambda: defaultdict(int))
    burst_windows = defaultdict(list)

    while running:
        try:
            for pid_str in os.listdir("/proc"):
                if not pid_str.isdigit():
                    continue
                pid = int(pid_str)
                if pid in seen_pids:
                    continue
                seen_pids.add(pid)

                # Read cmdline
                try:
                    with open(f"/proc/{pid}/cmdline", "rb") as f:
                        cmdline = f.read().replace(b"\x00", b" ").decode(errors="replace").strip()
                except (FileNotFoundError, PermissionError):
                    continue

                if not cmdline:
                    continue

                # Read status for namespace info
                try:
                    with open(f"/proc/{pid}/status", "r") as f:
                        status = f.read()
                except (FileNotFoundError, PermissionError):
                    continue

                # Detection: process in different user namespace
                nspid_match = re.search(r"NSpid:\s+(\d+)\s+(\d+)", status)
                if nspid_match:
                    detect(
                        "namespace_escape",
                        "high",
                        f"Process {pid} running in nested user namespace",
                        {"pid": pid, "cmdline": cmdline, "nspid": nspid_match.group(0)}
                    )

                # Detection: unusual capabilities
                try:
                    with open(f"/proc/{pid}/status", "r") as f:
                        for line in f:
                            if line.startswith("CapEff:"):
                                cap_eff = int(line.split(":")[1].strip(), 16)
                                # CAP_NET_ADMIN = bit 12
                                if cap_eff & (1 << 12) and not cmdline.startswith(("/usr/", "/sbin/")):
                                    detect(
                                        "suspicious_caps",
                                        "medium",
                                        f"Non-system process with CAP_NET_ADMIN",
                                        {"pid": pid, "cmdline": cmdline, "cap_eff": hex(cap_eff)}
                                    )
                except (FileNotFoundError, PermissionError):
                    pass

                # Detection: check for netlink sockets
                try:
                    fd_dir = f"/proc/{pid}/fd"
                    for fd in os.listdir(fd_dir):
                        try:
                            link = os.readlink(os.path.join(fd_dir, fd))
                            if "socket:" in link:
                                sock_inode = link.split("[")[1].rstrip("]")
                                # Check if it's a netlink socket
                                try:
                                    with open("/proc/net/netlink", "r") as nl:
                                        for nlline in nl:
                                            if sock_inode in nlline:
                                                parts = nlline.split()
                                                if len(parts) >= 3:
                                                    protocol = int(parts[1])
                                                    # NETLINK_NETFILTER = 12
                                                    if protocol == 12:
                                                        detect(
                                                            "netfilter_socket",
                                                            "high",
                                                            f"Process opened NETLINK_NETFILTER socket",
                                                            {"pid": pid, "cmdline": cmdline, "fd": fd}
                                                        )
                                except (FileNotFoundError, PermissionError):
                                    pass
                        except (FileNotFoundError, PermissionError, OSError):
                            pass
                except (FileNotFoundError, PermissionError):
                    pass

                # Detection: check /proc/pid/maps for suspicious mmap patterns
                try:
                    anon_count = 0
                    with open(f"/proc/{pid}/maps", "r") as f:
                        for line in f:
                            if "anon" in line and "rw" in line:
                                anon_count += 1
                    if anon_count > 500:
                        detect(
                            "heap_spray_pattern",
                            "high",
                            f"Excessive anonymous RW mappings (possible heap spray)",
                            {"pid": pid, "cmdline": cmdline, "anon_maps": anon_count}
                        )
                except (FileNotFoundError, PermissionError):
                    pass

            # Detection: check for pipe fd burst
            for pid_str in os.listdir("/proc"):
                if not pid_str.isdigit():
                    continue
                pid = int(pid_str)
                try:
                    fd_count = len(os.listdir(f"/proc/{pid}/fd"))
                    pipe_count = 0
                    for fd in os.listdir(f"/proc/{pid}/fd"):
                        try:
                            link = os.readlink(f"/proc/{pid}/fd/{fd}")
                            if link.startswith("pipe:"):
                                pipe_count += 1
                        except (FileNotFoundError, PermissionError, OSError):
                            pass
                    if pipe_count > 100:
                        detect(
                            "pipe_spray_pattern",
                            "high",
                            f"Excessive pipe file descriptors (possible pipe spray)",
                            {"pid": pid, "pipe_count": pipe_count, "total_fds": fd_count}
                        )
                except (FileNotFoundError, PermissionError):
                    pass

            # Detection: check for msgqueue burst via ipcs
            try:
                result = subprocess.run(
                    ["ipcs", "-q"],
                    capture_output=True, text=True, timeout=2
                )
                queue_lines = [l for l in result.stdout.splitlines()
                              if l.strip() and not l.startswith("-")
                              and not l.startswith("Message")
                              and not l.startswith("key")]
                queue_count = len(queue_lines)
                if queue_count > 10:
                    detect(
                        "msgsnd_spray_pattern",
                        "high",
                        f"Excessive System V message queues ({queue_count})",
                        {"queue_count": queue_count}
                    )
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

            # Detection: check /proc/sysvipc/msg directly (more reliable)
            try:
                with open("/proc/sysvipc/msg", "r") as f:
                    lines = f.readlines()
                # First line is header
                msg_count = len(lines) - 1
                if msg_count > 10:
                    detect(
                        "msgsnd_spray_pattern",
                        "high",
                        f"System V message queues via procfs ({msg_count})",
                        {"queue_count": msg_count}
                    )
            except (FileNotFoundError, PermissionError):
                pass

        except Exception:
            pass

        time.sleep(0.5)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    try:
        monitor_proc_syscalls()
    finally:
        with open(args.output, "w") as f:
            json.dump(DETECTIONS, f, indent=2)
        print(f"[syscall_monitor] Wrote {len(DETECTIONS)} detections to {args.output}")

if __name__ == "__main__":
    main()
