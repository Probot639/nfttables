#!/usr/bin/env python3
"""
Blue Team Agent 4: Process behavior monitor.
Watches for process trees and behavioral patterns typical of kernel exploits.
Tracks parent-child relationships, credential changes, and timing.
"""

import argparse
import json
import os
import re
import signal
import sys
import time
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
        "agent": "process_monitor",
        "category": category,
        "severity": severity,
        "description": description,
        "evidence": evidence
    })

def get_process_info(pid):
    """Read process info from /proc."""
    info = {"pid": pid}
    try:
        with open(f"/proc/{pid}/status", "r") as f:
            for line in f:
                if line.startswith("Name:"):
                    info["name"] = line.split(":", 1)[1].strip()
                elif line.startswith("PPid:"):
                    info["ppid"] = int(line.split(":", 1)[1].strip())
                elif line.startswith("Uid:"):
                    parts = line.split(":", 1)[1].split()
                    info["real_uid"] = int(parts[0])
                    info["eff_uid"] = int(parts[1])
                elif line.startswith("NStgid:"):
                    info["nstgid"] = line.split(":", 1)[1].strip()
                elif line.startswith("Threads:"):
                    info["threads"] = int(line.split(":", 1)[1].strip())
                elif line.startswith("TracerPid:"):
                    info["tracer_pid"] = int(line.split(":", 1)[1].strip())
    except (FileNotFoundError, PermissionError):
        return None

    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            info["cmdline"] = f.read().replace(b"\x00", b" ").decode(errors="replace").strip()
    except (FileNotFoundError, PermissionError):
        info["cmdline"] = ""

    return info

def scan_processes():
    """Full process table scan."""
    procs = {}
    for pid_str in os.listdir("/proc"):
        if not pid_str.isdigit():
            continue
        pid = int(pid_str)
        info = get_process_info(pid)
        if info:
            procs[pid] = info
    return procs

class ProcessTracker:
    def __init__(self):
        self.known = {}
        self.uid_history = {}  # pid -> list of observed uid values
        self.fork_bursts = defaultdict(list)  # ppid -> list of fork timestamps

    def update(self, procs):
        now = time.time()

        for pid, info in procs.items():
            if pid not in self.known:
                # New process
                self.known[pid] = info
                self.uid_history[pid] = [info.get("eff_uid", -1)]
                ppid = info.get("ppid", 0)
                self.fork_bursts[ppid].append(now)

                # Detection: fork bomb / rapid child creation
                recent = [t for t in self.fork_bursts[ppid] if now - t < 2]
                self.fork_bursts[ppid] = recent
                if len(recent) > 20:
                    parent_info = self.known.get(ppid, {})
                    detect(
                        "rapid_fork",
                        "high",
                        f"Rapid child process creation: {len(recent)} children in 2s",
                        {
                            "ppid": ppid,
                            "parent_name": parent_info.get("name", "?"),
                            "child_count": len(recent)
                        }
                    )
            else:
                # Existing process, check for changes
                old_uid = self.known[pid].get("eff_uid", -1)
                new_uid = info.get("eff_uid", -1)

                # Detection: UID changed (privilege escalation)
                if old_uid != new_uid and old_uid != -1:
                    detect(
                        "uid_change",
                        "critical",
                        f"Process {pid} changed UID: {old_uid} -> {new_uid}",
                        {
                            "pid": pid,
                            "name": info.get("name", "?"),
                            "cmdline": info.get("cmdline", ""),
                            "old_uid": old_uid,
                            "new_uid": new_uid
                        }
                    )

                # Detection: process gained root (0) from non-root
                if old_uid != 0 and new_uid == 0:
                    detect(
                        "privilege_escalation",
                        "critical",
                        f"Process {pid} escalated to root (uid {old_uid} -> 0)",
                        {
                            "pid": pid,
                            "name": info.get("name", "?"),
                            "cmdline": info.get("cmdline", ""),
                            "old_uid": old_uid
                        }
                    )

                # Detection: process is being ptraced by a non-debugger
                tracer = info.get("tracer_pid", 0)
                old_tracer = self.known[pid].get("tracer_pid", 0)
                if tracer != 0 and old_tracer == 0:
                    tracer_info = procs.get(tracer, {})
                    tracer_name = tracer_info.get("name", "?")
                    # gdb, strace, ltrace are expected ptrace users
                    known_debuggers = {"gdb", "strace", "ltrace", "lldb", "valgrind"}
                    if tracer_name not in known_debuggers:
                        detect(
                            "ptrace_attach",
                            "high",
                            f"Process {pid} ({info.get('name', '?')}) ptraced by "
                            f"PID {tracer} ({tracer_name})",
                            {
                                "victim_pid": pid,
                                "victim_name": info.get("name", "?"),
                                "tracer_pid": tracer,
                                "tracer_name": tracer_name,
                                "tracer_cmdline": tracer_info.get("cmdline", "?")
                            }
                        )

                self.known[pid] = info

        # Clean up dead processes
        live_pids = set(procs.keys())
        dead = set(self.known.keys()) - live_pids
        for pid in dead:
            del self.known[pid]
            self.uid_history.pop(pid, None)

    def check_suspicious_trees(self):
        """Look for process trees that match exploitation patterns."""
        for pid, info in self.known.items():
            ppid = info.get("ppid", 0)
            parent = self.known.get(ppid)

            if not parent:
                continue

            # Detection: child in different user namespace than parent
            child_nstgid = info.get("nstgid", "")
            if "\t" in child_nstgid:
                # Has multiple namespace TGIDs = in a nested namespace
                parent_nstgid = parent.get("nstgid", "")
                if "\t" not in parent_nstgid:
                    detect(
                        "child_namespace_escape",
                        "high",
                        f"Child {pid} entered user namespace from parent {ppid}",
                        {
                            "child_pid": pid,
                            "child_name": info.get("name", "?"),
                            "parent_pid": ppid,
                            "parent_name": parent.get("name", "?"),
                            "child_nstgid": child_nstgid
                        }
                    )

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    tracker = ProcessTracker()

    try:
        while running:
            procs = scan_processes()
            tracker.update(procs)
            tracker.check_suspicious_trees()
            time.sleep(0.5)
    finally:
        with open(args.output, "w") as f:
            json.dump(DETECTIONS, f, indent=2)
        print(f"[process_monitor] Wrote {len(DETECTIONS)} detections to {args.output}")

if __name__ == "__main__":
    main()
