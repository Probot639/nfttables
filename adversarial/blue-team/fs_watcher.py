#!/usr/bin/env python3
"""
Blue Team Agent 2: Filesystem watcher.
Monitors /tmp and sensitive paths for suspicious file creation.
Generic LPE detection heuristics, no nfttables knowledge.
"""

import argparse
import json
import os
import signal
import stat
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

WATCH_DIRS = ["/tmp", "/var/tmp", "/dev/shm", "/run", "/run/user"]
SENSITIVE_FILES = [
    "/proc/sys/kernel/modprobe",
    "/proc/sys/kernel/core_pattern",
    "/proc/sys/kernel/poweroff_cmd",
]

def detect(category, severity, description, evidence):
    DETECTIONS.append({
        "timestamp": datetime.now().isoformat(),
        "agent": "fs_watcher",
        "category": category,
        "severity": severity,
        "description": description,
        "evidence": evidence
    })

def scan_tmp_dirs():
    """Scan temp directories for suspicious files."""
    known_files = {}
    for d in WATCH_DIRS:
        if os.path.isdir(d):
            try:
                for f in os.listdir(d):
                    path = os.path.join(d, f)
                    try:
                        st = os.stat(path)
                        known_files[path] = st.st_mtime
                    except (FileNotFoundError, PermissionError):
                        pass
            except PermissionError:
                pass
    return known_files

def check_file_suspicious(path):
    """Check if a newly created file looks like an exploit artifact."""
    detections = []

    try:
        st = os.stat(path)
    except (FileNotFoundError, PermissionError):
        return detections

    basename = os.path.basename(path)

    # Hidden files in /tmp
    if basename.startswith(".") and os.path.dirname(path) in WATCH_DIRS:
        detections.append(("hidden_tmpfile", "medium",
            f"Hidden file created in temp directory: {path}",
            {"path": path}))

    # SUID binaries
    if st.st_mode & stat.S_ISUID:
        detections.append(("suid_created", "critical",
            f"SUID binary created: {path}",
            {"path": path, "mode": oct(st.st_mode), "owner": st.st_uid}))

    # SGID binaries
    if st.st_mode & stat.S_ISGID:
        detections.append(("sgid_created", "high",
            f"SGID binary created: {path}",
            {"path": path, "mode": oct(st.st_mode), "owner": st.st_uid}))

    # Executable files in /tmp
    if st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
        if os.path.dirname(path) in WATCH_DIRS:
            detections.append(("executable_in_tmp", "high",
                f"Executable created in temp directory: {path}",
                {"path": path, "mode": oct(st.st_mode)}))

    # Shell scripts (check content)
    try:
        with open(path, "rb") as f:
            header = f.read(256)
        if header.startswith(b"#!/"):
            detections.append(("script_in_tmp", "medium",
                f"Script created in temp directory: {path}",
                {"path": path, "header": header[:64].decode(errors="replace")}))
        # ELF binaries with weird magic
        if header[:4] == b"\x7fELF":
            detections.append(("elf_in_tmp", "high",
                f"ELF binary created in temp directory: {path}",
                {"path": path, "size": st.st_size}))
        # Non-ELF executables (modprobe trigger pattern)
        if (st.st_mode & stat.S_IXUSR) and header[:4] != b"\x7fELF" and not header.startswith(b"#!"):
            detections.append(("unknown_magic_executable", "critical",
                f"Executable with unknown magic bytes in temp: {path}",
                {"path": path, "magic": header[:8].hex()}))
    except (FileNotFoundError, PermissionError, IsADirectoryError):
        pass

    return detections

def check_modprobe_path():
    """Check if modprobe_path has been tampered with."""
    try:
        with open("/proc/sys/kernel/modprobe", "r") as f:
            current = f.read().strip()
        if current != "/sbin/modprobe" and current != "/usr/sbin/modprobe":
            return ("modprobe_tampered", "critical",
                f"modprobe_path changed to non-standard value: {current}",
                {"current": current, "expected": "/sbin/modprobe"})
    except (FileNotFoundError, PermissionError):
        pass
    return None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    known_files = scan_tmp_dirs()
    last_modprobe_check = 0

    try:
        while running:
            # Scan for new files
            for d in WATCH_DIRS:
                if not os.path.isdir(d):
                    continue
                try:
                    for f in os.listdir(d):
                        path = os.path.join(d, f)
                        try:
                            st = os.stat(path)
                        except (FileNotFoundError, PermissionError):
                            continue

                        if path not in known_files or st.st_mtime != known_files.get(path):
                            known_files[path] = st.st_mtime
                            for cat, sev, desc, ev in check_file_suspicious(path):
                                detect(cat, sev, desc, ev)
                except PermissionError:
                    pass

            # Frequent modprobe check (iteration 2: was 1s, now 200ms)
            now = time.time()
            if now - last_modprobe_check > 0.2:
                result = check_modprobe_path()
                if result:
                    detect(*result)
                last_modprobe_check = now

            time.sleep(0.2)
    finally:
        with open(args.output, "w") as f:
            json.dump(DETECTIONS, f, indent=2)
        print(f"[fs_watcher] Wrote {len(DETECTIONS)} detections to {args.output}")

if __name__ == "__main__":
    main()
