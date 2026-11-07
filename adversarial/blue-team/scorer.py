#!/usr/bin/env python3
"""
Blue Team Scorer: Aggregates detections from all agents and produces a scorecard.
Evaluates what the blue team caught vs what slipped through.
"""

import argparse
import json
import os
import sys
from collections import defaultdict
from datetime import datetime

# Known observable artifacts of a kernel LPE exploit.
# The blue team doesn't know which specific ones nfttables produces,
# but we score against this ground truth after the fact.
GROUND_TRUTH_OBSERVABLES = {
    # Category: what nfttables actually does
    "namespace_creation": "Creates user+net namespace via unshare()",
    "netlink_socket": "Opens NETLINK_NETFILTER socket",
    "nftables_objects": "Creates/deletes nftables tables, chains, sets, rules",
    "heap_spray_ipc": "Burst of msgsnd() calls for heap spray",
    "heap_spray_pipe": "Burst of pipe() calls for pipe spray",
    "heap_spray_mmap": "Burst of mmap(MAP_POPULATE) for PTE spray",
    "tmp_file_creation": "Creates files in /tmp (.nft_mint, .nft_sh, .nft_trigger)",
    "suid_creation": "Creates SUID binary (/tmp/.nft_sh)",
    "modprobe_overwrite": "Overwrites modprobe_path in kernel memory",
    "privilege_escalation": "Process gains root credentials (uid 0)",
    "strings_in_binary": "Distinctive strings in binary (operational constants)",
    "ptrace_injection": "ptrace attach/detach on victim process for syscall injection",
    "entropy_anomaly": "High-entropy blob in .rodata suggesting encrypted/packed data",
}

# Map detection categories to ground truth observables
CATEGORY_TO_OBSERVABLE = {
    "namespace_escape": "namespace_creation",
    "child_namespace_escape": "namespace_creation",
    "unprivileged_namespace": "namespace_creation",
    "new_network_namespace": "namespace_creation",
    "unnamed_network_namespace": "namespace_creation",
    "netfilter_socket": "netlink_socket",
    "excessive_netfilter_sockets": "netlink_socket",
    "nftables_new_table": "nftables_objects",
    "nftables_table_deleted": "nftables_objects",
    "nftables_config_change": "nftables_objects",
    "nftables_verdict_map": "nftables_objects",
    "nftables_anonymous_set": "nftables_objects",
    "nftables_many_chains": "nftables_objects",
    "msgsnd_spray_pattern": "heap_spray_ipc",
    "ipc_activity": "heap_spray_ipc",
    "pipe_spray_pattern": "heap_spray_pipe",
    "heap_spray_pattern": "heap_spray_mmap",
    "hidden_tmpfile": "tmp_file_creation",
    "tmp_file_write": "tmp_file_creation",
    "script_in_tmp": "tmp_file_creation",
    "executable_in_tmp": "tmp_file_creation",
    "elf_in_tmp": "tmp_file_creation",
    "unknown_magic_executable": "tmp_file_creation",
    "suid_created": "suid_creation",
    "sgid_created": "suid_creation",
    "modprobe_tampered": "modprobe_overwrite",
    "uid_change": "privilege_escalation",
    "privilege_escalation": "privilege_escalation",
    "privilege_change": "privilege_escalation",
    "rapid_fork": "heap_spray_pipe",
    "suspicious_caps": "namespace_creation",
    # Binary scanner (added iteration 2)
    "kernel_exploit_string": "strings_in_binary",
    "heap_spray_string": "strings_in_binary",
    "exploit_technique_string": "strings_in_binary",
    "nftables_exploit_string": "strings_in_binary",
    "netfilter_string": "strings_in_binary",
    "cve_reference": "strings_in_binary",
    "namespace_string": "strings_in_binary",
    "generic_exploit_string": "strings_in_binary",
    "kernel_info_access": "strings_in_binary",
    # ptrace injection detections
    "ptrace_attach": "ptrace_injection",
    "ptrace_inject": "ptrace_injection",
    "ptrace_suspicious": "ptrace_injection",
    # entropy analysis detections
    "high_entropy_section": "entropy_anomaly",
    "encrypted_data_blob": "entropy_anomaly",
    "obfuscated_binary": "entropy_anomaly",
    # format string pattern detections
    "format_string_exploit_indicator": "strings_in_binary",
}

def load_detections(report_dir):
    """Load all detection files from the report directory."""
    all_detections = []
    for fname in os.listdir(report_dir):
        if fname.endswith("_detections.json"):
            path = os.path.join(report_dir, fname)
            try:
                with open(path, "r") as f:
                    detections = json.load(f)
                    all_detections.extend(detections)
            except (json.JSONDecodeError, FileNotFoundError):
                pass
    return all_detections

def score(detections):
    """Score the blue team's performance."""
    # Which observables were detected
    detected_observables = set()
    detection_by_observable = defaultdict(list)
    severity_counts = defaultdict(int)
    agent_counts = defaultdict(int)

    for d in detections:
        cat = d.get("category", "")
        observable = CATEGORY_TO_OBSERVABLE.get(cat)
        if observable:
            detected_observables.add(observable)
            detection_by_observable[observable].append(d)

        severity_counts[d.get("severity", "unknown")] += 1
        agent_counts[d.get("agent", "unknown")] += 1

    # Score
    total_observables = len(GROUND_TRUTH_OBSERVABLES)
    detected_count = len(detected_observables)
    missed = set(GROUND_TRUTH_OBSERVABLES.keys()) - detected_observables

    detection_rate = detected_count / total_observables if total_observables > 0 else 0

    # Build scorecard
    scorecard = {
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "total_detections": len(detections),
            "total_observables": total_observables,
            "detected_observables": detected_count,
            "missed_observables": len(missed),
            "detection_rate": round(detection_rate * 100, 1),
            "grade": grade_from_rate(detection_rate),
        },
        "by_severity": dict(severity_counts),
        "by_agent": dict(agent_counts),
        "detected": {
            obs: {
                "description": GROUND_TRUTH_OBSERVABLES[obs],
                "detection_count": len(detection_by_observable[obs]),
                "first_detection": detection_by_observable[obs][0].get("timestamp", "?"),
                "detecting_agents": list(set(
                    d.get("agent", "?") for d in detection_by_observable[obs]
                )),
            }
            for obs in sorted(detected_observables)
        },
        "missed": {
            obs: GROUND_TRUTH_OBSERVABLES[obs]
            for obs in sorted(missed)
        },
        "evasion_recommendations": generate_recommendations(missed, detected_observables),
        "detection_improvements": generate_improvements(missed),
    }

    return scorecard

def grade_from_rate(rate):
    if rate >= 0.9:
        return "A"
    elif rate >= 0.75:
        return "B"
    elif rate >= 0.6:
        return "C"
    elif rate >= 0.4:
        return "D"
    else:
        return "F"

def generate_recommendations(missed, detected):
    """Generate red team evasion recommendations based on what was detected."""
    recs = []

    if "nftables_objects" in detected:
        recs.append({
            "target": "nftables_objects",
            "recommendation": "Rename tables/chains/sets to common system names to blend in",
            "difficulty": "easy"
        })

    if "heap_spray_ipc" in detected:
        recs.append({
            "target": "heap_spray_ipc",
            "recommendation": "Spread msgsnd() calls over time with random delays",
            "difficulty": "medium"
        })

    if "heap_spray_pipe" in detected:
        recs.append({
            "target": "heap_spray_pipe",
            "recommendation": "Reduce pipe count, use alternative spray primitives (skb, key)",
            "difficulty": "medium"
        })

    if "tmp_file_creation" in detected:
        recs.append({
            "target": "tmp_file_creation",
            "recommendation": "Use memfd_create() instead of /tmp files, or randomize names",
            "difficulty": "easy"
        })

    if "suid_creation" in detected:
        recs.append({
            "target": "suid_creation",
            "recommendation": "Use commit_creds ROP path instead of SUID shell, or use memfd",
            "difficulty": "hard"
        })

    if "namespace_creation" in detected:
        recs.append({
            "target": "namespace_creation",
            "recommendation": "Namespace creation is inherent to the technique. Consider alternative CAP_NET_ADMIN acquisition if available.",
            "difficulty": "hard"
        })

    if "modprobe_overwrite" in detected:
        recs.append({
            "target": "modprobe_overwrite",
            "recommendation": "Restore modprobe_path immediately after payload executes, or use core_pattern/poweroff_cmd instead",
            "difficulty": "medium"
        })

    return recs

def generate_improvements(missed):
    """Generate blue team improvement recommendations for missed observables."""
    improvements = []

    if "heap_spray_mmap" in missed:
        improvements.append({
            "observable": "heap_spray_mmap",
            "improvement": "Monitor /proc/pid/maps for rapid anonymous mapping growth (>500 RW anon regions)",
            "implementation": "Increase polling frequency in syscall_monitor, check maps more aggressively"
        })

    if "strings_in_binary" in missed:
        improvements.append({
            "observable": "strings_in_binary",
            "improvement": "Add static binary analysis: scan executable pages for known exploit tool signatures",
            "implementation": "New agent: binary_scanner.py that strings-checks /proc/pid/exe on new process"
        })

    if "modprobe_overwrite" in missed:
        improvements.append({
            "observable": "modprobe_overwrite",
            "improvement": "Increase modprobe_path polling frequency to sub-second",
            "implementation": "Check /proc/sys/kernel/modprobe every 200ms instead of 1s"
        })

    if "privilege_escalation" in missed:
        improvements.append({
            "observable": "privilege_escalation",
            "improvement": "Track UID changes in real-time via audit or eBPF",
            "implementation": "Add auditd rule for setuid/setgid, or eBPF probe on commit_creds"
        })

    return improvements

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    detections = load_detections(args.report_dir)
    scorecard = score(detections)

    # Write JSON
    with open(args.output, "w") as f:
        json.dump(scorecard, f, indent=2)

    # Print human-readable summary
    s = scorecard["summary"]
    print(f"\n{'='*60}")
    print(f"  BLUE TEAM SCORECARD - Grade: {s['grade']}")
    print(f"{'='*60}")
    print(f"  Detection rate: {s['detection_rate']}% ({s['detected_observables']}/{s['total_observables']} observables)")
    print(f"  Total alerts:   {s['total_detections']}")
    print(f"  Missed:         {s['missed_observables']} observables")
    print()

    if scorecard["detected"]:
        print("  DETECTED:")
        for obs, info in scorecard["detected"].items():
            agents = ", ".join(info["detecting_agents"])
            print(f"    [+] {obs}: {info['description']}")
            print(f"        ({info['detection_count']} alerts from {agents})")

    if scorecard["missed"]:
        print()
        print("  MISSED:")
        for obs, desc in scorecard["missed"].items():
            print(f"    [-] {obs}: {desc}")

    if scorecard["evasion_recommendations"]:
        print()
        print("  RED TEAM EVASION OPPORTUNITIES:")
        for rec in scorecard["evasion_recommendations"]:
            print(f"    > {rec['target']}: {rec['recommendation']} [{rec['difficulty']}]")

    if scorecard["detection_improvements"]:
        print()
        print("  BLUE TEAM IMPROVEMENTS:")
        for imp in scorecard["detection_improvements"]:
            print(f"    > {imp['observable']}: {imp['improvement']}")

    print(f"\n{'='*60}\n")

if __name__ == "__main__":
    main()
