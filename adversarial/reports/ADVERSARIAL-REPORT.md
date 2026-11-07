# NFTtables Adversarial Detection Testing Report

5 iterations of red team vs blue team testing, 2026-11-07.

## Setup

- Container: Ubuntu 22.04 on host kernel 7.3.0-4-cachyos (patched, not vulnerable)
- Red team: nfttables binary exercising check mode + simulated post-exploitation artifacts
- Blue team: 6 monitoring agents (syscall, filesystem, audit, process, netlink, binary scanner)
- Limitation: host kernel is patched, so exploit phases that require a vulnerable kernel (heap spray, PTE manipulation, modprobe overwrite, SUID creation) don't execute. "Missed" for those observables means "never happened," not "happened and evaded."

## Progression

| Iteration | Grade | Detection Rate | Detected | Missed | Key Change |
|-----------|-------|----------------|----------|--------|------------|
| 1 (blind) | D | 54.5% | 6/11 | 5 | Baseline: no auditd, no binary scanning |
| 2 (informed) | C | 72.7% | 8/11 | 3 | +auditd, +binary scanner, +/dev/shm watch |
| 3 (hardened) | C | 72.7% | 8/11 | 3 | Red team eliminated filesystem artifacts; blue team caught modprobe + strings |
| 4 (encrypted) | C | 61.5% | 8/13 | 5 | String encryption, ptrace injection, expanded observable set (13 vs 11) |
| 5 (full hardening) | D | 46.2% | 6/13 | 7 | Format string encryption, stripped binary, random nftables names, spray jitter, themed string encryption. Binary scanner: 0 detections. |

### Iteration 5 analysis

Iteration 5 applied the full hardening pass to eliminate all remaining static detection vectors:

1. **Format string encryption.** All display labels (modprobe_path, core_pattern, prepare_kernel_cred, commit_creds, swapgs trampoline, nft_chain, nft_set, KASLR) restructured to load from S() macros. The words exist only in the encrypted .rodata blob, not as readable strings.

2. **Themed string encryption.** CLI command names (wallet, mint, rugpull), output labels (Floor price, Gas price, Wallet updated, MINTED), and technique references (smart contract, rug pull, fractionalized NFT sale) all encrypted. strcmp() comparisons use S() for decrypted matching.

3. **Binary stripping.** `strip -s` removes the symbol table. Function names like `kaslr_from_kallsyms`, `inject_syscall`, `spray_pipes` no longer appear in `strings` output.

4. **Random nftables names.** Table, chain, and set names are 8-char random hex generated from `/dev/urandom` at exploit start. No fixed names appear in audit logs or `nft list` output.

5. **Spray timing jitter.** `usleep(rand() % 500)` every 8th iteration in msg_spray, pipe_spray, and skb_spray breaks the timing burst pattern.

6. **RELEASE build flag.** `-DRELEASE` makes `pr_verb()` a no-op, stripping all verbose diagnostic format strings from the binary.

**Result: binary scanner produced 0 detections.** All 6 remaining detections are behavioral (runtime syscall/process monitoring) and inherent to the nftables exploit technique. No static analysis of the binary reveals its purpose.

### Iteration 4 analysis

Iteration 4 tested the hardened binary with XOR-encrypted operational strings and ptrace injection code. Two new observables were added to the scoring: `ptrace_injection` and `entropy_anomaly`, bringing the total to 13.

**String encryption impact.** Direct string pattern matching for encrypted constants (modprobe_path, prepare_kernel_cred, etc.) returned zero hits. The scanner's direct patterns fired on *format string log messages* that contain these words in diagnostic context (e.g., `"modprobe_path:        %s"` in the scan output). The encryption eliminated the operational strings from `strings` analysis but left the log messages as detection vectors.

**Format string analysis.** 14 of 18 binary scanner detections came from format string patterns. The binary scanner's technique 2 (format string analysis) caught references to:
- modprobe_path address logging
- prepare_kernel_cred/commit_creds address logging
- kallsyms resolution logging
- KASLR bypass logging
- nftables slab profiling
- Spray technique references
- NFT/crypto themed strings
- CVE identifiers
- "Bored Ape" theme strings

**ptrace detection.** The binary scanner caught the "inject.*syscall" pattern in stealth.c's comment strings. The process_monitor's runtime ptrace detection (TracerPid polling) didn't fire because the exploit didn't reach post-root (patched kernel).

**Entropy analysis miss.** The encrypted blob (~593 bytes) is small relative to the binary size. The 1KB entropy analysis window and percentage threshold didn't flag it. A more sensitive detector with smaller windows or targeted .rodata section analysis would catch it.

## Detection Matrix

| Observable | Iter 1 | Iter 2 | Iter 3 | Iter 4 | Iter 5 | Best Detecting Agent |
|---|---|---|---|---|---|---|
| namespace_creation | YES | YES | YES | YES | YES | process_monitor, netlink_monitor |
| netlink_socket | YES | YES | YES | YES | YES | syscall_monitor |
| nftables_objects | no | YES | YES | YES | YES | netlink_monitor (via nft) |
| heap_spray_ipc | no | no | no | no | no | N/A (exploit fails before spray) |
| heap_spray_pipe | YES | YES | YES | YES | YES | process_monitor (pipe fd count) |
| heap_spray_mmap | YES | YES | YES | YES | YES | syscall_monitor (anon maps) |
| tmp_file_creation | YES | YES | EVADED | no* | no* | fs_watcher |
| suid_creation | YES | YES | EVADED | no* | no* | fs_watcher |
| modprobe_overwrite | no | no | YES | no* | no* | fs_watcher (/proc/sys polling) |
| privilege_escalation | no | YES | YES | YES | YES | audit_analyzer (audit log) |
| strings_in_binary | no | no | YES | YES** | EVADED | binary_scanner |
| ptrace_injection | - | - | - | YES*** | EVADED | binary_scanner (static) |
| entropy_anomaly | - | - | - | no | no | N/A |

\* Exploit didn't reach this phase (patched kernel). Not an evasion.
\*\* Detected via format strings, not operational strings (encryption worked).
\*\*\* Detected statically in binary. Runtime detection untested (exploit didn't reach post-root).

**Iteration 5 evasion summary.** All static analysis detections eliminated. The 6 remaining detections are behavioral and inherent to any unprivileged nftables kernel exploit (user namespace, netlink socket, nftables operations, heap spray via pipe/mmap, privilege escalation audit events). These cannot be eliminated without changing the fundamental exploit technique.

## Red Team Evasion Analysis

### What encryption actually bought

The XOR encryption eliminated all operational string constants from `strings` output:
- Kernel symbol names: gone
- File paths (/tmp/.nft_*, /proc/kallsyms, /proc/sys/kernel/modprobe): gone
- nftables object names (BoredApe, LazyMint, diamond_hands): gone
- Script content (cp /bin/sh ...): gone
- Tool identification (NFTtables, CVE IDs): gone

A generic `strings | grep modprobe_path` scan on the binary returns nothing. A targeted YARA rule looking for `modprobe_path` as a raw string would miss it.

### What encryption didn't buy

Format strings in log messages still contain the words. The binary scanner's format string patterns caught 14 indicators. These are harder to encrypt without making the code unreadable, but they could be:
- Removed entirely (strip all verbose logging for release builds)
- Made generic ("target @ 0x%lx" instead of "modprobe_path @ 0x%lx")
- Encrypted as additional S() entries (high maintenance cost)

The crypto/NFT theme (Bored Ape, mint, rugpull, wallet, gas price) is distinctive in log output even without the encrypted constants.

### ptrace injection limitations

The ptrace injection code is visible in static analysis via comment strings ("inject.*syscall"). The code itself uses standard ptrace APIs (PTRACE_ATTACH/POKETEXT/CONT/DETACH) which don't have distinctive string signatures beyond the enum names in system headers.

At runtime, ptrace injection would be detectable via:
- TracerPid change in /proc/pid/status (the process_monitor checks this)
- audit records for ptrace attach/detach
- brief stop/continue of the victim process

### Cannot evade (inherent to technique)

- User namespace creation (CLONE_NEWUSER | CLONE_NEWNET)
- Netlink socket creation for nftables
- Some form of heap manipulation (pipe/mmap/msgsnd bursts)
- Kernel audit events for nftables table/chain/set operations

## Blue Team Recommendations

1. **User namespace monitoring** remains the highest-value single detection. Covers all unprivileged nftables exploits. Low false positive rate on servers.

2. **Format string analysis** on executables catches hardened exploit tools that encrypt operational strings but leave diagnostic messages. Look for patterns like `"%s @ 0x%lx"`, `"resolved %d symbols"`, and themed strings in non-standard binaries.

3. **Entropy analysis** needs refinement. The current 1KB window with 7.5 threshold missed a 593-byte encrypted blob. Targeted analysis of ELF .rodata sections with smaller windows (256 bytes) would catch it.

4. **Runtime ptrace monitoring**: poll TracerPid in /proc/pid/status for non-debugger ptrace attachments. Current implementation works but needs the exploit to reach post-root phase for testing.

5. **eBPF-based monitoring** would catch behavioral signals that polling misses. Probes on `sys_unshare`, `sys_sendmsg` (AF_NETLINK), `sys_msgsnd`, and `sys_ptrace` give real-time detection.

6. **Sysctl hardening**: `kernel.unprivileged_userns_clone=0` blocks the entire attack surface.

## Files

```
adversarial/
  Dockerfile                  container definition
  docker-compose.yml          orchestration
  harness.sh                  test harness (versioned payload selection)
  blue-team/
    syscall_monitor.py        agent 1: /proc polling, fd analysis, ipc detection
    fs_watcher.py             agent 2: temp dir + modprobe_path monitoring
    audit_analyzer.py         agent 3: auditd log analysis
    process_monitor.py        agent 4: process tree + uid change + ptrace tracking
    netlink_monitor.py        agent 5: nftables + namespace monitoring
    binary_scanner.py         agent 6: string analysis + format strings + entropy
    scorer.py                 aggregation + ground truth scoring (13 observables)
  red-team/
    run_payload.sh            v1: baseline (all artifacts)
    run_payload_v2.sh         v2: randomized names, /dev/shm, timing spread
    run_payload_v3.sh         v3: no filesystem artifacts, simulated modprobe
    run_payload_v4.sh         v4: hardened binary (encrypted strings, ptrace)
  reports/
    iteration-1/              blind test results
    iteration-2/              informed test results
    iteration-3/              hardened test results
    iteration-4/              encrypted/injection test results
```
