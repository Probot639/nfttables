# OPSEC considerations

What the tool touches, what it leaves behind, and what watches. Updated for the v0.2 hardening pass (string encryption, ptrace injection).

## Static analysis resistance

All operational strings are XOR-encrypted at build time with a random 32-byte key. The encrypted table covers:

- Kernel symbol names (modprobe_path, prepare_kernel_cred, commit_creds, etc.)
- nftables object names (table/chain/set names for both exploits)
- File paths (/tmp/.nft_*, /proc/kallsyms, /proc/sys/kernel/modprobe)
- Script content (the modprobe payload)
- Tool identification strings (name, motto, CVE IDs)
- Slab cache names

`strings` on the stripped binary won't find any of these. Log format strings (verbose/debug messages) are not encrypted. They contain words like "modprobe_path" and "kallsyms" in diagnostic context. A targeted YARA rule looking for these format strings could still flag the binary, but generic string-matching tools won't find the operational constants.

Each build regenerates the key and produces different ciphertext. Signature-based detection of the encrypted blob doesn't transfer between builds.

## Filesystem artifacts

| Path | Created by | Lifetime | Stealth |
|---|---|---|---|
| `/tmp/.nft_mint` | modprobe_path payload script | until rugpull | ptrace injection (32233) / direct (1086) |
| `/tmp/.nft_sh` | SUID root shell | until rugpull | created by kernel (modprobe exec) |
| `/tmp/.nft_trigger` | binary with bad magic (triggers modprobe) | seconds | direct write, unlinked after exec |
| `/tmp/.nft_xattr_*` | xattr spray temp file (1086) | seconds | direct write, unlinked |

`rugpull` removes all persistent artifacts. If the process crashes mid-exploit, they persist.

The binary itself (wherever you drop it) is the largest artifact. `make release` strips it. Delete after use or run from memfd.

## Process injection (attribution evasion)

Post-root, the tool can write files via ptrace injection into a victim process. The flow:

1. Find a long-lived root daemon (prefers systemd-journald, rsyslogd, chronyd, crond)
2. PTRACE_ATTACH to the victim, save register state
3. Write syscall + int3 shellcode at the victim's current RIP
4. Push file path and data below the victim's RSP via PTRACE_POKETEXT
5. Set up syscall args in registers, PTRACE_CONT
6. Wait for SIGTRAP (int3 after syscall return), read result from RAX
7. Repeat for open/write/close sequence
8. Restore original registers and code, PTRACE_DETACH

Audit sees the open/write/close attributed to the victim PID. The NFTtables process only shows ptrace attach/detach, which is less distinctive than direct file creation.

Current coverage: CVE-2023-32233 post-root path uses injection for the modprobe script write and modprobe_path overwrite. CVE-2024-1086 does not use injection because the script write happens before the exploit grants root (the dirty pagetable technique writes kernel memory directly, then modprobe executes the script to create the SUID shell).

Limitations:
- Requires root (only useful post-exploitation)
- x86_64 only (register layout and syscall ABI are hardcoded)
- The victim process is briefly interrupted (stopped/continued). Long-lived daemons tolerate this. Interactive processes might visibly stall.
- PTRACE_ATTACH generates a ptrace audit event. Less distinctive than file creation, but not invisible.

## Kernel memory

CVE-2024-1086 overwrites `modprobe_path` in kernel memory. The default value is `/sbin/modprobe`. After exploitation:

```bash
cat /proc/sys/kernel/modprobe
# shows the overwrite path instead of /sbin/modprobe

# restore:
echo -n '/sbin/modprobe' > /proc/sys/kernel/modprobe
```

`rugpull` prints this reminder but cannot restore it without root. If you already have root from the exploit, restore it before dropping privileges.

CVE-2023-32233 corrupts heap objects but the corruption is consumed during exploitation. No persistent kernel memory modification after the ROP chain completes (modprobe_path is overwritten via /proc, which is a clean write, not memory corruption).

## Audit trail

### nftables audit events

The kernel logs nftables operations to the audit subsystem. Creating tables, chains, sets, and rules all generate audit records:

```
type=NETFILTER_CFG msg=audit(...): table=BoredApe family=1 ...
type=NETFILTER_CFG msg=audit(...): table=LazyMint family=2 ...
```

The table names appear in audit logs. They're encrypted in the binary but decrypted at runtime and passed to the kernel, so they show up in kernel audit. This cannot be avoided without changing the names (which you should do before deployment, see Reducing Footprint below).

### dmesg / kernel log

Depending on kernel config:
- nf_tables messages about table creation/deletion
- KASAN/KFENCE reports if memory debugging is enabled (unlikely in production)
- Page fault traces if exploitation fails uncleanly

### Process artifacts

- `unshare()` / `clone3()` syscall for namespace creation
- Burst of `msgsnd()` calls (heap spray)
- Burst of `pipe()` calls (pipe spray, CVE-2024-1086)
- Burst of `mmap()` calls with MAP_POPULATE (PTE spray)
- `ptrace()` attach/detach on a victim process (post-root injection)
- Child process with different network namespace

### Network

Both exploits operate entirely through netlink sockets (AF_NETLINK, NETLINK_NETFILTER). No network traffic leaves the box. The nftables operations happen inside the child's network namespace and don't affect the host's packet filtering.

## Detection signatures

What a defender would look for:

1. **Static analysis.** The encrypted strings defeat basic `strings` scanning. A targeted YARA rule on the format strings (which are not encrypted) could flag the binary. The XOR key is embedded in .rodata and could be extracted with a known-plaintext attack if the defender knows any of the original strings. Entropy analysis of the .rodata section would show a high-entropy blob (the encrypted table) which is unusual for a C binary without embedded resources.

2. **Behavioral.** The syscall sequence is distinctive. Within a few seconds: clone(CLONE_NEWUSER|CLONE_NEWNET) -> socket(AF_NETLINK) -> sendmsg (nftables batch) -> msgsnd/pipe/mmap burst -> ptrace attach/detach. An eBPF program on clone+sendmsg could flag this. The ptrace attach on a daemon is itself suspicious when not from a debugger.

3. **Audit.** nftables table names in audit log. A rule watching for table creation by unprivileged users (via user namespaces) would catch this. PTRACE_ATTACH events from a non-debugger process.

4. **Filesystem.** inotify on /tmp for dotfile creation. The file paths are encrypted in the binary but the actual files still land on disk at runtime.

5. **Memory.** modprobe_path changed from default. Periodic check via /proc/sys/kernel/modprobe.

6. **Process tree.** A short-lived child with CLONE_NEWUSER|CLONE_NEWNET that then does IPC spray is unusual. Process tree analysis (parent->child->namespace) is a strong signal.

## Reducing footprint

If OPSEC matters for your engagement:

- Change table/chain/set names in gen_obf.py to something bland before deployment. The encrypted binary won't have the originals in strings, but the kernel audit will record whatever names you use.
- Change /tmp paths to a less obvious location. The paths are in gen_obf.py.
- Add delays between spray phases to spread the syscall burst over time.
- Clean up immediately after exploitation (call rugpull logic inline).
- Run from memfd_create rather than writing to disk. Pipe the binary in via stdin.
- Restore modprobe_path immediately after getting root.
- Deploy on a system where ptrace from root isn't logged (no audit rules on ptrace).
- The binary's .rodata entropy profile could be smoothed by padding the encrypted section with random data to match normal .rodata distributions. Not implemented.

## What hardening does NOT cover

Some things are visible regardless of hardening. These are inherent to the exploitation technique:

- **User namespace creation.** Both exploits need CLONE_NEWUSER|CLONE_NEWNET. You can use clone3() instead of unshare() (the kernel function is the same, some userspace tools don't hook clone3), but the namespace is still created and visible.
- **Netlink socket.** AF_NETLINK with NETLINK_NETFILTER is required for nftables batch operations. Cannot be avoided.
- **Heap spray syscalls.** msgsnd, pipe, mmap bursts are inherent to the technique. They can be spread over time but not eliminated.
- **Kernel audit events.** NETFILTER_CFG audit records are generated by the kernel, not userspace. Cannot be suppressed from the exploit.
- **nftables objects.** The actual table/chain/set/rule structures exist in kernel memory during exploitation. They're torn down with the namespace, but they exist for the duration.
