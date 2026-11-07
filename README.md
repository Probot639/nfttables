# NFTtables

Post-exploitation persistence tool for Linux. Targets nftables kernel vulnerabilities to escalate privileges and establish a root foothold. Two exploits, auto-targeting, full offset resolution, string encryption, process injection for attribution evasion, and a cleanup command. Ships as a single stripped static binary.

"Not your keys, not your kernel."

## What it does

You already have a shell on the box. NFTtables turns that into root via kernel bugs in nftables, then persists a SUID shell. The binary is designed to resist static analysis (encrypted strings, stripped symbols) and minimize its audit footprint (ptrace-based syscall injection attributes file operations to other processes).

## Exploits

**Bored Ape #1086** (CVE-2024-1086). nft_verdict_init double-free. A verdict map element with NF_DROP + chain reference causes the chain to be freed twice on table flush. The double-free feeds a dirty pagetable attack: cross-cache reclaim converts the slab object into a PTE page, giving arbitrary physical memory read/write. Overwrites modprobe_path. Affected: 3.15 through 6.7.1. Reliability: high.

**Bored Ape #32233** (CVE-2023-32233). Anonymous set use-after-free in batch processing. A single netlink batch creates an anonymous set, binds it to a rule, and deletes it. The commit path frees the set while the rule still references it. Heap spray reclaims the freed nft_set with controlled data redirecting function pointers through a ROP chain to commit_creds(prepare_kernel_cred(0)). After getting root, uses ptrace injection for the modprobe script write and modprobe_path overwrite. Affected: 3.18 through 6.3.1. Reliability: medium (needs per-kernel ROP gadgets).

Both exploits use unprivileged user namespaces to obtain CAP_NET_ADMIN for nftables access. No prior privileges required beyond the ability to create user namespaces (default on Ubuntu, Fedora, most modern distros).

## Build

```
make            # dynamic build (development)
make static     # musl static binary (deployment, needs musl-gcc)
make release    # static + stripped
make install    # release + copy to /bin/nfttables
```

Depends on: C11 compiler, Linux kernel headers, musl-tools (for static build).

String encryption key regenerates every build. Each build produces a binary with unique encrypted constants.

## Usage

```
nfttables wallet         # show privilege state
nfttables collections    # list available exploits
nfttables info           # full recon: kernel, vulns, namespace support
nfttables scan -v        # resolve kernel offsets + gadgets + slab info
nfttables extract        # extract vmlinux from /boot for gadget scanning
nfttables check [id]     # probe for vulnerability without exploiting
nfttables mint [id]      # escalate (auto, 1086, or 32233)
nfttables rugpull        # clean up artifacts
```

The `scan` command runs the full resolution pipeline: /proc/kallsyms, hardcoded offset database (Ubuntu, Debian, Fedora, RHEL, Amazon Linux, Arch), vmlinux extraction, and ROP gadget scanning. Run it first to see what the tool can resolve on the target.

## Hardening

**String encryption.** All operational strings (symbol names, file paths, nftables object names, script content, identification strings) are XOR-encrypted with a 32-byte random key generated at build time. Decrypted at runtime into heap memory, freed on exit. `strings` on the binary returns nothing useful for these. Log format strings (human-readable messages) are not encrypted since they're informational, not operational.

**Process injection.** Post-root filesystem writes go through ptrace injection when possible. The tool attaches to a long-lived root daemon (systemd-journald, rsyslogd, etc.), injects open/write/close syscalls into the victim's register state, and detaches. Audit logs attribute the file operations to the victim PID, not the NFTtables process. Falls back to direct writes if injection fails.

**Static build.** musl-gcc static link, stripped. No dynamic loader, no libc dependency. Single file deployment.

See [docs/OPSEC.md](docs/OPSEC.md) for the full detection surface.

## Offset Resolution

The tool resolves kernel symbol addresses and struct offsets through multiple strategies, tried in order:

1. **/proc/kallsyms** -- instant if kptr_restrict=0. Gives all needed symbol addresses.
2. **Hardcoded database** -- covers common distro kernels (Ubuntu 22.04/24.04, Debian 11/12, Fedora 38/39, RHEL 8/9, Amazon Linux 2, Arch/CachyOS). Provides struct field offsets and slab cache sizes.
3. **vmlinux extraction** -- decompresses /boot/vmlinuz-* (gzip, xz, lz4, zstd, bzip2, lzma, lzo) and scans the ELF .text section for ROP gadgets.
4. **KASLR bypass** -- tries kallsyms, dmesg leaks, /proc/modules, /sys/kernel/notes to determine the kernel text base address.

For CVE-2024-1086, you only need modprobe_path (strategy 1 or 2). For CVE-2023-32233, you need ROP gadgets (strategy 3) or can fall back to modprobe_path if a gadget-free exploitation path is available.

## Spray Library

spray.c provides composable heap manipulation primitives:

- **msg_spray** -- msgsnd()-based slab allocation with controlled content
- **pipe_spray** -- pipe buffer page allocation for dirty pagetable
- **pte_spray** -- anonymous memory mapping to force PTE page allocation
- **skb_spray** -- UDP sk_buff allocation for network buffer caches
- **key_spray** -- add_key() for user_key_payload allocation
- **setxattr** -- ephemeral slab allocation during race windows
- **cross_cache_drain** -- free all objects in a slab to return the page to buddy
- **overwrite_via_pte** -- forge and write PTEs for arbitrary physical memory access

## Adding Kernel Support

See [docs/ADDING-KERNELS.md](docs/ADDING-KERNELS.md). Short version: run `nfttables scan -v` on the target, record the output, add an entry to the offset_db table in offsets.c.

## OPSEC

See [docs/OPSEC.md](docs/OPSEC.md).

## Adversarial Testing

The `adversarial/` directory contains a Docker-based red vs. blue test lab. Six blue team monitoring agents (syscall monitor, filesystem watcher, audit analyzer, process monitor, netlink monitor, binary scanner) run against the payload. A scorer grades detection coverage. See [adversarial/reports/ADVERSARIAL-REPORT.md](adversarial/reports/ADVERSARIAL-REPORT.md) for results.

```
cd adversarial && docker compose up --build
```

## Files

```
nfttables.h        types, constants, function declarations
arch.h             x86_64/aarch64 page table and gadget constants
offsets.h          offset database types and resolution API
obf.h              string encryption IDs and decryption API
stealth.h          ptrace-based process injection API
main.c             CLI dispatch
netlink.c          nftables netlink batch construction + namespace setup
detect.c           kernel version detection + exploit selection
wallet.c           privilege state display
offsets.c          offset database (15 distro entries) + resolution pipeline
kaslr.c            KASLR bypass collection (kallsyms, dmesg, modules, sysfs)
vmlinux.c          boot image decompression + ELF section parsing
gadgets.c          x86_64 ROP gadget scanner
spray.c            heap spray primitives (msg, pipe, PTE, skb, key, xattr)
obf.c              runtime XOR string decryption
stealth.c          ptrace syscall injection for attribution evasion
cve_2024_1086.c    verdict double-free + dirty pagetable exploit
cve_2023_32233.c   anonymous set UAF + heap spray + ROP exploit
rugpull.c          post-exploitation cleanup
tools/gen_obf.py   build-time string encryption generator
```
