# NFTtables

Red team LPE tool targeting Linux nftables kernel vulnerabilities. Two exploits, auto-targeting, full offset resolution pipeline, and a cleanup command. Ships as a single static binary.

"Not your keys, not your kernel."

## Exploits

**Bored Ape #1086** (CVE-2024-1086). nft_verdict_init double-free. A verdict map element with NF_DROP + chain reference causes the chain to be freed twice on table flush. The double-free feeds a dirty pagetable attack: cross-cache reclaim converts the slab object into a PTE page, giving arbitrary physical memory read/write. Overwrites modprobe_path. Affected: 3.15 through 6.7.1. Reliability: high.

**Bored Ape #32233** (CVE-2023-32233). Anonymous set use-after-free in batch processing. A single netlink batch creates an anonymous set, binds it to a rule, and deletes it. The commit path frees the set while the rule still references it. Heap spray reclaims the freed nft_set with controlled data redirecting function pointers through a ROP chain to commit_creds(prepare_kernel_cred(0)). Affected: 3.18 through 6.3.1. Reliability: medium (needs per-kernel ROP gadgets).

Both exploits use unprivileged user namespaces to obtain CAP_NET_ADMIN for nftables access. No prior privileges required beyond the ability to create user namespaces (default on Ubuntu, Fedora, most modern distros).

## Build

```
make            # dynamic build (development)
make static     # musl static binary (deployment, needs musl-gcc)
make release    # static + stripped
```

Depends on: C11 compiler, Linux kernel headers, musl-tools (for static build).

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

Observable artifacts: netlink socket creation, CLONE_NEWUSER|CLONE_NEWNET, nftables table/chain/set manipulation, msgsnd burst, pipe burst, /tmp file creation, modprobe_path overwrite in kernel memory.

The `rugpull` command removes filesystem artifacts and advises on kernel memory restoration. It does not undo nftables audit log entries or dmesg messages.

## Files

```
nfttables.h        types, constants, function declarations
arch.h             x86_64/aarch64 page table and gadget constants
offsets.h          offset database types and resolution API
main.c             CLI dispatch
netlink.c          nftables netlink batch construction + namespace setup
detect.c           kernel version detection + exploit selection
wallet.c           privilege state display
offsets.c          offset database (15 distro entries) + resolution pipeline
kaslr.c            KASLR bypass collection (kallsyms, dmesg, modules, sysfs)
vmlinux.c          boot image decompression + ELF section parsing
gadgets.c          x86_64 ROP gadget scanner
spray.c            heap spray primitives (msg, pipe, PTE, skb, key, xattr)
cve_2024_1086.c    verdict double-free + dirty pagetable exploit
cve_2023_32233.c   anonymous set UAF + heap spray + ROP exploit
rugpull.c          post-exploitation cleanup
```
