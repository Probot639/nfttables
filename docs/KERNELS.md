# Kernel Compatibility

## CVE version ranges

**CVE-2024-1086** (nft_verdict_init double-free)
- Introduced: 3.15
- Fixed: 6.7.2, 6.6.14, 6.1.75
- Technique: dirty pagetable (works best on 5.14+, where the anonymous VMA handling gives stable page table control)
- Reliability: high on kernels with known offsets, medium on cold targets

**CVE-2023-32233** (anonymous set use-after-free)
- Introduced: 3.18
- Fixed: 6.3.2, 6.2.16, 6.1.31
- Technique: heap spray + ROP (credential overwrite via slab corruption)
- Reliability: medium (heap layout dependent, spray may need tuning)

Both exploits require unprivileged user namespaces. On most distros this is a sysctl:

```
# check
cat /proc/sys/kernel/unprivileged_userns_clone
# or
sysctl kernel.unprivileged_userns_clone

# enable (needs root)
sysctl -w kernel.unprivileged_userns_clone=1
```

Some distros (Ubuntu 23.10+, Debian 12+) use AppArmor restrictions on unprivileged namespaces instead of the sysctl. Check with `aa-status` and look for `unprivileged_userns` profiles.

## Offset database

The hardcoded offset database covers struct sizes and slab cache geometry for these kernels. Symbol addresses (modprobe_path, prepare_kernel_cred, etc.) resolve at runtime via /proc/kallsyms or vmlinux extraction.

| Kernel pattern | Distro | CVE-2024-1086 | CVE-2023-32233 |
|---|---|---|---|
| `5.15.0-*-generic` | Ubuntu 22.04 | yes | no (patched in 6.1.75 LTS, but 5.15 is below the fix line for 32233 too... it was fixed in 6.1.31, so 5.15 is affected) |
| `5.19.0-*-generic` | Ubuntu 22.04 HWE | yes | yes |
| `6.2.0-*-generic` | Ubuntu 22.04 HWE / 23.04 | yes | yes |
| `6.5.0-*-generic` | Ubuntu 22.04 HWE / 23.10 | yes | no (fixed in 6.3.2) |
| `6.8.0-*-generic` | Ubuntu 24.04 | no (fixed in 6.7.2) | no |
| `5.10.0-*-amd64` | Debian 11 | yes | yes |
| `6.1.0-*-amd64` | Debian 12 | yes | depends on subversion |
| `6.2.*-*-fc38.*` | Fedora 38 | yes | yes |
| `6.5.*-*-fc39.*` | Fedora 39 | yes | no |
| `6.6.*-*-fc39.*` | Fedora 39 | yes | no |
| `4.18.0-*.el8*` | RHEL 8 / CentOS 8 | yes | yes |
| `5.14.0-*.el9*` | RHEL 9 / Rocky 9 / Alma 9 | yes | yes |
| `5.10.*-*-amzn2.*` | Amazon Linux 2 | yes | yes |
| `5.15.*-*-amzn2.*` | Amazon Linux 2 | yes | yes |
| `6.*-*-cachyos*` | CachyOS | depends on version | depends on version |
| `6.*-arch*` | Arch Linux | depends on version | depends on version |

Rolling-release distros (Arch, CachyOS) patch fast. Check the actual running kernel version against the fix versions listed above.

RHEL/CentOS/Amazon Linux backport security fixes without changing the major.minor version number. A kernel reporting `5.14.0-362.el9` might have the CVE fix even though 5.14 is nominally in the affected range. The offset database still helps with struct sizes on these kernels, but `nfttables check auto` is the only reliable way to confirm vulnerability.

## What "in the offset database" means

The database stores struct layout information: `task_struct` to `cred` offset, `cred` to `uid` offset, and `nft_chain`/`nft_set` slab object sizes. These change between kernel versions as struct members are added or reordered.

Symbol addresses (kernel function pointers, global variable locations) are NOT in the database. They resolve at runtime through:

1. `/proc/kallsyms` (fastest, needs `kptr_restrict` < 2)
2. vmlinux extraction from `/boot` (slower, works without kallsyms)
3. The hardcoded database (struct offsets only)

If a kernel matches the database but kallsyms is locked down and /boot has no vmlinux, the exploit can still work for CVE-2024-1086 (dirty pagetable doesn't need all gadgets) but will likely fail for CVE-2023-32233 (needs the full ROP chain).

## Adding a new kernel

Run `nfttables scan -v` on the target to dump all resolved offsets, then add an entry to the database. See docs/ADDING-KERNELS.md for the full procedure.

## Quick check

```
./nfttables info          # shows version ranges and whether target is affected
./nfttables check auto    # probes for actual vulnerability (non-destructive)
./nfttables scan -v       # full offset resolution dump
```
