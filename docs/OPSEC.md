# OPSEC considerations

What the tool touches, what it leaves behind, and what watches.

## Filesystem artifacts

| Path | Created by | Lifetime |
|---|---|---|
| `/tmp/.nft_mint` | modprobe_path payload script | until rugpull |
| `/tmp/.nft_sh` | SUID root shell (CVE-2024-1086) | until rugpull |
| `/tmp/.nft_trigger` | binary with bad magic (triggers modprobe) | until rugpull |

`rugpull` removes all three. If the process crashes mid-exploit, they persist.

The binary itself (wherever you drop it) is the largest artifact. Strip it (`make release`) and delete after use.

## Kernel memory

CVE-2024-1086 overwrites `modprobe_path` in kernel memory. The default value is `/sbin/modprobe`. After exploitation:

```bash
# Check current value (needs root after escalation):
cat /proc/sys/kernel/modprobe
# Should show /tmp/.nft_mint instead of /sbin/modprobe

# Restore:
echo -n '/sbin/modprobe' > /proc/sys/kernel/modprobe
```

`rugpull` prints this reminder but cannot restore it without root. If you already have root from the exploit, restore it before dropping privileges.

CVE-2023-32233 corrupts heap objects but the corruption is consumed during exploitation. No persistent kernel memory modification after the ROP chain completes.

## Audit trail

### nftables audit events

The kernel logs nftables operations to the audit subsystem. Creating tables, chains, sets, and rules all generate audit records:

```
type=NETFILTER_CFG msg=audit(...): table=BoredApe family=1 ...
type=NETFILTER_CFG msg=audit(...): table=LazyMint family=2 ...
```

The table names ("BoredApe", "LazyMint") appear in audit logs. These are distinctive. On a system with auditd running, they're written to /var/log/audit/audit.log.

### dmesg / kernel log

Depending on kernel config, you may see:
- nf_tables messages about table creation/deletion
- KASAN/KFENCE reports if the kernel has memory debugging enabled (unlikely in production, but common in test environments)
- Page fault traces if exploitation fails and the kernel doesn't crash cleanly

### Process artifacts

- `unshare()` syscall is logged by seccomp/audit if configured
- Burst of `msgsnd()` calls (heap spray) is unusual
- Burst of `pipe()` calls (pipe spray) is unusual
- Burst of `mmap()` calls with MAP_POPULATE (PTE spray) is unusual
- Child process with different network namespace

### Network

Both exploits operate entirely through netlink sockets (AF_NETLINK, NETLINK_NETFILTER). No network traffic leaves the box. The nftables operations happen inside the child's network namespace and don't affect the host's packet filtering.

## Detection signatures

What a defender would look for:

1. **Static**: strings in the binary ("BoredApe", "LazyMint", "diamond_hands", "hodl", "rugged", "vmap", NFT emoji). Strip helps but strings analysis on the binary before stripping reveals these.

2. **Behavioral**: the syscall pattern is distinctive. Within a few seconds: clone(CLONE_NEWUSER|CLONE_NEWNET) -> socket(AF_NETLINK) -> sendmsg (nftables batch) -> msgsnd burst -> pipe burst -> mmap burst -> write to /tmp. An eBPF program on clone+sendmsg could flag this.

3. **Audit**: nftables table names in audit log. A rule watching for table creation by unprivileged users (user namespaces) would catch this.

4. **Filesystem**: /tmp/.nft_* files. inotify watch on /tmp for dotfiles with "nft" prefix.

5. **Memory**: modprobe_path changed from default. Periodic check via /proc/sys/kernel/modprobe.

## Reducing footprint

Some options if OPSEC matters:

- Rename table/chain/set names to something bland before deployment (edit the string constants in the exploit files)
- Change /tmp paths to something less patterned
- Add delays between spray phases to spread the syscall burst
- Clean up immediately after exploitation (call rugpull logic inline)
- Pipe the binary in via stdin or memfd_create rather than writing to disk
- Restore modprobe_path immediately after getting root

The tool as shipped prioritizes reliability and debuggability over stealth. It's built for testing, not for quiet deployment.
