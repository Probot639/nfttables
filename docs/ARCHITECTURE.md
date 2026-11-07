# Architecture

## Exploit flow

Both exploits follow the same high-level structure:

```
detect -> resolve offsets -> fork child -> enter namespace -> trigger bug -> exploit -> payload -> signal parent
```

The child process enters a new user+network namespace (for CAP_NET_ADMIN), triggers the nftables vulnerability, and exploits it. The parent waits for a result signal.

### Namespace isolation

The child calls `unshare(CLONE_NEWUSER | CLONE_NEWNET)` to get its own user namespace (mapped uid 0 = real uid) and network namespace. Inside the new net namespace it has full CAP_NET_ADMIN, which is needed to create nftables objects via the NETLINK_NETFILTER socket.

The nftables objects exist only in the child's network namespace and are destroyed when the namespace is torn down. The kernel bug, however, corrupts memory in the global kernel heap, not the namespace-local state. This is why the exploitation (heap spray, PTE manipulation) affects the whole system.

### Netlink protocol

netlink.c implements the nfnetlink batch protocol from scratch. A batch is a sequence of netlink messages sent as a single sendmsg():

```
BATCH_BEGIN (nlmsg_type=0x10, nfgenmsg.res_id=htons(10))
NFT_MSG_NEWTABLE + attributes
NFT_MSG_NEWCHAIN + attributes
...
BATCH_END (nlmsg_type=0x11)
```

The kernel processes the batch atomically. If any operation fails, the whole batch is rolled back. The tool checks the response for NLMSG_ERROR to detect patched kernels that reject the trigger operations.

## Offset resolution

offsets.c implements a multi-strategy pipeline:

1. **kallsyms** -- parse /proc/kallsyms for symbol addresses (modprobe_path, prepare_kernel_cred, commit_creds, etc.)
2. **database** -- match uname -r against known distro kernel patterns, apply struct offsets and slab sizes
3. **slab profiling** -- read /proc/slabinfo for nft_chain and nft_set cache parameters
4. **vmlinux extraction** -- decompress /boot/vmlinuz-*, parse ELF sections
5. **gadget scanning** -- scan .text for ROP gadget byte sequences

Each strategy fills gaps left by the previous ones. The resolved offset struct is passed to the exploit code.

## Spray library

spray.c provides heap manipulation primitives that the exploits compose:

- **msg_spray**: allocate slab objects via System V message queues. Each msgsnd() allocates a kernel buffer of the message size. Controllable content, persistent until msgrcv().
- **pipe_spray**: allocate page-sized buffers via pipe(). Each write of PAGE_SIZE forces a page allocation for the pipe buffer.
- **pte_spray**: force PTE page allocation by mapping and faulting in large anonymous memory regions. Each 2MB of virtual memory needs a PTE page (512 entries, 4KB).
- **cross_cache_drain**: free enough objects from a slab cache to return the underlying page to the buddy allocator, enabling cross-cache reclaim.

## CVE-2024-1086 specifics

The double-free is on an nft_chain object. The exploitation converts this into arbitrary physical memory access:

1. Double-free the chain (slab object freed twice)
2. Cross-cache: drain the slab so the page returns to buddy allocator
3. PTE spray: reclaim the page as a PTE page AND a pipe buffer page
4. The pipe buffer gives read/write access to PTE entries
5. Forge PTEs to map the physical page containing modprobe_path
6. Overwrite modprobe_path to point at our script
7. Trigger modprobe (execute a binary with unknown magic bytes)
8. Our script creates a SUID root shell

## CVE-2023-32233 specifics

The UAF is on an nft_set object. The exploitation redirects kernel execution:

1. Trigger UAF by creating + binding + deleting an anonymous set in one batch
2. Heap spray with msgsnd() to reclaim the freed nft_set with controlled data
3. The controlled data overwrites nft_set_ops function pointers
4. When the kernel accesses the corrupted set (during table cleanup), it calls through our pointers
5. Stack pivot via xchg rax, rsp gadget
6. ROP chain: prepare_kernel_cred(NULL) -> commit_creds(result)
7. Return to userspace via swapgs+iretq trampoline
8. Current process now has uid=0 credentials
9. Post-root: ptrace injection writes modprobe script and modprobe_path (attributed to victim PID)

## String encryption (obf.c, tools/gen_obf.py)

Build-time encryption. gen_obf.py generates _obf_data.h containing:
- A random 32-byte XOR key
- An index table mapping string ID -> (offset, length) in the encrypted blob
- The encrypted blob (all strings concatenated, each null-terminated, then XOR'd with the key at the string's absolute offset)

At runtime, obf_init() allocates a buffer, decrypts all strings in one pass, and stores pointers indexed by enum ID. S(id) returns the decrypted pointer. obf_fini() frees and zeros the buffer.

The key rotation uses the absolute offset of each byte in the packed stream, not the offset within individual strings. This means the same character at different positions encrypts differently.

## Process injection (stealth.c)

x86_64 ptrace-based syscall injection. Used post-root to attribute filesystem operations to a victim process.

The injection mechanism:
1. stealth_find_victim() walks /proc looking for root-owned long-lived daemons
2. PTRACE_ATTACH stops the victim. Save all registers with PTRACE_GETREGS
3. Read the original code at RIP. Write `syscall; int3` (0x0f 0x05 0xcc) at RIP via PTRACE_POKETEXT
4. push_string() writes arbitrary data below RSP via PTRACE_POKETEXT (8 bytes at a time)
5. inject_syscall() sets up registers (rax=syscall nr, rdi/rsi/rdx/r10 = args), PTRACE_CONT
6. Wait for SIGTRAP from the int3 after syscall. Read return value from RAX
7. Chain open->write->close for file operations
8. Restore original code and registers, PTRACE_DETACH

The victim process doesn't know anything happened. Its registers and code are restored exactly. The only side effect is the file operation the kernel attributed to its PID.
