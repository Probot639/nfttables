# Usage

How to build, run, and test NFTtables.

## Build

```
make              # dynamic build, good for development
make release      # adds -DRELEASE (strips verbose logging) + strip -s
make install      # release build copied to /bin/nfttables
```

`make release` needs musl-gcc for a static build. If you don't have it, build with `make` and strip manually:

```
make && cp nfttables nfttables-release && strip -s nfttables-release
```

The string encryption key regenerates every build. Two builds of the same source produce different encrypted constants.

## Recon

Start with recon. This tells you what the tool can see on the target.

```
./nfttables info
```

Shows kernel version, distro, uid, namespace support, and whether the kernel falls in either CVE's affected range. If both CVEs say "not affected," you're on a patched kernel and neither exploit will work.

```
./nfttables scan -v
```

Runs the full offset resolution pipeline: /proc/kallsyms, the hardcoded offset database, vmlinux extraction from /boot, KASLR bypass attempts, ROP gadget scanning. The output shows exactly which symbols and gadgets resolved and which didn't. This is the step that determines whether the exploit can actually run.

If kallsyms is locked down (kptr_restrict=2, no root), offsets come from the hardcoded database or vmlinux extraction. If neither works, you're stuck unless you add the target kernel to the offset database manually (see docs/ADDING-KERNELS.md).

```
./nfttables collections
```

Lists the two exploits with their version ranges, technique names, and reliability.

## Exploitation

```
./nfttables check auto
```

Dry run. Probes for the vulnerability without triggering the exploit. For CVE-2023-32233 this is reliable: the batch either succeeds (vulnerable) or fails with EBUSY (patched). For CVE-2024-1086, the check exercises everything up to the actual double-free trigger.

```
./nfttables mint auto
```

Full send. Auto-selects the best exploit for the running kernel and attempts privilege escalation. On success, drops a SUID shell at the path shown in the output.

You can also target a specific exploit:

```
./nfttables mint 1086      # CVE-2024-1086 only
./nfttables mint 32233     # CVE-2023-32233 only
```

Add `-v` for verbose output (offset resolution details, spray counts, injection steps).

## Cleanup

```
./nfttables rugpull
```

Removes artifacts the exploit left behind: temp files, SUID shell, IPC message queues. Prints a reminder about the modprobe_path kernel memory change, which can't be reverted from userspace without a reboot.

## Test lab

The `test/` directory has a Docker Compose setup with three containers for testing. All containers run privileged with host PID namespace access.

```
cd test
docker compose build
```

Then open three terminals:

**Red team** (non-root user, just the binary):
```
docker compose run --rm red
```
Drops you into `~/` with `nfttables` and `nfttables-release`. Run the exploit from here.

**Blue team** (monitoring station):
```
docker compose run --rm blue
```
Starts all six detection monitors in the background. Detections write to `/reports/`. Run `score.sh` to see detection coverage.

**Root observer** (full access):
```
docker compose run --rm root
```
Root shell with both binaries, all blue team scripts, and forensics tools (strace, ltrace, gdb, strings, readelf, nft, auditctl). Good for post-exploitation analysis and poking at kernel state.

The blue team monitors watch for: namespace creation, netlink sockets, nftables object creation, heap spray (pipe/mmap/ipc), filesystem artifacts, modprobe_path changes, privilege escalation via audit, binary string analysis, and ptrace injection.

The containers share a `/reports` volume. Blue team writes detections there, any container can read them.

Note: the host kernel is shared across all containers. If it's patched (which it probably is), the exploit won't reach the post-root phases. The test lab is for exercising the tool's detection surface, not for actually popping root.

## Adversarial testing

The `adversarial/` directory has its own Docker setup for automated red-vs-blue scoring:

```
cd adversarial
docker compose run --rm -e ITERATION=5 -e BLUE_TEAM_MODE=full adversarial-lab
```

This runs the full pipeline: starts all blue team monitors, executes the red team payload, collects trailing events, stops monitors, and scores detection coverage against 13 ground-truth observables. See adversarial/reports/ADVERSARIAL-REPORT.md for results across iterations.
