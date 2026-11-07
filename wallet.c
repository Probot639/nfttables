#include "nfttables.h"

void wallet_read(struct wallet *w)
{
    w->uid  = getuid();
    w->euid = geteuid();
    w->gid  = getgid();
    w->egid = getegid();
    w->ngroups = getgroups(64, w->groups);
    if (w->ngroups < 0)
        w->ngroups = 0;
    gethostname(w->hostname, sizeof(w->hostname));
}

void wallet_print(const struct wallet *w, const struct kernel_info *ki)
{
    const char *gas;
    /* rough OPSEC assessment based on environment */
    if (access("/sys/kernel/security/apparmor/profiles", F_OK) == 0 ||
        access("/sys/fs/selinux/enforce", F_OK) == 0)
        gas = C_RED "high (MAC detected)" C_RST;
    else
        gas = C_GRN "low" C_RST;

    fprintf(stderr,
        FOX " " C_BOLD "MetaMask" C_RST " v0.0.1 " C_DIM "(not financial advice)" C_RST "\n"
        "\n"
        "  Chain:     " C_CYN "Linux %s" C_RST "\n"
        "  Network:   %s%s" C_RST "\n"
        "  Address:   uid=%d(%s) gid=%d\n"
        "  Balance:   %s\n"
        "  Gas price: %s\n"
        "  Userns:    %s\n"
        "\n",
        ki->release,
        ki->distro[0] ? ki->distro : "unknown", ki->distro[0] ? "" : "",
        w->uid,
        w->uid == 0 ? "root" : "user",
        w->gid,
        w->euid == 0
            ? C_GRN "1 ROOT token " APE C_RST
            : C_YEL "0 ROOT tokens" C_RST,
        gas,
        ki->userns_available
            ? C_GRN "available" C_RST
            : C_RED "unavailable" C_RST
    );
}
