#include "nfttables.h"

/* ── socket setup ─────────────────────────────────────────────── */

int nft_socket_open(void)
{
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);
    if (fd < 0)
        return -1;

    struct sockaddr_nl sa = {
        .nl_family = AF_NETLINK,
        .nl_pid    = 0,
        .nl_groups = 0,
    };

    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(fd);
        return -1;
    }

    return fd;
}

/* ── batch construction ───────────────────────────────────────── */

void nft_batch_init(struct nft_batch *b, int fd)
{
    memset(b, 0, sizeof(*b));
    b->fd  = fd;
    b->seq = 1;
}

static void *batch_tail(struct nft_batch *b)
{
    return b->buf + b->len;
}


void nft_batch_begin(struct nft_batch *b)
{
    struct nlmsghdr *nlh = batch_tail(b);
    struct nfgenmsg *nfg;

    nlh->nlmsg_len   = NLMSG_HDRLEN + NFGENMSG_LEN;
    nlh->nlmsg_type  = NFNL_MSG_BATCH_BEGIN;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq   = b->seq++;
    nlh->nlmsg_pid   = 0;

    nfg = (struct nfgenmsg *)((uint8_t *)nlh + NLMSG_HDRLEN);
    nfg->nfgen_family = AF_UNSPEC;
    nfg->version      = NFNETLINK_V0;
    nfg->res_id       = htons(NFNL_SUBSYS_NFTABLES);

    b->len += NLMSG_ALIGN(nlh->nlmsg_len);
    b->cur  = NULL;
}

void nft_batch_end(struct nft_batch *b)
{
    struct nlmsghdr *nlh = batch_tail(b);
    struct nfgenmsg *nfg;

    nlh->nlmsg_len   = NLMSG_HDRLEN + NFGENMSG_LEN;
    nlh->nlmsg_type  = NFNL_MSG_BATCH_END;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq   = b->seq++;
    nlh->nlmsg_pid   = 0;

    nfg = (struct nfgenmsg *)((uint8_t *)nlh + NLMSG_HDRLEN);
    nfg->nfgen_family = AF_UNSPEC;
    nfg->version      = NFNETLINK_V0;
    nfg->res_id       = htons(NFNL_SUBSYS_NFTABLES);

    b->len += NLMSG_ALIGN(nlh->nlmsg_len);
    b->cur  = NULL;
}

/* ── message construction ─────────────────────────────────────── */

struct nlmsghdr *nft_msg_alloc(struct nft_batch *b, uint16_t msg_type,
                               uint16_t flags, uint8_t family)
{
    struct nlmsghdr *nlh = batch_tail(b);
    struct nfgenmsg *nfg;

    uint32_t base_len = NLMSG_HDRLEN + NFGENMSG_LEN;

    nlh->nlmsg_len   = base_len;
    nlh->nlmsg_type  = (NFNL_SUBSYS_NFTABLES << 8) | msg_type;
    nlh->nlmsg_flags = NLM_F_REQUEST | flags;
    nlh->nlmsg_seq   = b->seq++;
    nlh->nlmsg_pid   = 0;

    nfg = (struct nfgenmsg *)((uint8_t *)nlh + NLMSG_HDRLEN);
    nfg->nfgen_family = family;
    nfg->version      = NFNETLINK_V0;
    nfg->res_id       = htons(NFNL_SUBSYS_NFTABLES);

    b->len += base_len;
    b->cur  = nlh;
    return nlh;
}

/* ── NLA attribute helpers ────────────────────────────────────── */

static void *msg_tail(struct nft_batch *b)
{
    return b->buf + b->len;
}

static void nla_put_raw(struct nft_batch *b, uint16_t type,
                        const void *data, uint16_t data_len)
{
    struct nlattr *nla = msg_tail(b);
    uint16_t total = NLA_HDRLEN + data_len;

    nla->nla_len  = total;
    nla->nla_type = type;
    if (data && data_len)
        memcpy((uint8_t *)nla + NLA_HDRLEN, data, data_len);

    uint32_t padded = NLA_ALIGN(total);
    /* zero padding bytes */
    if (padded > total)
        memset((uint8_t *)nla + total, 0, padded - total);

    b->len        += padded;
    b->cur->nlmsg_len += padded;
}

void nft_put_str(struct nft_batch *b, uint16_t type, const char *s)
{
    nla_put_raw(b, type, s, strlen(s) + 1);
}

void nft_put_u32(struct nft_batch *b, uint16_t type, uint32_t val)
{
    uint32_t be = htonl(val);
    nla_put_raw(b, type, &be, sizeof(be));
}

void nft_put_u64(struct nft_batch *b, uint16_t type, uint64_t val)
{
    /* nf_tables u64 attributes are in host byte order, NOT network order.
       the kernel uses nla_get_be64 for some and nla_get_u64 for others.
       set ID and similar fields use host order. */
    nla_put_raw(b, type, &val, sizeof(val));
}

void nft_put_data(struct nft_batch *b, uint16_t type,
                  const void *data, uint16_t len)
{
    nla_put_raw(b, type, data, len);
}

void *nft_nest_begin(struct nft_batch *b, uint16_t type)
{
    struct nlattr *nla = msg_tail(b);
    nla->nla_type = type | NLA_F_NESTED;
    nla->nla_len  = NLA_HDRLEN;

    b->len        += NLA_HDRLEN;
    b->cur->nlmsg_len += NLA_HDRLEN;
    return nla;
}

void nft_nest_end(struct nft_batch *b, void *start)
{
    struct nlattr *nla = start;
    nla->nla_len = (uint8_t *)msg_tail(b) - (uint8_t *)nla;
}

/* ── high-level nft object helpers ────────────────────────────── */

void nft_add_table(struct nft_batch *b, const char *name, uint8_t family)
{
    nft_msg_alloc(b, NFT_MSG_NEWTABLE, NLM_F_CREATE | NLM_F_ACK, family);
    nft_put_str(b, NFTA_TABLE_NAME, name);
}

void nft_del_table(struct nft_batch *b, const char *name, uint8_t family)
{
    nft_msg_alloc(b, NFT_MSG_DELTABLE, NLM_F_ACK, family);
    nft_put_str(b, NFTA_TABLE_NAME, name);
}

void nft_add_chain(struct nft_batch *b, const char *table, const char *name,
                   uint8_t family)
{
    nft_msg_alloc(b, NFT_MSG_NEWCHAIN, NLM_F_CREATE | NLM_F_ACK, family);
    nft_put_str(b, NFTA_CHAIN_TABLE, table);
    nft_put_str(b, NFTA_CHAIN_NAME, name);
}

void nft_add_base_chain(struct nft_batch *b, const char *table,
                        const char *name, uint8_t family,
                        uint32_t hooknum, int32_t priority)
{
    nft_msg_alloc(b, NFT_MSG_NEWCHAIN, NLM_F_CREATE | NLM_F_ACK, family);
    nft_put_str(b, NFTA_CHAIN_TABLE, table);
    nft_put_str(b, NFTA_CHAIN_NAME, name);
    nft_put_str(b, NFTA_CHAIN_TYPE, "filter");
    nft_put_u32(b, NFTA_CHAIN_POLICY, NF_ACCEPT);

    void *hook = nft_nest_begin(b, NFTA_CHAIN_HOOK);
    nft_put_u32(b, NFTA_HOOK_HOOKNUM, hooknum);
    nft_put_u32(b, NFTA_HOOK_PRIORITY, (uint32_t)priority);
    nft_nest_end(b, hook);
}

void nft_del_chain(struct nft_batch *b, const char *table, const char *name,
                   uint8_t family)
{
    nft_msg_alloc(b, NFT_MSG_DELCHAIN, NLM_F_ACK, family);
    nft_put_str(b, NFTA_CHAIN_TABLE, table);
    nft_put_str(b, NFTA_CHAIN_NAME, name);
}

void nft_add_set(struct nft_batch *b, const char *table, const char *name,
                 uint8_t family, uint32_t key_type, uint32_t key_len,
                 uint32_t data_type, uint32_t data_len,
                 uint32_t flags, uint32_t set_id)
{
    nft_msg_alloc(b, NFT_MSG_NEWSET, NLM_F_CREATE | NLM_F_ACK, family);
    nft_put_str(b, NFTA_SET_TABLE, table);
    nft_put_str(b, NFTA_SET_NAME, name);
    nft_put_u32(b, NFTA_SET_KEY_TYPE, key_type);
    nft_put_u32(b, NFTA_SET_KEY_LEN, key_len);
    nft_put_u32(b, NFTA_SET_FLAGS, flags);
    nft_put_u32(b, NFTA_SET_ID, set_id);

    if (flags & NFT_SET_MAP) {
        nft_put_u32(b, NFTA_SET_DATA_TYPE, data_type);
        nft_put_u32(b, NFTA_SET_DATA_LEN, data_len);
    }
}

void nft_del_set(struct nft_batch *b, const char *table, const char *name,
                 uint8_t family)
{
    nft_msg_alloc(b, NFT_MSG_DELSET, NLM_F_ACK, family);
    nft_put_str(b, NFTA_SET_TABLE, table);
    nft_put_str(b, NFTA_SET_NAME, name);
}

static void build_elem_verdict(struct nft_batch *b, const void *key,
                               uint32_t key_len, int32_t verdict_code,
                               const char *chain)
{
    void *elems = nft_nest_begin(b, NFTA_SET_ELEM_LIST_ELEMENTS);
    void *elem  = nft_nest_begin(b, NFTA_LIST_ELEM);

    /* key */
    void *k = nft_nest_begin(b, NFTA_SET_ELEM_KEY);
    nft_put_data(b, NFTA_DATA_VALUE, key, key_len);
    nft_nest_end(b, k);

    /* data = verdict */
    void *d = nft_nest_begin(b, NFTA_SET_ELEM_DATA);
    void *v = nft_nest_begin(b, NFTA_DATA_VERDICT);
    nft_put_u32(b, NFTA_VERDICT_CODE, (uint32_t)verdict_code);
    if (chain)
        nft_put_str(b, NFTA_VERDICT_CHAIN, chain);
    nft_nest_end(b, v);
    nft_nest_end(b, d);

    nft_nest_end(b, elem);
    nft_nest_end(b, elems);
}

void nft_add_set_elem_verdict(struct nft_batch *b, const char *table,
                              const char *set, uint8_t family,
                              const void *key, uint32_t key_len,
                              int32_t verdict_code, const char *chain)
{
    nft_msg_alloc(b, NFT_MSG_NEWSETELEM, NLM_F_CREATE | NLM_F_ACK, family);
    nft_put_str(b, NFTA_SET_ELEM_LIST_TABLE, table);
    nft_put_str(b, NFTA_SET_ELEM_LIST_SET, set);

    build_elem_verdict(b, key, key_len, verdict_code, chain);
}

void nft_del_set_elem_verdict(struct nft_batch *b, const char *table,
                              const char *set, uint8_t family,
                              const void *key, uint32_t key_len,
                              int32_t verdict_code, const char *chain)
{
    nft_msg_alloc(b, NFT_MSG_DELSETELEM, NLM_F_ACK, family);
    nft_put_str(b, NFTA_SET_ELEM_LIST_TABLE, table);
    nft_put_str(b, NFTA_SET_ELEM_LIST_SET, set);

    build_elem_verdict(b, key, key_len, verdict_code, chain);
}

void nft_add_rule_immediate_verdict(struct nft_batch *b, const char *table,
                                    const char *chain, uint8_t family,
                                    int32_t verdict_code,
                                    const char *target_chain)
{
    nft_msg_alloc(b, NFT_MSG_NEWRULE, NLM_F_CREATE | NLM_F_ACK, family);
    nft_put_str(b, NFTA_RULE_TABLE, table);
    nft_put_str(b, NFTA_RULE_CHAIN, chain);

    void *exprs = nft_nest_begin(b, NFTA_RULE_EXPRESSIONS);
    void *expr  = nft_nest_begin(b, NFTA_LIST_ELEM);

    nft_put_str(b, NFTA_EXPR_NAME, "immediate");

    void *data = nft_nest_begin(b, NFTA_EXPR_DATA);
    nft_put_u32(b, NFTA_IMMEDIATE_DREG, NFT_REG_VERDICT);

    void *imm = nft_nest_begin(b, NFTA_IMMEDIATE_DATA);
    void *v   = nft_nest_begin(b, NFTA_DATA_VERDICT);
    nft_put_u32(b, NFTA_VERDICT_CODE, (uint32_t)verdict_code);
    if (target_chain)
        nft_put_str(b, NFTA_VERDICT_CHAIN, target_chain);
    nft_nest_end(b, v);
    nft_nest_end(b, imm);

    nft_nest_end(b, data);
    nft_nest_end(b, expr);
    nft_nest_end(b, exprs);
}

/* ── send batch + receive ack ─────────────────────────────────── */

int nft_batch_send(struct nft_batch *b)
{
    struct sockaddr_nl sa = {
        .nl_family = AF_NETLINK,
    };
    struct iovec iov = {
        .iov_base = b->buf,
        .iov_len  = b->len,
    };
    struct msghdr msg = {
        .msg_name    = &sa,
        .msg_namelen = sizeof(sa),
        .msg_iov     = &iov,
        .msg_iovlen  = 1,
    };

    if (sendmsg(b->fd, &msg, 0) < 0)
        return -errno;

    /* receive ack/error */
    uint8_t rbuf[4096];
    struct iovec riov = { .iov_base = rbuf, .iov_len = sizeof(rbuf) };
    struct msghdr rmsg = {
        .msg_iov    = &riov,
        .msg_iovlen = 1,
    };

    for (;;) {
        ssize_t n = recvmsg(b->fd, &rmsg, 0);
        if (n < 0)
            return -errno;

        struct nlmsghdr *nlh;
        for (nlh = (struct nlmsghdr *)rbuf;
             NLMSG_OK(nlh, (unsigned)n);
             nlh = NLMSG_NEXT(nlh, n)) {

            if (nlh->nlmsg_type == NLMSG_DONE)
                return 0;

            if (nlh->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *err = NLMSG_DATA(nlh);
                if (err->error) {
                    pr_verb("netlink error: %s (msg type 0x%x, seq %u)",
                            strerror(-err->error),
                            err->msg.nlmsg_type, err->msg.nlmsg_seq);
                    return err->error;
                }
            }
        }
    }
}

/* ── namespace setup ──────────────────────────────────────────── */

int write_file_str(const char *path, const char *data)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0)
        return -errno;
    ssize_t n = write(fd, data, strlen(data));
    close(fd);
    return n < 0 ? -errno : 0;
}

int ns_setup_user_net(void)
{
    uid_t real_uid = getuid();
    gid_t real_gid = getgid();

    if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
        pr_verb("unshare(CLONE_NEWUSER|CLONE_NEWNET): %s", strerror(errno));
        return -1;
    }

    write_file_str("/proc/self/setgroups", "deny\n");

    char map[64];
    snprintf(map, sizeof(map), "0 %d 1\n", real_uid);
    if (write_file_str("/proc/self/uid_map", map) < 0)
        return -1;

    snprintf(map, sizeof(map), "0 %d 1\n", real_gid);
    if (write_file_str("/proc/self/gid_map", map) < 0)
        return -1;

    return 0;
}

/* ── kallsyms lookup ──────────────────────────────────────────── */

uint64_t kallsyms_lookup(const char *name)
{
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f)
        return 0;

    char line[256];
    uint64_t addr = 0;

    while (fgets(line, sizeof(line), f)) {
        uint64_t a;
        char type;
        char sym[128];
        if (sscanf(line, "%lx %c %127s", &a, &type, sym) == 3) {
            if (strcmp(sym, name) == 0) {
                addr = a;
                break;
            }
        }
    }

    fclose(f);

    /* kptr_restrict=2 returns all zeros */
    if (addr == 0)
        return 0;

    return addr;
}
