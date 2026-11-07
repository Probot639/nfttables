#ifndef OBF_H
#define OBF_H

enum obf_id {
    S_TEXT = 0,
    S_STEXT,
    S_MODPROBE_PATH,
    S_CORE_PATTERN,
    S_POWEROFF_CMD,
    S_PREPARE_CRED,
    S_COMMIT_CREDS,
    S_FIND_TASK,
    S_SWITCH_NS,
    S_INIT_NSPROXY,
    S_SWAPGS_RET,

    S_TABLE_1086,
    S_CHAIN_BASE_1086,
    S_CHAIN_TGT_1086,
    S_SET_1086,

    S_TABLE_32233,
    S_CHAIN_32233,
    S_ANONSET_FMT,

    S_NFT_MINT,
    S_NFT_SH,
    S_NFT_TRIGGER,

    S_PROC_KALLSYMS,
    S_PROC_SLABINFO,
    S_PROC_MODPROBE,

    S_MINT_SCRIPT,

    S_NFT_CHAIN_CACHE,
    S_NFT_SET_CACHE,

    S_TOOL_NAME,
    S_COLLECTION,
    S_MOTTO,
    S_CVE_1086,
    S_CVE_32233,
    S_CVE_1086_DESC,
    S_CVE_32233_DESC,

    S_NFT_XATTR_FMT,
    S_NFT_VMLINUX,
    S_NFT_VMLINUX_FMT,
    S_SBIN_MODPROBE,

    S_DIRTY_PT,
    S_HEAP_SPRAY,

    OBF_STR_COUNT_ENUM
};

/* returns decrypted string (valid until obf_fini) */
const char *S(int id);

void obf_init(void);
void obf_fini(void);

#endif
