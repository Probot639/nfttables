#include "nfttables.h"
#include "arch.h"
#include "offsets.h"
#include <elf.h>

/*
 * Extract an uncompressed vmlinux ELF from a compressed boot image.
 *
 * Linux boot images (/boot/vmlinuz-*) contain a compressed kernel
 * payload preceded by a decompression stub. We locate the compressed
 * stream by scanning for magic bytes, then decompress using the
 * system's tools (gzip, xz, lz4, zstd, etc.).
 */

struct compressor {
    const char     *name;
    const uint8_t  *magic;
    int             magic_len;
    const char     *decompress_cmd;
};

static const uint8_t magic_gzip[]  = {0x1f, 0x8b, 0x08};
static const uint8_t magic_xz[]    = {0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00};
static const uint8_t magic_bz2[]   = {0x42, 0x5a, 0x68};
static const uint8_t magic_lzma[]  = {0x5d, 0x00, 0x00};
static const uint8_t magic_lz4[]   = {0x02, 0x21, 0x4c, 0x18};
static const uint8_t magic_zstd[]  = {0x28, 0xb5, 0x2f, 0xfd};
static const uint8_t magic_lzo[]   = {0x89, 0x4c, 0x5a, 0x4f};

static const struct compressor compressors[] = {
    {"gzip",  magic_gzip,  3, "gzip -dc"},
    {"xz",    magic_xz,    6, "xz -dc"},
    {"bzip2", magic_bz2,   3, "bzip2 -dc"},
    {"lzma",  magic_lzma,  3, "lzma -dc"},
    {"lz4",   magic_lz4,   4, "lz4 -dc"},
    {"zstd",  magic_zstd,  4, "zstd -dc"},
    {"lzo",   magic_lzo,   4, "lzop -dc"},
    {NULL, NULL, 0, NULL},
};

/* scan for compressed stream in the boot image */
static int find_compressed(const uint8_t *data, size_t len,
                           const struct compressor **out_comp,
                           size_t *out_offset)
{
    for (size_t i = 0; i < len - 16; i++) {
        for (const struct compressor *c = compressors; c->name; c++) {
            if (i + c->magic_len > len)
                continue;
            if (memcmp(data + i, c->magic, c->magic_len) == 0) {
                *out_comp   = c;
                *out_offset = i;
                pr_verb("found %s stream at offset 0x%zx", c->name, i);
                return 0;
            }
        }
    }
    return -1;
}

/* check if a buffer starts with an ELF header */
static bool is_elf(const uint8_t *data, size_t len)
{
    if (len < sizeof(Elf64_Ehdr))
        return false;
    return memcmp(data, ELFMAG, SELFMAG) == 0;
}

int vmlinux_extract(const char *vmlinuz_path, const char *outpath)
{
    int ret = -1;

    /* read the entire boot image */
    FILE *f = fopen(vmlinuz_path, "rb");
    if (!f) {
        pr_verb("can't open %s: %s", vmlinuz_path, strerror(errno));
        return -1;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fsize <= 0 || fsize > 256 * 1024 * 1024) {
        pr_verb("boot image size suspicious: %ld", fsize);
        fclose(f);
        return -1;
    }

    uint8_t *data = malloc(fsize);
    if (!data) { fclose(f); return -1; }
    if (fread(data, 1, fsize, f) != (size_t)fsize) {
        free(data); fclose(f); return -1;
    }
    fclose(f);

    /* already uncompressed ELF? (some distros ship vmlinux directly) */
    if (is_elf(data, fsize)) {
        pr_verb("boot image is already an ELF");
        FILE *out = fopen(outpath, "wb");
        if (out) {
            fwrite(data, 1, fsize, out);
            fclose(out);
            ret = 0;
        }
        free(data);
        return ret;
    }

    /* scan for compressed payload */
    const struct compressor *comp = NULL;
    size_t offset = 0;

    if (find_compressed(data, fsize, &comp, &offset) < 0) {
        pr_verb("no known compression magic found in boot image");
        free(data);
        return -1;
    }

    /* write the compressed tail to a temp file */
    char tmpcomp[256];
    snprintf(tmpcomp, sizeof(tmpcomp), "%s.compressed", outpath);

    FILE *tc = fopen(tmpcomp, "wb");
    if (!tc) { free(data); return -1; }
    fwrite(data + offset, 1, fsize - offset, tc);
    fclose(tc);
    free(data);

    /* decompress */
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "%s '%s' > '%s' 2>/dev/null",
             comp->decompress_cmd, tmpcomp, outpath);

    pr_verb("extracting: %s", cmd);
    int status = system(cmd);
    unlink(tmpcomp);

    if (status != 0) {
        pr_verb("decompression failed (status %d)", status);
        unlink(outpath);
        return -1;
    }

    /* verify the output is an ELF */
    f = fopen(outpath, "rb");
    if (!f) return -1;
    uint8_t hdr[64];
    size_t n = fread(hdr, 1, sizeof(hdr), f);
    fclose(f);

    if (!is_elf(hdr, n)) {
        /* the first compressed stream might be a nested archive or
           the setup code. try to find the ELF inside the decompressed
           data. */
        pr_verb("decompressed output is not ELF, scanning for nested ELF");

        f = fopen(outpath, "rb");
        if (!f) return -1;
        fseek(f, 0, SEEK_END);
        long dsz = ftell(f);
        fseek(f, 0, SEEK_SET);
        uint8_t *ddata = malloc(dsz);
        if (!ddata) { fclose(f); return -1; }
        fread(ddata, 1, dsz, f);
        fclose(f);

        /* scan for ELF magic */
        bool found = false;
        for (long i = 0; i < dsz - 4; i++) {
            if (memcmp(ddata + i, ELFMAG, SELFMAG) == 0) {
                pr_verb("found ELF at offset 0x%lx in decompressed data", i);
                FILE *out = fopen(outpath, "wb");
                if (out) {
                    fwrite(ddata + i, 1, dsz - i, out);
                    fclose(out);
                    found = true;
                }
                break;
            }
        }

        free(ddata);
        if (!found) {
            unlink(outpath);
            return -1;
        }
    }

    /* final size check */
    struct stat st;
    if (stat(outpath, &st) == 0) {
        pr_verb("extracted vmlinux: %s (%ld bytes)", outpath, st.st_size);
    }

    return 0;
}

int vmlinux_find_boot_image(char *path, size_t pathsz)
{
    struct utsname u;
    if (uname(&u) < 0)
        return -1;

    /* try common locations */
    const char *templates[] = {
        "/boot/vmlinuz-%s",
        "/boot/vmlinux-%s",
        "/boot/vmlinuz",
        "/lib/modules/%s/vmlinuz",
        "/lib/modules/%s/vmlinux",
        NULL,
    };

    for (const char **t = templates; *t; t++) {
        snprintf(path, pathsz, *t, u.release);
        if (access(path, R_OK) == 0) {
            pr_verb("found boot image: %s", path);
            return 0;
        }
    }

    return -1;
}

/* ── ELF section helpers for gadget scanner ───────────────────── */

int vmlinux_find_text_section(const char *path,
                              uint64_t *vaddr, uint64_t *offset,
                              uint64_t *size)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    Elf64_Ehdr ehdr;
    if (fread(&ehdr, 1, sizeof(ehdr), f) != sizeof(ehdr)) {
        fclose(f); return -1;
    }

    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 ||
        ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
        fclose(f); return -1;
    }

    /* read section headers */
    Elf64_Shdr *shdrs = calloc(ehdr.e_shnum, sizeof(Elf64_Shdr));
    if (!shdrs) { fclose(f); return -1; }

    fseek(f, ehdr.e_shoff, SEEK_SET);
    if (fread(shdrs, sizeof(Elf64_Shdr), ehdr.e_shnum, f) != ehdr.e_shnum) {
        free(shdrs); fclose(f); return -1;
    }

    /* read section name string table */
    if (ehdr.e_shstrndx >= ehdr.e_shnum) {
        free(shdrs); fclose(f); return -1;
    }
    Elf64_Shdr *strtab_sh = &shdrs[ehdr.e_shstrndx];
    char *strtab = malloc(strtab_sh->sh_size);
    if (!strtab) { free(shdrs); fclose(f); return -1; }
    fseek(f, strtab_sh->sh_offset, SEEK_SET);
    fread(strtab, 1, strtab_sh->sh_size, f);

    int ret = -1;
    for (int i = 0; i < ehdr.e_shnum; i++) {
        const char *name = strtab + shdrs[i].sh_name;
        if (strcmp(name, ".text") == 0) {
            *vaddr  = shdrs[i].sh_addr;
            *offset = shdrs[i].sh_offset;
            *size   = shdrs[i].sh_size;
            ret = 0;
            break;
        }
    }

    free(strtab);
    free(shdrs);
    fclose(f);
    return ret;
}
