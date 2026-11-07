#ifndef KXOR_H
#define KXOR_H

/*
 * Kernel-space XOR string decryption.
 * Strings live encrypted in the module's .rodata until kxor_init()
 * decrypts them into a kmalloc'd buffer. kxor_fini() zeros and frees.
 *
 * Usage:
 *   kxor_init();            // in module_init
 *   pr_info("%s\n", KS(KS_SOME_ID));
 *   kxor_fini();            // in module_exit
 *
 * The actual encrypted data comes from gen_kxor.py -> _kxor_data.h
 */

#include <linux/slab.h>
#include <linux/string.h>

#include "_kxor_data.h"

static char *_kxor_dec_buf;
static char **_kxor_ptrs;

static int kxor_init(void)
{
    unsigned int total = 0;
    int i;

    for (i = 0; i < KXOR_STR_COUNT; i++)
        total += _kxor_idx[i].len;

    _kxor_dec_buf = kmalloc(total, GFP_KERNEL);
    if (!_kxor_dec_buf)
        return -ENOMEM;

    _kxor_ptrs = kmalloc(sizeof(char *) * KXOR_STR_COUNT, GFP_KERNEL);
    if (!_kxor_ptrs) {
        kfree(_kxor_dec_buf);
        return -ENOMEM;
    }

    for (i = 0; i < KXOR_STR_COUNT; i++) {
        unsigned int off = _kxor_idx[i].off;
        unsigned int len = _kxor_idx[i].len;
        unsigned int j;

        _kxor_ptrs[i] = _kxor_dec_buf + off;
        for (j = 0; j < len; j++)
            _kxor_dec_buf[off + j] = _kxor_data[off + j] ^
                _kxor_key[(off + j) % KXOR_KEY_LEN];
    }

    return 0;
}

static void kxor_fini(void)
{
    if (_kxor_dec_buf) {
        unsigned int total = 0;
        int i;
        for (i = 0; i < KXOR_STR_COUNT; i++)
            total += _kxor_idx[i].len;
        memset(_kxor_dec_buf, 0, total);
        kfree(_kxor_dec_buf);
        _kxor_dec_buf = NULL;
    }
    kfree(_kxor_ptrs);
    _kxor_ptrs = NULL;
}

static inline const char *KS(int id)
{
    if (!_kxor_ptrs || id < 0 || id >= KXOR_STR_COUNT)
        return "";
    return _kxor_ptrs[id];
}

#endif /* KXOR_H */
