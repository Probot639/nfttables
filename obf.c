#include <stdlib.h>
#include <string.h>
#include "obf.h"

#include "_obf_data.h"

static char *_dec_buf;
static const char **_dec_ptrs;
static int _inited;

void obf_init(void)
{
    if (_inited) return;

    size_t total = 0;
    for (int i = 0; i < OBF_STR_COUNT; i++)
        total += _obf_idx[i].len;

    _dec_buf = malloc(total);
    _dec_ptrs = malloc(sizeof(char *) * OBF_STR_COUNT);
    if (!_dec_buf || !_dec_ptrs) {
        /* fall through, S() will return empty string */
        _inited = 1;
        return;
    }

    char *p = _dec_buf;
    for (int i = 0; i < OBF_STR_COUNT; i++) {
        unsigned int off = _obf_idx[i].off;
        unsigned int len = _obf_idx[i].len;
        _dec_ptrs[i] = p;
        for (unsigned int j = 0; j < len; j++)
            p[j] = _obf_data[off + j] ^ _obf_key[(off + j) % OBF_KEY_LEN];
        p += len;
    }
    _inited = 1;
}

const char *S(int id)
{
    if (!_inited) obf_init();
    if (id < 0 || id >= OBF_STR_COUNT || !_dec_ptrs)
        return "";
    return _dec_ptrs[id];
}

void obf_fini(void)
{
    free(_dec_buf);
    free(_dec_ptrs);
    _dec_buf = NULL;
    _dec_ptrs = NULL;
    _inited = 0;
}
