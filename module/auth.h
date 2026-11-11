/* SPDX-License-Identifier: GPL-2.0-or-later */
/* SipHash-2-4 and key derivation adapted from UROV-X. */
#ifndef UROV_Z_AUTH_H
#define UROV_Z_AUTH_H
#include <stdint.h>
#ifndef UINT64_C
#define UINT64_C(value) value##ULL
#endif
static inline uint64_t uz_rotl(uint64_t v, unsigned n)
{
    return (v << n) | (v >> (64U - n));
}

static inline uint64_t uz_load64(const uint8_t *p)
{
    uint64_t v = 0;
    unsigned i;
    for (i = 0; i < 8; ++i) v |= (uint64_t)p[i] << (i * 8U);
    return v;
}

#define UZ_AUTH_SIPROUND                                                   \
    do {                                                                  \
        v0 += v1; v1 = uz_rotl(v1, 13); v1 ^= v0;                     \
        v0 = uz_rotl(v0, 32);                                         \
        v2 += v3; v3 = uz_rotl(v3, 16); v3 ^= v2;                     \
        v0 += v3; v3 = uz_rotl(v3, 21); v3 ^= v0;                     \
        v2 += v1; v1 = uz_rotl(v1, 17); v1 ^= v2;                     \
        v2 = uz_rotl(v2, 32);                                         \
    } while (0)

static inline uint64_t uz_siphash(const uint64_t k[2], const uint8_t *in,
                                      unsigned len)
{
    uint64_t v0 = UINT64_C(0x736f6d6570736575) ^ k[0];
    uint64_t v1 = UINT64_C(0x646f72616e646f6d) ^ k[1];
    uint64_t v2 = UINT64_C(0x6c7967656e657261) ^ k[0];
    uint64_t v3 = UINT64_C(0x7465646279746573) ^ k[1];
    uint64_t m;
    unsigned i = 0, j;

    while (len - i >= 8U) {
        m = uz_load64(in + i);
        v3 ^= m;
        UZ_AUTH_SIPROUND;
        UZ_AUTH_SIPROUND;
        v0 ^= m;
        i += 8U;
    }
    m = (uint64_t)len << 56;
    for (j = 0; i + j < len; ++j) m |= (uint64_t)in[i + j] << (j * 8U);
    v3 ^= m;
    UZ_AUTH_SIPROUND;
    UZ_AUTH_SIPROUND;
    v0 ^= m;
    v2 ^= 0xffU;
    UZ_AUTH_SIPROUND;
    UZ_AUTH_SIPROUND;
    UZ_AUTH_SIPROUND;
    UZ_AUTH_SIPROUND;
    return v0 ^ v1 ^ v2 ^ v3;
}

/* One derived value per label: the label is never secret, the key is. */
static inline uint64_t uz_kdf(const uint64_t k[2], uint8_t tag)
{
    uint8_t label[8] = { (uint8_t)'U', (uint8_t)'R', (uint8_t)'O', (uint8_t)'V',
                         (uint8_t)'Z', (uint8_t)'/', (uint8_t)'1', 0 };
    label[7] = tag;
    return uz_siphash(k, label, 8);
}

struct uz_keys {
    uint64_t option;  /* low 32 bits are the prctl option word */
    uint64_t magic;   /* reserved derivation; ABI v1 uses fixed PRCTL_MAGIC */
    uint64_t mac[2];  /* SipHash key for request MACs */
};

static inline void uz_derive(const uint8_t key[16], struct uz_keys *out)
{
    uint64_t k[2];
    k[0] = uz_load64(key);
    k[1] = uz_load64(key + 8);
    out->option = uz_kdf(k, 1U) & UINT64_C(0xffffffff);
    out->magic = uz_kdf(k, 2U);
    out->mac[0] = uz_kdf(k, 3U);
    out->mac[1] = uz_kdf(k, 4U);
}

/* Strict 32-hex-digit parse. Returns 0 on success, -1 otherwise. */
static inline int uz_parse_key(const char *text, unsigned len, uint8_t out[16])
{
    unsigned i;
    if (!text || len != 32U) return -1;
    for (i = 0; i < 32U; ++i) {
        unsigned c = (unsigned char)text[i];
        unsigned nibble;
        if (c >= (unsigned)'0' && c <= (unsigned)'9') nibble = c - (unsigned)'0';
        else if (c >= (unsigned)'a' && c <= (unsigned)'f') nibble = c - (unsigned)'a' + 10U;
        else if (c >= (unsigned)'A' && c <= (unsigned)'F') nibble = c - (unsigned)'A' + 10U;
        else return -1;
        if ((i & 1U) == 0U) out[i >> 1] = (uint8_t)(nibble << 4);
        else out[i >> 1] |= (uint8_t)nibble;
    }
    return 0;
}

#endif
