/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * UROV-X: covert, read-site-bound variant of the ARM64 user read overlay.
 *
 * The wire ABI is deliberately NOT the urov-lab ABI:
 *   - the prctl option word and the magic word are derived from a per-load
 *     secret, so no constant in this source identifies the channel;
 *   - every request carries a SipHash-2-4 MAC over its own bytes, so a caller
 *     without the secret cannot make the module react at all;
 *   - an unauthenticated call falls through to the native syscall, i.e. it
 *     returns exactly what the kernel returns when no module is loaded;
 *   - responses only describe the caller's own mm and carry no global caps,
 *     no session attribution and no "another mm has a session" hint.
 *
 * The overlay itself is bound to explicit reader PCs ("sites").  Only the
 * instruction at a registered PC observes the fake bytes; every other EL0
 * data load of the protected page is emulated from the pinned original page,
 * which is exactly what the same load would return without the module.
 */
#ifndef UROV_X_ABI_H
#define UROV_X_ABI_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

/* KernelPatch's freestanding stdint.h supplies types but no literal macros. */
#ifndef UINT64_C
#define UINT64_C(value) value##ULL
#endif

#define UROV_X_NAME "urov-x"
#define UROV_X_ABI_VERSION 3U
#define UROV_X_PAGE 4096U
#define UROV_X_FAKE_MAX 32U
#define UROV_X_MAX_SITES 8U

/* Request ops.  The op is carried twice: once as the prctl argument (checked
 * before the request is copied in) and once inside the authenticated body. */
enum urov_x_op {
    UROV_X_QUERY = 1,
    UROV_X_REGISTER = 2,
    UROV_X_SET = 3,
    UROV_X_STATUS = 4,
    UROV_X_DEACTIVATE = 5,
};

enum urov_x_state {
    UROV_X_INACTIVE = 0,
    UROV_X_ACTIVE = 1,
};

/* 192 bytes, no pointers, no implicit padding, fixed little-endian layout. */
struct urov_x_request {
    uint32_t size;
    uint16_t version;
    uint16_t op;
    uint64_t request_id;          /* client nonce, echoed unchanged */
    uint64_t session;             /* 0 or 1 */
    uint64_t address;             /* page-aligned protected page */
    uint64_t expected_generation; /* SET */
    uint64_t value;               /* fake bytes 0..7 */
    uint32_t offset;              /* overlay byte offset inside the page */
    uint32_t length;              /* 8, 16, 24 or 32 (0 means 8) */
    uint64_t value_hi[3];         /* fake bytes 8..15, 16..23, 24..31 */
    uint32_t site_count;          /* 1..UROV_X_MAX_SITES, required */
    uint32_t reserved;            /* must be 0 */
    uint64_t sites[UROV_X_MAX_SITES]; /* reader instruction PCs */
    uint64_t generation;          /* out */
    uint64_t hits;                /* out: emulated loads */
    uint64_t failures;            /* out */
    uint32_t state;               /* out */
    int32_t last_error;           /* out */
    uint64_t mac;                 /* SipHash over bytes [0, MAC_BYTES) */
};

_Static_assert(sizeof(struct urov_x_request) == 192U, "UROV-X wire ABI");
#define UROV_X_MAC_BYTES (sizeof(struct urov_x_request) - sizeof(uint64_t))

/* ------------------------------------------------------------ SipHash-2-4 */
/* Freestanding: no libc, no division, defined for any byte length. The key is
 * a 128-bit value derived from the per-load secret; MACs are 64 bits, which
 * is far beyond what an in-process detector can brute-force through prctl. */

static inline uint64_t urov_x_rotl(uint64_t v, unsigned n)
{
    return (v << n) | (v >> (64U - n));
}

static inline uint64_t urov_x_load64(const uint8_t *p)
{
    uint64_t v = 0;
    unsigned i;
    for (i = 0; i < 8; ++i) v |= (uint64_t)p[i] << (i * 8U);
    return v;
}

#define UROV_X_SIPROUND                                                   \
    do {                                                                  \
        v0 += v1; v1 = urov_x_rotl(v1, 13); v1 ^= v0;                     \
        v0 = urov_x_rotl(v0, 32);                                         \
        v2 += v3; v3 = urov_x_rotl(v3, 16); v3 ^= v2;                     \
        v0 += v3; v3 = urov_x_rotl(v3, 21); v3 ^= v0;                     \
        v2 += v1; v1 = urov_x_rotl(v1, 17); v1 ^= v2;                     \
        v2 = urov_x_rotl(v2, 32);                                         \
    } while (0)

static inline uint64_t urov_x_siphash(const uint64_t k[2], const uint8_t *in,
                                      unsigned len)
{
    uint64_t v0 = UINT64_C(0x736f6d6570736575) ^ k[0];
    uint64_t v1 = UINT64_C(0x646f72616e646f6d) ^ k[1];
    uint64_t v2 = UINT64_C(0x6c7967656e657261) ^ k[0];
    uint64_t v3 = UINT64_C(0x7465646279746573) ^ k[1];
    uint64_t m;
    unsigned i = 0, j;

    while (len - i >= 8U) {
        m = urov_x_load64(in + i);
        v3 ^= m;
        UROV_X_SIPROUND;
        UROV_X_SIPROUND;
        v0 ^= m;
        i += 8U;
    }
    m = (uint64_t)len << 56;
    for (j = 0; i + j < len; ++j) m |= (uint64_t)in[i + j] << (j * 8U);
    v3 ^= m;
    UROV_X_SIPROUND;
    UROV_X_SIPROUND;
    v0 ^= m;
    v2 ^= 0xffU;
    UROV_X_SIPROUND;
    UROV_X_SIPROUND;
    UROV_X_SIPROUND;
    UROV_X_SIPROUND;
    return v0 ^ v1 ^ v2 ^ v3;
}

/* One derived value per label: the label is never secret, the key is. */
static inline uint64_t urov_x_kdf(const uint64_t k[2], uint8_t tag)
{
    uint8_t label[8] = { (uint8_t)'U', (uint8_t)'R', (uint8_t)'O', (uint8_t)'V',
                         (uint8_t)'X', (uint8_t)'/', (uint8_t)'1', 0 };
    label[7] = tag;
    return urov_x_siphash(k, label, 8);
}

struct urov_x_keys {
    uint64_t option;  /* low 32 bits are the prctl option word */
    uint64_t magic;   /* prctl arg1 */
    uint64_t mac[2];  /* SipHash key for request MACs */
};

static inline void urov_x_derive(const uint8_t key[16], struct urov_x_keys *out)
{
    uint64_t k[2];
    k[0] = urov_x_load64(key);
    k[1] = urov_x_load64(key + 8);
    out->option = urov_x_kdf(k, 1U) & UINT64_C(0xffffffff);
    out->magic = urov_x_kdf(k, 2U);
    out->mac[0] = urov_x_kdf(k, 3U);
    out->mac[1] = urov_x_kdf(k, 4U);
}

static inline uint64_t urov_x_request_mac(const uint64_t mack[2],
                                          const struct urov_x_request *q)
{
    return urov_x_siphash(mack, (const uint8_t *)q, (unsigned)UROV_X_MAC_BYTES);
}

/* Strict 32-hex-digit parse. Returns 0 on success, -1 otherwise. */
static inline int urov_x_parse_key(const char *text, unsigned len, uint8_t out[16])
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
