/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "emulate.h"

static int same_regs(const struct uro_regs *a, const struct uro_regs *b)
{
    unsigned i;
    for (i = 0; i < 31; ++i)
        if (a->x[i] != b->x[i]) return 0;
    return a->sp == b->sp && a->pc == b->pc && a->pstate == b->pstate;
}

static void copy_regs(struct uro_regs *to, const struct uro_regs *from)
{
    unsigned i;
    for (i = 0; i < 31; ++i) to->x[i] = from->x[i];
    to->sp = from->sp; to->pc = from->pc; to->pstate = from->pstate;
}

/* Little-endian byte model. The overlay is only defined for little-endian
 * EL0, which the active backend validates through its platform checks. */
static void put64(uint8_t *p, uint64_t value)
{
    unsigned i;
    for (i = 0; i < 8; ++i) p[i] = (uint8_t)(value >> (i * 8U));
}

/* Independent oracle for one eight-byte load from the merged page. */
static uint64_t merged_word(const uint8_t *page, const uint8_t *fake,
                            unsigned overlay_offset, unsigned overlay_len,
                            unsigned at)
{
    uint64_t value = 0;
    unsigned i;
    for (i = 0; i < 8; ++i) {
        unsigned pos = at + i;
        uint8_t b = (pos >= overlay_offset &&
                     pos - overlay_offset < overlay_len)
                        ? fake[pos - overlay_offset]
                        : page[pos];
        value |= (uint64_t)b << (i * 8U);
    }
    return value;
}

int uro_core_selftest(uint8_t *page, unsigned *checks)
{
    uint8_t fake[URO_FAKE_MAX];
    struct uro_view v = { page, fake, 0x10000, UINT64_C(1) << 48, 64, 8 };
    struct uro_regs r = { { 0 }, 0x10040, 0x20000, UINT64_C(0xa0000000) };
    struct uro_regs before;
    const uint64_t word0 = UINT64_C(0x8877665544332211);
    const uint64_t word1 = UINT64_C(0xf1e2d3c4b5a69788);
    const uint64_t word2 = UINT64_C(0x0123456789abcdef);
    const uint64_t word3 = UINT64_C(0xdeadbeefcafebabe);
    unsigned i;
    if (!page || !checks) return __LINE__;
    *checks = 0;
#define CHECK(x) do { ++*checks; if (!(x)) return __LINE__; } while (0)
    for (i = 0; i < URO_PAGE_SIZE; ++i) page[i] = (uint8_t)(i * 17U + 3U);
    put64(fake, word0);
    put64(fake + 8, word1);
    put64(fake + 16, word2);
    put64(fake + 24, word3);
    r.x[0] = 0x10040;
    copy_regs(&before, &r);
    CHECK(uro_emulate(&v, 0xf9400002U, URO_READ_ESR, r.x[0], &r) == URO_OK);
    CHECK(r.x[2] == word0 && r.pc == before.pc + 4 && r.pstate == before.pstate);
    copy_regs(&r, &before);
    fake[0] = 0x80;
    CHECK(uro_emulate(&v, 0x39c00002U, URO_READ_ESR, r.x[0], &r) == URO_OK);
    CHECK(r.x[2] == UINT64_C(0xffffff80));
    copy_regs(&r, &before);
    CHECK(uro_emulate(&v, 0x39800002U, URO_READ_ESR, r.x[0], &r) == URO_OK);
    CHECK(r.x[2] == UINT64_C(0xffffffffffffff80));
    put64(fake, word0);
    copy_regs(&r, &before);
    r.x[0] -= 8;
    CHECK(uro_emulate(&v, 0xa9400c02U, URO_READ_ESR, 0x10040, &r) == URO_OK);
    CHECK(r.x[3] == word0);
    copy_regs(&r, &before);
    CHECK(uro_emulate(&v, 0xf8408402U, URO_READ_ESR, r.x[0], &r) == URO_OK);
    CHECK(r.x[0] == 0x10048 && r.x[2] == word0);
    copy_regs(&r, &before);
    CHECK(uro_emulate(&v, 0xf9000002U, URO_READ_ESR, r.x[0], &r) == URO_UNSUPPORTED);
    CHECK(same_regs(&r, &before));
    CHECK(uro_emulate(&v, 0xf9400002U, URO_READ_ESR, 0x10050, &r) == URO_BAD_FAR);
    CHECK(same_regs(&r, &before));
    CHECK(uro_emulate(&v, 0xf9400002U, URO_READ_ESR | 64U, r.x[0], &r) == URO_NOT_MINE);
    CHECK(same_regs(&r, &before));
    r.x[0] = 0x10ffc;
    copy_regs(&before, &r);
    CHECK(uro_emulate(&v, 0xf9400002U, URO_READ_ESR, r.x[0], &r) == URO_BAD_RANGE);
    CHECK(same_regs(&r, &before));

    /* 16-byte window: both halves, a pair wholly inside it and a pair that
     * crosses from the fake bytes back into the original page bytes. */
    v.overlay_offset = 4;
    v.overlay_len = 16;
    r = (struct uro_regs){ { 0 }, 0x10ff0, 0x20000, UINT64_C(0xa0000000) };
    r.x[0] = 0x10004;
    copy_regs(&before, &r);
    CHECK(uro_emulate(&v, 0xf9400002U, URO_READ_ESR, r.x[0], &r) == URO_OK);
    CHECK(r.x[2] == merged_word(page, fake, 4, 16, 4));
    CHECK(r.x[2] == word0);
    copy_regs(&r, &before);
    r.x[0] = 0x1000c;
    CHECK(uro_emulate(&v, 0xf9400002U, URO_READ_ESR, r.x[0], &r) == URO_OK);
    CHECK(r.x[2] == merged_word(page, fake, 4, 16, 12));
    CHECK(r.x[2] == word1);
    copy_regs(&r, &before);
    CHECK(uro_emulate(&v, 0xa9400c02U, URO_READ_ESR, r.x[0], &r) == URO_OK);
    CHECK(r.x[2] == word0 && r.x[3] == word1);
    copy_regs(&r, &before);
    r.x[0] = 0x10010;
    CHECK(uro_emulate(&v, 0xa9400c02U, URO_READ_ESR, r.x[0], &r) == URO_OK);
    CHECK(r.x[2] == merged_word(page, fake, 4, 16, 16));
    CHECK(r.x[3] == merged_word(page, fake, 4, 16, 24));

    /* 32-byte window: unaligned start, an interior 16-byte pair, and the two
     * page-original stitches at the front and back of the window. */
    v.overlay_len = 32;
    r = (struct uro_regs){ { 0 }, 0x10ff0, 0x20000, UINT64_C(0xa0000000) };
    r.x[0] = 0x10000;
    copy_regs(&before, &r);
    CHECK(uro_emulate(&v, 0xf9400002U, URO_READ_ESR, r.x[0], &r) == URO_OK);
    CHECK(r.x[2] == merged_word(page, fake, 4, 32, 0));
    copy_regs(&r, &before);
    r.x[0] = 0x10008;
    CHECK(uro_emulate(&v, 0xa9400c02U, URO_READ_ESR, r.x[0], &r) == URO_OK);
    CHECK(r.x[2] == merged_word(page, fake, 4, 32, 8));
    CHECK(r.x[3] == merged_word(page, fake, 4, 32, 16));
    copy_regs(&r, &before);
    r.x[0] = 0x1001c;
    CHECK(uro_emulate(&v, 0xf9400002U, URO_READ_ESR, r.x[0], &r) == URO_OK);
    CHECK(r.x[2] == merged_word(page, fake, 4, 32, 28));
    copy_regs(&r, &before);
    r.x[0] = 0x10020;
    CHECK(uro_emulate(&v, 0xf9400002U, URO_READ_ESR, r.x[0], &r) == URO_OK);
    CHECK(r.x[2] == merged_word(page, fake, 4, 32, 32));

    /* Configuration rejection must not fall back to an eight-byte window. */
    {
        struct uro_regs keep;
        copy_regs(&keep, &r);
        v.overlay_len = 0;   CHECK(uro_emulate(&v, 0xf9400002U, URO_READ_ESR, r.x[0], &r) == URO_BAD_CONFIG);
        v.overlay_len = 33;  CHECK(uro_emulate(&v, 0xf9400002U, URO_READ_ESR, r.x[0], &r) == URO_BAD_CONFIG);
        v.overlay_len = 16;
        v.overlay_offset = 4081;
        CHECK(uro_emulate(&v, 0xf9400002U, URO_READ_ESR, r.x[0], &r) == URO_BAD_CONFIG);
        v.overlay_offset = 4;
        v.fake = 0;
        CHECK(uro_emulate(&v, 0xf9400002U, URO_READ_ESR, r.x[0], &r) == URO_BAD_CONFIG);
        CHECK(same_regs(&r, &keep));
        v.fake = fake;
    }

    /* decode.c also decodes the SIMD&FP load forms so the urov-z target-page
     * backend can serve large libc transfers (bionic switches to LDR Q/LDP Q
     * from 16 bytes in memcpy and in memcmp/strlen over larger ranges).  The
     * shared GPR emulator must keep rejecting them exactly as urov-x did. */
    {
        struct uro_load d;
        struct uro_regs keep;
        struct uro_regs q = { { 0 }, 0x2000, 0x20000, 0 };

        q.x[0] = 0x10020;
        q.x[1] = 0x10020;
        CHECK(uro_decode(0x3dc00020U, &q, &d) == 0);
        CHECK(d.vector && d.size == 16 && d.count == 1 && d.rt == 0 &&
              d.address == 0x10020 && d.dest_bits == 128);
        CHECK(uro_decode(0xad412c2aU, &q, &d) == 0);
        CHECK(d.vector && d.size == 16 && d.count == 2 && d.rt == 10 &&
              d.rt2 == 11 && d.address == 0x10040 && !d.writeback);
        CHECK(uro_decode(0xadc2342cU, &q, &d) == 0);
        CHECK(d.vector && d.writeback && d.address == 0x10060 && d.wb == 0x10060);
        CHECK(uro_decode(0x3cdf0022U, &q, &d) == 0);
        CHECK(d.vector && d.size == 16 && d.address == 0x10010 && !d.writeback);
        CHECK(uro_decode(0xfd400026U, &q, &d) == 0);
        CHECK(d.vector && d.size == 8 && d.rt == 6 && d.dest_bits == 64);
        CHECK(uro_decode(0x3d800020U, &q, &d) == -1); /* STR Q is not a load */
        copy_regs(&keep, &r);
        CHECK(uro_emulate(&v, 0x3dc00020U, URO_READ_ESR, 0x10020, &r) == URO_UNSUPPORTED);
        CHECK(same_regs(&r, &keep));
    }

    for (i = 0; i < URO_PAGE_SIZE; ++i) CHECK(page[i] == (uint8_t)(i * 17U + 3U));
#undef CHECK
    return 0;
}
