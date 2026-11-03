/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../emulate.h"

static unsigned long checks;
#define CHECK(x) do { ++checks; if (!(x)) { \
    fprintf(stderr, "FAIL line=%d: %s\n", __LINE__, #x); exit(1); } } while (0)
static uint8_t page[URO_PAGE_SIZE];
static uint64_t random_state = UINT64_C(0xc71f0926884a32d1);
static uint64_t next_random(void)
{
    random_state ^= random_state << 13;
    random_state ^= random_state >> 7;
    random_state ^= random_state << 17;
    return random_state;
}
static struct uro_regs registers(void)
{
    struct uro_regs r;
    unsigned i;
    for (i = 0; i < 31; ++i) r.x[i] = next_random();
    r.sp = 0x10ff0;
    r.pc = 0x40000;
    r.pstate = next_random() & UINT64_C(0xf0000000);
    return r;
}
/* Independent byte-array oracle: no decoder or emulator helpers. */
static uint64_t reference(const uint8_t *bytes, unsigned size, int sign, unsigned bits)
{
    uint64_t result = 0;
    unsigned i;
    for (i = size; i != 0; --i) result = result * 256U + bytes[i - 1];
    if (sign && size < 8 && (bytes[size - 1] & 128U))
        result = 0U - ((UINT64_C(1) << (size * 8U)) - result);
    return bits == 32 ? result & UINT64_C(0xffffffff) : result;
}
static void test_values(void)
{
    static const struct {
        uint32_t op; unsigned size, count, bits; int sign;
    } types[] = {
        {0x39400002,1,1,32,0}, {0x79400002,2,1,32,0},
        {0xb9400002,4,1,32,0}, {0xf9400002,8,1,64,0},
        {0x39800002,1,1,64,1}, {0x39c00002,1,1,32,1},
        {0x79800002,2,1,64,1}, {0x79c00002,2,1,32,1},
        {0xb9800002,4,1,64,1}, {0xa9400c02,8,2,64,0},
        {0x29400c02,4,2,32,0}, {0x69400c02,4,2,64,1}
    };
    static const unsigned widths[] = { 8, 16, 32 };
    uint8_t shadow[URO_PAGE_SIZE];
    uint8_t fake[URO_FAKE_MAX];
    unsigned t, round, i;
    struct uro_view v = { page, fake, 0x10000, UINT64_C(1) << 48, 0, 8 };
    for (t = 0; t < sizeof(types) / sizeof(types[0]); ++t) {
        for (round = 0; round < 12000; ++round) {
            struct uro_regs r = registers(), expected;
            unsigned width = widths[round % 3U];
            unsigned total = types[t].size * types[t].count;
            unsigned pos = (unsigned)(next_random() % (URO_PAGE_SIZE - total + 1));
            /* Many intentional overlaps, plus arbitrary/page-edge coverage. */
            v.overlay_len = width;
            v.overlay_offset = round % 2 ? pos : (unsigned)(next_random() % (URO_PAGE_SIZE - width + 1U));
            if (round % 4 == 0 && pos >= 4) v.overlay_offset = pos - 4;
            if (v.overlay_offset > URO_PAGE_SIZE - width) v.overlay_offset = URO_PAGE_SIZE - width;
            for (i = 0; i < URO_FAKE_MAX; ++i) fake[i] = (uint8_t)next_random();
            memcpy(shadow, page, sizeof(shadow));
            for (i = 0; i < width; ++i) shadow[v.overlay_offset + i] = fake[i];
            r.x[0] = v.base + pos;
            expected = r;
            expected.x[2] = reference(shadow + pos, types[t].size, types[t].sign, types[t].bits);
            if (types[t].count == 2)
                expected.x[3] = reference(shadow + pos + types[t].size, types[t].size, types[t].sign, types[t].bits);
            expected.pc += 4;
            CHECK(uro_emulate(&v, types[t].op, URO_READ_ESR,
                r.x[0] + (round % total), &r) == URO_OK);
            CHECK(memcmp(&r, &expected, sizeof(r)) == 0);
        }
    }
}
static void test_address_modes(void)
{
    static const struct {
        uint32_t op; uint64_t base, index; unsigned pos; uint64_t wb;
    } cases[] = {
        {0xf9400402,0x10038,0,64,0},       /* scaled */
        {0xf85f8002,0x10048,0,64,0},       /* negative unscaled */
        {0xf8408c02,0x10038,0,64,0x10040}, /* pre */
        {0xf8408402,0x10040,0,64,0x10048}, /* post */
        {0xf8616802,0x10038,8,64,0},      /* register */
        {0xf8617802,0x10038,1,64,0},      /* LSL */
        {0xf8615802,0x10038,0xffffffff00000001ULL,64,0},
        {0xf861d802,0x10048,0xffffffff,64,0}, /* SXTW */
        {0xf861f802,0x10048,~UINT64_C(0),64,0} /* SXTX */
    };
    uint8_t fake[URO_FAKE_MAX] = { 0 };
    struct uro_view v = { page, fake, 0x10000, UINT64_C(1) << 48, 64, 8 };
    unsigned i;
    for (i = 0; i < 8; ++i) fake[i] = (uint8_t)(UINT64_C(0xabcdef9876543210) >> (i * 8U));
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        struct uro_regs r = registers(), expected;
        r.x[0] = cases[i].base;
        r.x[1] = cases[i].index;
        expected = r;
        expected.x[2] = UINT64_C(0xabcdef9876543210);
        expected.pc += 4;
        if (cases[i].wb) expected.x[0] = cases[i].wb;
        CHECK(uro_emulate(&v, cases[i].op, URO_READ_ESR, v.base + cases[i].pos, &r) == URO_OK);
        CHECK(memcmp(&r, &expected, sizeof(r)) == 0);
    }
    {
        struct uro_regs r = registers(), expected;
        r.sp = 0x10040;
        expected = r;
        expected.pc += 4;
        expected.sp += 8;
        /* LDR XZR,[SP],#8: discard, but SP writeback still happens. */
        CHECK(uro_emulate(&v, 0xf84087ff, URO_READ_ESR, r.sp, &r) == URO_OK);
        CHECK(memcmp(&r, &expected, sizeof(r)) == 0);
        r = registers(); r.pc = 0x10030; expected = r;
        expected.x[2] = UINT64_C(0xabcdef9876543210); expected.pc += 4;
        CHECK(uro_emulate(&v, 0x58000082, URO_READ_ESR, 0x10040, &r) == URO_OK);
        CHECK(memcmp(&r, &expected, sizeof(r)) == 0);
    }
}
static void no_commit(struct uro_view *v, uint32_t op, uint64_t esr,
                      uint64_t far, struct uro_regs r, int result)
{
    struct uro_regs before = r;
    CHECK(uro_emulate(v, op, esr, far, &r) == result);
    CHECK(memcmp(&r, &before, sizeof(r)) == 0);
}
static void test_failures(void)
{
    uint8_t fake[URO_FAKE_MAX] = { 0 };
    struct uro_view v = { page, fake, 0x10000, UINT64_C(1) << 48, 64, 8 };
    struct uro_regs r = registers();
    unsigned i;
    static const uint32_t unsupported[] = {
        0xf9000002,0x3dc00002,0xc8dffc02,0xc85f7c02,0xf8400802,0xd503201f,
        0xf8408400,0xa9400802 /* overlaps */
    };
    r.x[0] = 0x10040;
    for (i = 0; i < sizeof(unsupported) / sizeof(unsupported[0]); ++i)
        no_commit(&v, unsupported[i], URO_READ_ESR, r.x[0], r, URO_UNSUPPORTED);
    for (i = 6; i <= 14; ++i)
        no_commit(&v, 0xf9400002, URO_READ_ESR | (UINT64_C(1) << i), r.x[0], r, URO_NOT_MINE);
    no_commit(&v, 0xf9400002, URO_READ_ESR ^ 4U, r.x[0], r, URO_NOT_MINE);
    no_commit(&v, 0xf9400002, URO_READ_ESR, 0x11000, r, URO_NOT_MINE);
    no_commit(&v, 0xf9400002, URO_READ_ESR, 0x10048, r, URO_BAD_FAR);
    no_commit(&v, 0xf9400002, URO_READ_ESR | (UINT64_C(1) << 24), r.x[0], r, URO_BAD_SYNDROME);
    {
        uint64_t valid_isv = URO_READ_ESR | (UINT64_C(1) << 24) |
            (UINT64_C(3) << 22) | (UINT64_C(2) << 16) | (UINT64_C(1) << 15);
        struct uro_regs test = r;
        CHECK(uro_emulate(&v, 0xf9400002, valid_isv, r.x[0], &test) == URO_OK);
        CHECK(test.x[2] == 0);
    }
    r.pc = v.user_limit - 4;
    no_commit(&v, 0xf9400002, URO_READ_ESR, r.x[0], r, URO_BAD_CONTEXT);
    r.pc = 0x40002;
    no_commit(&v, 0xf9400002, URO_READ_ESR, r.x[0], r, URO_BAD_CONTEXT);
    r.pc = 0x40000; r.pstate |= 0x10;
    no_commit(&v, 0xf9400002, URO_READ_ESR, r.x[0], r, URO_BAD_CONTEXT);
    r.pstate = 0; r.x[0] = 0x10ffc;
    no_commit(&v, 0xf9400002, URO_READ_ESR, r.x[0], r, URO_BAD_RANGE);
    r.x[0] = UINT64_C(0xab00000000010040);
    no_commit(&v, 0xf9400002, URO_READ_ESR, 0x10040, r, URO_BAD_RANGE);
    v.overlay_len = 0;
    no_commit(&v, 0xf9400002, URO_READ_ESR, 0x10040, r, URO_BAD_CONFIG);
    v.overlay_len = 33;
    no_commit(&v, 0xf9400002, URO_READ_ESR, 0x10040, r, URO_BAD_CONFIG);
    v.overlay_len = 16; v.overlay_offset = 4081;
    no_commit(&v, 0xf9400002, URO_READ_ESR, 0x10040, r, URO_BAD_CONFIG);
    v.overlay_len = 8; v.overlay_offset = 4089;
    no_commit(&v, 0xf9400002, URO_READ_ESR, 0x10040, r, URO_BAD_CONFIG);
    v.overlay_offset = 64; v.fake = 0;
    no_commit(&v, 0xf9400002, URO_READ_ESR, 0x10040, r, URO_BAD_CONFIG);
    CHECK(uro_emulate(NULL, 0, 0, 0, &r) == URO_BAD_CONFIG);
    CHECK(uro_emulate(&v, 0, 0, 0, NULL) == URO_BAD_CONFIG);
}

static const uint64_t set_a[4] = {
    UINT64_C(0x1122334455667788), UINT64_C(0x99aabbccddeeff00),
    UINT64_C(0x0123456789abcdef), UINT64_C(0xfedcba9876543210)
};
static const uint64_t set_b[4] = {
    UINT64_C(0xfedcba9876543210), UINT64_C(0x0123456789abcdef),
    UINT64_C(0x99aabbccddeeff00), UINT64_C(0x1122334455667788)
};
static _Atomic(const uint64_t *) live_set;
static _Atomic unsigned failures;
static void *reader(void *unused)
{
    uint8_t fake[URO_FAKE_MAX];
    struct uro_view v = { page, fake, 0x10000, UINT64_C(1) << 48, 64, 32 };
    unsigned n;
    (void)unused;
    for (n = 0; n < 25000; ++n) {
        const uint64_t *set = atomic_load_explicit(&live_set, memory_order_acquire);
        struct uro_regs r = { { 0 }, 0x10040, 0x40000, 0 };
        memcpy(fake, set, URO_FAKE_MAX);
        r.x[0] = 0x10040;
        if (uro_emulate(&v, 0xa9400c02, URO_READ_ESR, 0x10040, &r) != URO_OK) {
            fprintf(stderr, "pair emulate failed set=%llx\n", (unsigned long long)set[0]);
            atomic_fetch_add(&failures, 1); continue;
        }
        if (!((r.x[2] == set_a[0] && r.x[3] == set_a[1]) ||
              (r.x[2] == set_b[0] && r.x[3] == set_b[1]))) {
            fprintf(stderr, "pair mismatch got=%llx,%llx set=%llx,%llx\n",
                    (unsigned long long)r.x[2], (unsigned long long)r.x[3],
                    (unsigned long long)set[0], (unsigned long long)set[1]);
            atomic_fetch_add(&failures, 1);
        }
        r = (struct uro_regs){ { 0 }, 0x10ff0, 0x40000, 0 };
        r.x[0] = 0x10058;
        {
            int wrc = uro_emulate(&v, 0xf9400002, URO_READ_ESR, 0x10058, &r);
            if (wrc != URO_OK || !(r.x[2] == set_a[3] || r.x[2] == set_b[3])) {
                fprintf(stderr, "word mismatch rc=%d got=%llx set=%llx\n", wrc,
                        (unsigned long long)r.x[2], (unsigned long long)set[3]);
                atomic_fetch_add(&failures, 1);
            }
        }
    }
    return NULL;
}
static void test_threads(void)
{
    pthread_t threads[4];
    unsigned i;
    atomic_store(&live_set, set_a);
    for (i = 0; i < 4; ++i) CHECK(pthread_create(&threads[i], NULL, reader, NULL) == 0);
    for (i = 0; i < 100000; ++i)
        atomic_store_explicit(&live_set, i % 2 ? set_a : set_b, memory_order_release);
    for (i = 0; i < 4; ++i) CHECK(pthread_join(threads[i], NULL) == 0);
    CHECK(atomic_load(&failures) == 0);
}
int main(void)
{
    unsigned small_checks;
    int line = uro_core_selftest(page, &small_checks);
    if (line) fprintf(stderr, "core_selftest line=%d\n", line);
    CHECK(line == 0);
    test_values(); test_address_modes(); test_failures(); test_threads();
    CHECK(small_checks == URO_CORE_CHECKS);
    printf("PASS emulator_checks=%lu core_checks=%u value_cases=144000 threaded_pair_cases=100000 scope=software_core_only\n",
           checks, small_checks);
    return 0;
}
