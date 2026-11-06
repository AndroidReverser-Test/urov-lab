/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Assemble with -x assembler-with-cpp -DURO_ASM_CORPUS to independently check
 * every opcode in the table. Use objcopy -O binary -j .text, then pass the
 * resulting file as argv[1] to the native host test. No target is accessed. */
#ifdef URO_ASM_CORPUS
.text
ldrb w0, [x1, #3]
ldrh w2, [x1, #6]
ldr w3, [x1, #12]
ldr x4, [x1, #24]
ldrsb x5, [x1, #3]
ldrsb w6, [x1, #3]
ldrsh x7, [x1, #6]
ldrsh w8, [x1, #6]
ldrsw x9, [x1, #12]
ldur x10, [x1, #-8]
ldurb w11, [x1, #-1]
ldurh w12, [x1, #-2]
ldursb x13, [x1, #-1]
ldursb w14, [x1, #-1]
ldursh x15, [x1, #-2]
ldursh w16, [x1, #-2]
ldursw x17, [x1, #-4]
ldr x2, [x1, #16]!
ldr x2, [x1], #16
ldr w2, [x1, #-4]!
ldr x2, [x1, x3]
ldr x2, [x1, x3, lsl #3]
ldr x2, [x1, w3, uxtw]
ldr x2, [x1, w3, uxtw #3]
ldr x2, [x1, w3, sxtw #3]
ldr x2, [x1, x3, sxtx #3]
ldr w2, .+16
ldr x3, .-16
ldrsw x4, .+12
ldp x2, x3, [x1, #16]
ldp w2, w3, [x1, #8]
ldpsw x2, x3, [x1, #8]
ldnp x2, x3, [x1, #-16]
ldnp w2, w3, [x1, #8]
ldp x2, x3, [x1, #16]!
ldp x2, x3, [x1], #-16
ldpsw x2, x3, [x1, #8]!
ldpsw x2, x3, [x1], #-8
ldp xzr, x2, [sp]
ldr xzr, [sp, #8]
ldr x2, [x1, xzr]
str x2, [x1]
prfm pldl1keep, [x1]
ldar x2, [x1]
ldxr x2, [x1]
ldr q0, [x1]
ldp q0, q1, [x1]
ldtr x2, [x1]
prfm pldl1keep, .+16
nop
ldur q2, [x1, #-16]
ldr q3, [x1, #48]!
ldp q12, q13, [x1, #64]!
ldr d6, [x1]
ldp s20, s21, [x1]
ldr q5, [x1, x3, lsl #4]
ldr q7, .+16
str q0, [x1]
/* Multiple-structure loads (LD1/LD2/LD3/LD4), plus two rejected forms. */
ld1 {v0.16b}, [x0]
ld1 {v0.16b, v1.16b}, [x0]
ld1 {v0.16b - v2.16b}, [x0]
ld1 {v0.16b - v3.16b}, [x0]
ld2 {v0.16b, v1.16b}, [x0]
ld3 {v0.16b - v2.16b}, [x0]
ld4 {v0.16b - v3.16b}, [x0]
ld1 {v0.8b}, [x0], #8
ld1 {v0.16b}, [x0], #16
ld1 {v0.16b, v1.16b}, [x0], #32
ld2 {v0.16b, v1.16b}, [x0], #32
ld1 {v0.16b}, [x0], x1
ld1 {v0.16b - v3.16b}, [x0], x1
ld1 {v0.4h}, [x0]
ld2 {v0.4h, v1.4h}, [x0]
ld1 {v0.2d}, [x0]
ld1 {v0.8b - v2.8b}, [x0]
st1 {v0.16b}, [x0]
ld1 {v0.b}[0], [x0]
#else
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../decode.h"

struct vector {
    uint32_t opcode;
    uint64_t address;
    unsigned size, count, rt, rt2, dest_bits;
    int sign, writeback;
    unsigned rn;
    uint64_t wb;
    unsigned is_vector;
};

#define SINGLE(op, addr, sz, dest, bits, sign) \
    { op, addr, sz, 1, dest, 31, bits, sign, 0, 1, 0, 0 }
#define WB(op, addr, sz, base) \
    { op, addr, sz, 1, 2, 31, sz == 8 ? 64 : 32, 0, 1, 1, base, 0 }
#define PAIR(op, addr, sz, bits, sign, writes, base) \
    { op, addr, sz, 2, 2, 3, bits, sign, writes, 1, base, 0 }
#define VSINGLE(op, addr, sz, rt) \
    { op, addr, sz, 1, rt, 31, sz * 8, 0, 0, 1, 0, 1 }
#define VWB(op, addr, sz, rt, base) \
    { op, addr, sz, 1, rt, 31, sz * 8, 0, 1, 1, base, 1 }
#define VPAIR(op, addr, sz, rt, rt2) \
    { op, addr, sz, 2, rt, rt2, sz * 8, 0, 0, 1, 0, 1 }
#define VPAIRWB(op, addr, sz, rt, rt2, base) \
    { op, addr, sz, 2, rt, rt2, sz * 8, 0, 1, 1, base, 1 }
#define BAD(op) { op, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
static const struct vector vectors[] = {
    SINGLE(0x39400c20U, 0x1003, 1, 0, 32, 0),
    SINGLE(0x79400c22U, 0x1006, 2, 2, 32, 0),
    SINGLE(0xb9400c23U, 0x100c, 4, 3, 32, 0),
    SINGLE(0xf9400c24U, 0x1018, 8, 4, 64, 0),
    SINGLE(0x39800c25U, 0x1003, 1, 5, 64, 1),
    SINGLE(0x39c00c26U, 0x1003, 1, 6, 32, 1),
    SINGLE(0x79800c27U, 0x1006, 2, 7, 64, 1),
    SINGLE(0x79c00c28U, 0x1006, 2, 8, 32, 1),
    SINGLE(0xb9800c29U, 0x100c, 4, 9, 64, 1),
    SINGLE(0xf85f802aU, 0x0ff8, 8, 10, 64, 0),
    SINGLE(0x385ff02bU, 0x0fff, 1, 11, 32, 0),
    SINGLE(0x785fe02cU, 0x0ffe, 2, 12, 32, 0),
    SINGLE(0x389ff02dU, 0x0fff, 1, 13, 64, 1),
    SINGLE(0x38dff02eU, 0x0fff, 1, 14, 32, 1),
    SINGLE(0x789fe02fU, 0x0ffe, 2, 15, 64, 1),
    SINGLE(0x78dfe030U, 0x0ffe, 2, 16, 32, 1),
    SINGLE(0xb89fc031U, 0x0ffc, 4, 17, 64, 1),
    WB(0xf8410c22U, 0x1010, 8, 0x1010),
    WB(0xf8410422U, 0x1000, 8, 0x1010),
    WB(0xb85fcc22U, 0x0ffc, 4, 0x0ffc),
    SINGLE(0xf8636822U, 0x1003, 8, 2, 64, 0),
    SINGLE(0xf8637822U, 0x1018, 8, 2, 64, 0),
    SINGLE(0xf8634822U, 0x1003, 8, 2, 64, 0),
    SINGLE(0xf8635822U, 0x1018, 8, 2, 64, 0),
    SINGLE(0xf863d822U, 0x1018, 8, 2, 64, 0),
    SINGLE(0xf863f822U, 0x1018, 8, 2, 64, 0),
    { 0x18000082U, 0x3010, 4, 1, 2, 31, 32, 0, 0, 31, 0, 0 },
    { 0x58ffff83U, 0x2ff0, 8, 1, 3, 31, 64, 0, 0, 31, 0, 0 },
    { 0x98000064U, 0x300c, 4, 1, 4, 31, 64, 1, 0, 31, 0, 0 },
    PAIR(0xa9410c22U, 0x1010, 8, 64, 0, 0, 0),
    PAIR(0x29410c22U, 0x1008, 4, 32, 0, 0, 0),
    PAIR(0x69410c22U, 0x1008, 4, 64, 1, 0, 0),
    PAIR(0xa87f0c22U, 0x0ff0, 8, 64, 0, 0, 0),
    PAIR(0x28410c22U, 0x1008, 4, 32, 0, 0, 0),
    PAIR(0xa9c10c22U, 0x1010, 8, 64, 0, 1, 0x1010),
    PAIR(0xa8ff0c22U, 0x1000, 8, 64, 0, 1, 0x0ff0),
    PAIR(0x69c10c22U, 0x1008, 4, 64, 1, 1, 0x1008),
    PAIR(0x68ff0c22U, 0x1000, 4, 64, 1, 1, 0x0ff8),
    { 0xa9400bffU, 0x2000, 8, 2, 31, 2, 64, 0, 0, 31, 0, 0 },
    { 0xf94007ffU, 0x2008, 8, 1, 31, 31, 64, 0, 0, 31, 0, 0 },
    SINGLE(0xf87f6822U, 0x1000, 8, 2, 64, 0),
    BAD(0xf9000022U), BAD(0xf9800020U), BAD(0xc8dffc22U),
    BAD(0xc85f7c22U), VSINGLE(0x3dc00020U, 0x1000, 16, 0),
    VPAIR(0xad400420U, 0x1000, 16, 0, 1),
    BAD(0xf8400822U), BAD(0xd8000080U), BAD(0xd503201fU),
    /* SIMD&FP loads the urov-y target-page backend now emulates: the forms
     * bionic takes for large memcpy/memcmp/strlen transfers. */
    VSINGLE(0x3cdf0022U, 0x0ff0, 16, 2),
    VWB(0x3cc30c23U, 0x1030, 16, 3, 0x1030),
    VPAIRWB(0xadc2342cU, 0x1040, 16, 12, 13, 0x1040),
    VSINGLE(0xfd400026U, 0x1000, 8, 6),
    VPAIR(0x2d405434U, 0x1000, 4, 20, 21),
    VSINGLE(0x3ce37825U, 0x1030, 16, 5),
    { 0x9c000087U, 0x3010, 16, 1, 7, 31, 128, 0, 0, 31, 0, 1 },
    BAD(0x3d800020U)
};

/* Multiple-structure corpus.  Address 0 comes from the zeroed x0 of
 * registers(); x1 is 0x1000, hence the register post-index writeback. */
struct multi_vector {
    uint32_t opcode;
    uint64_t address, wb;
    unsigned size, count, rt, rt2, dest_bits, writeback, rn;
    unsigned nregs, selem, esize, elements;
    unsigned dst[4];
};

#define MULTI(op, sz, cnt, nregs, selem, esize, elements, \
              d0, d1, d2, d3, writes, wb) \
    { op, 0, wb, sz, cnt, 0, 31, sz * 8U, writes, 0, \
      nregs, selem, esize, elements, { d0, d1, d2, d3 } }

static const struct multi_vector multis[] = {
    MULTI(0x4c407000U, 16, 1, 1, 1, 1, 16, 0, 0, 0, 0, 0, 0),
    MULTI(0x4c40a000U, 16, 2, 2, 1, 1, 16, 0, 1, 0, 0, 0, 0),
    MULTI(0x4c406000U, 16, 3, 3, 1, 1, 16, 0, 1, 2, 0, 0, 0),
    MULTI(0x4c402000U, 16, 4, 4, 1, 1, 16, 0, 1, 2, 3, 0, 0),
    MULTI(0x4c408000U, 16, 2, 1, 2, 1, 16, 0, 1, 0, 0, 0, 0),
    MULTI(0x4c404000U, 16, 3, 1, 3, 1, 16, 0, 1, 2, 0, 0, 0),
    MULTI(0x4c400000U, 16, 4, 1, 4, 1, 16, 0, 1, 2, 3, 0, 0),
    MULTI(0x0cdf7000U, 8, 1, 1, 1, 1, 8, 0, 0, 0, 0, 1, 8),
    MULTI(0x4cdf7000U, 16, 1, 1, 1, 1, 16, 0, 0, 0, 0, 1, 16),
    MULTI(0x4cdfa000U, 16, 2, 2, 1, 1, 16, 0, 1, 0, 0, 1, 32),
    MULTI(0x4cdf8000U, 16, 2, 1, 2, 1, 16, 0, 1, 0, 0, 1, 32),
    MULTI(0x4cc17000U, 16, 1, 1, 1, 1, 16, 0, 0, 0, 0, 1, 0x1000),
    MULTI(0x4cc12000U, 16, 4, 4, 1, 1, 16, 0, 1, 2, 3, 1, 0x1000),
    MULTI(0x0c407400U, 8, 1, 1, 1, 2, 4, 0, 0, 0, 0, 0, 0),
    MULTI(0x0c408400U, 8, 2, 1, 2, 2, 4, 0, 1, 0, 0, 0, 0),
    MULTI(0x4c407c00U, 16, 1, 1, 1, 8, 2, 0, 0, 0, 0, 0, 0),
    MULTI(0x0c406000U, 8, 3, 3, 1, 1, 8, 0, 1, 2, 0, 0, 0)
};

static unsigned checks;
#define CHECK(expr) do { \
    ++checks; \
    if (!(expr)) { fprintf(stderr, "FAIL line=%d: %s\n", __LINE__, #expr); exit(1); } \
} while (0)

static struct uro_regs registers(void)
{
    struct uro_regs r = { { 0 }, 0x2000, 0x3000, 0 };
    r.x[1] = 0x1000;
    r.x[3] = 3;
    return r;
}

static void reject(uint32_t opcode, const struct uro_regs *r)
{
    struct uro_load out, original;
    memset(&out, 0xa5, sizeof(out));
    memcpy(&original, &out, sizeof(out));
    CHECK(uro_decode(opcode, r, &out) == -1);
    CHECK(memcmp(&out, &original, sizeof(out)) == 0);
}

static void test_vectors(void)
{
    size_t i;
    struct uro_regs r = registers();
    for (i = 0; i < sizeof(vectors) / sizeof(vectors[0]); ++i) {
        const struct vector *v = &vectors[i];
        struct uro_load out;
        if (!v->count) {
            reject(v->opcode, &r);
            continue;
        }
        CHECK(uro_decode(v->opcode, &r, &out) == 0);
        CHECK(out.address == v->address);
        CHECK(out.size == v->size && out.count == v->count);
        CHECK(out.rt == v->rt && out.rt2 == v->rt2);
        CHECK(out.dest_bits == v->dest_bits && out.sign_extend == v->sign);
        CHECK(out.writeback == v->writeback && out.wb == v->wb && out.rn == v->rn);
        CHECK(out.vector == v->is_vector);
    }
}

static void test_multi(void)
{
    struct uro_regs r = registers();
    size_t i;

    for (i = 0; i < sizeof(multis) / sizeof(multis[0]); ++i) {
        const struct multi_vector *m = &multis[i];
        struct uro_load out;
        unsigned j;
        CHECK(uro_decode(m->opcode, &r, &out) == 0);
        CHECK(out.vector && out.multi);
        CHECK(out.address == m->address);
        CHECK(out.size == m->size && out.count == m->count);
        CHECK(out.total == (uint64_t)m->size * m->count);
        CHECK(out.rt == m->rt && out.rt2 == m->rt2);
        CHECK(out.dest_bits == m->dest_bits);
        CHECK(out.writeback == (int)m->writeback && out.wb == m->wb && out.rn == m->rn);
        CHECK(out.nregs == m->nregs && out.selem == m->selem);
        CHECK(out.esize == m->esize && out.elements == m->elements);
        for (j = 0; j < m->count; ++j)
            CHECK(out.dst[j] == m->dst[j]);
    }
    reject(0x4c007000U, &r); /* ST1 is a store. */
    reject(0x0d400000U, &r); /* single-lane group is not multiple-structure. */
    reject(0x4c410800U, &r); /* no-offset form with a nonzero Rm. */
    reject(0x0c408c00U, &r); /* 1D LD2 form is UNDEF. */
    r.x[0] = ~(uint64_t)0 - 8U;
    reject(0x4cdfa000U, &r); /* 32-byte post-index wraps the address. */
}


static void verify_assembly(const char *path)
{
    FILE *input = fopen(path, "rb");
    size_t i;

    CHECK(input != NULL);
    for (i = 0; i < sizeof(vectors) / sizeof(vectors[0]); ++i) {
        unsigned char b[4];
        uint32_t opcode;
        CHECK(fread(b, 1, sizeof(b), input) == sizeof(b));
        opcode = (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
                 ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
        if (opcode != vectors[i].opcode)
            fprintf(stderr, "corpus[%zu] assembler=%08x expected=%08x\n", i, opcode, vectors[i].opcode);
        CHECK(opcode == vectors[i].opcode);
    }
    for (i = 0; i < sizeof(multis) / sizeof(multis[0]); ++i) {
        unsigned char b[4];
        uint32_t opcode;
        CHECK(fread(b, 1, sizeof(b), input) == sizeof(b));
        opcode = (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
                 ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
        if (opcode != multis[i].opcode)
            fprintf(stderr, "multi[%zu] assembler=%08x expected=%08x\n", i, opcode, multis[i].opcode);
        CHECK(opcode == multis[i].opcode);
    }
    /* The two rejected forms at the end of the assembly corpus. */
    {
        static const uint32_t tail[] = { 0x4c007000U, 0x0d400000U };
        for (i = 0; i < sizeof(tail) / sizeof(tail[0]); ++i) {
            unsigned char b[4];
            uint32_t opcode;
            CHECK(fread(b, 1, sizeof(b), input) == sizeof(b));
            opcode = (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
                     ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
            CHECK(opcode == tail[i]);
        }
    }
    CHECK(fgetc(input) == EOF && !ferror(input));
    CHECK(fclose(input) == 0);
}

static void test_edges(void)
{
    struct uro_regs r = registers();
    struct uro_load out;
    const uint64_t max = ~(uint64_t)0;
    CHECK(uro_decode(0xf9400022U, NULL, &out) == -1);
    CHECK(uro_decode(0xf9400022U, &r, NULL) == -1);
    reject(0xf8410c21U, &r); /* LDR X1,[X1,#16]! writeback overlap. */
    reject(0xa9c10822U, &r); /* Pair duplicate destinations. */
    reject(0xa9c10c21U, &r); /* Pair base overlaps first destination. */
    reject(0xa9c10422U, &r); /* Pair base overlaps second destination. */
    reject(0x68400c22U, &r); /* Reserved non-temporal LDPSW. */
    reject(0xf8630822U, &r); /* UXTB register offset is not allowed. */
    reject(0xf8630022U, &r); /* Reserved register addressing mode. */
    reject(0xb9c00022U, &r); /* Reserved signed word to W destination. */
    reject(0xf9c00022U, &r); /* Reserved size/opc. */
    reject(0x3d800020U, &r); /* SIMD store must keep its native fault. */
    reject(0xad400020U, &r); /* LDP Q with duplicate destinations. */
    reject(0x3cc00820U, &r); /* LDTR Q unprivileged form is not supported. */
    reject(0x3c000000U, &r); /* SIMD store (STR B) must fault natively. */
    r.sp = 0x2008;
    reject(0xf94007ffU, &r);
    reject(0xa9400bffU, &r);
    r = registers();
    r.pc += 2;
    reject(0xf9400022U, &r);
    r = registers();
    r.x[3] = 0xffffffffU;
    CHECK(uro_decode(0xf863d822U, &r, &out) == 0 && out.address == 0x0ff8);
    CHECK(uro_decode(0xf8635822U, &r, &out) == 0 && out.address == 0x800000ff8ULL);
    r.x[3] = max;
    CHECK(uro_decode(0xf863f822U, &r, &out) == 0 && out.address == 0x0ff8);
    reject(0xf8637822U, &r); /* Unsigned index shift overflow. */
    r.x[3] = (uint64_t)1 << 63;
    reject(0xf863f822U, &r); /* Signed magnitude shift overflow. */
    r.x[3] = ((uint64_t)1 << 63) - 1;
    reject(0xf863f822U, &r); /* Positive SXTX shift overflow. */
    r = registers();
    r.x[1] = 0;
    reject(0xf85f802aU, &r); /* Negative immediate underflow. */
    r.x[3] = max;
    reject(0xf863f822U, &r); /* Negative register offset underflow. */
    r = registers();
    r.x[1] = max - 7;
    CHECK(uro_decode(0xf9400022U, &r, &out) == 0 && out.address == max - 7);
    reject(0xf9400422U, &r); /* Base+offset overflow. */
    reject(0xa9400c22U, &r); /* Second pair element overflows. */
    reject(0xf8410422U, &r); /* Post-index WB overflow though load fits. */
    ++r.x[1];
    reject(0xf9400022U, &r); /* Single load last byte overflows. */
    r = registers();
    r.pc = 0;
    reject(0x58ffff83U, &r);
    r.pc = max - 3;
    reject(0x18000082U, &r);
    r = registers();
    r.x[1] = 0xab00000000001000ULL;
    CHECK(uro_decode(0xf9400c24U, &r, &out) == 0 && out.address == 0xab00000000001018ULL);
    CHECK(uro_decode(0xf8410c22U, &r, &out) == 0 && out.wb == 0xab00000000001010ULL);
}

/* Random hostile words check output invariants and failure atomicity. */
static void test_random(void)
{
    unsigned i;
    uint32_t random = 0x10203040U;
    struct uro_regs r = registers();
    for (i = 0; i < 100000; ++i) {
        struct uro_load out, original;
        int result;
        random ^= random << 13;
        random ^= random >> 17;
        random ^= random << 5;
        memset(&out, 0xa5, sizeof(out));
        memcpy(&original, &out, sizeof(out));
        result = uro_decode(random, &r, &out);
        CHECK(result == 0 || result == -1);
        if (result) {
            CHECK(memcmp(&out, &original, sizeof(out)) == 0);
        } else {
            CHECK(out.count >= 1 && out.count <= 4);
            CHECK(out.size == 1 || out.size == 2 || out.size == 4 ||
                  out.size == 8 || (out.vector && out.size == 16));
            CHECK(out.dest_bits == 32 || out.dest_bits == 64 ||
                  (out.vector && out.dest_bits == out.size * 8));
            CHECK(out.rt <= 31 && out.rt2 <= 31 && out.rn <= 31);
            CHECK(out.total == (uint64_t)out.size * out.count);
            CHECK(out.address <= ~(uint64_t)0 - (out.total - 1));
            CHECK(out.vector || !out.writeback || out.rn == 31 ||
                  (out.rn != out.rt && (out.count == 1 || out.rn != out.rt2)));
        }
    }
}

int main(int argc, char **argv)
{
    CHECK(argc <= 2);
    if (argc == 2)
        verify_assembly(argv[1]);
    test_vectors();
    test_multi();
    test_edges();
    test_random();
    printf("PASS checks=%u vectors=%zu multi=%zu random=100000 independent_assembler=%s\n", checks,
           sizeof(vectors) / sizeof(vectors[0]), sizeof(multis) / sizeof(multis[0]),
           argc == 2 ? "verified" : "not_supplied");
    return 0;
}
#endif
