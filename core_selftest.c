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

int uro_core_selftest(uint8_t *page, unsigned *checks)
{
    struct uro_view v = { page, 0x10000, UINT64_C(1) << 48, 64 };
    struct uro_regs r = { { 0 }, 0x10040, 0x20000, UINT64_C(0xa0000000) };
    struct uro_regs before;
    unsigned i;
    const uint64_t fake = UINT64_C(0x8877665544332211);
    if (!page || !checks) return __LINE__;
    *checks = 0;
#define CHECK(x) do { ++*checks; if (!(x)) return __LINE__; } while (0)
    for (i = 0; i < URO_PAGE_SIZE; ++i) page[i] = (uint8_t)(i * 17U + 3U);
    r.x[0] = 0x10040;
    copy_regs(&before, &r);
    CHECK(uro_emulate(&v, 0xf9400002U, URO_READ_ESR, r.x[0], fake, &r) == URO_OK);
    CHECK(r.x[2] == fake && r.pc == before.pc + 4 && r.pstate == before.pstate);
    copy_regs(&r, &before);
    CHECK(uro_emulate(&v, 0x39c00002U, URO_READ_ESR, r.x[0], 0x80, &r) == URO_OK);
    CHECK(r.x[2] == UINT64_C(0xffffff80));
    copy_regs(&r, &before);
    CHECK(uro_emulate(&v, 0x39800002U, URO_READ_ESR, r.x[0], 0x80, &r) == URO_OK);
    CHECK(r.x[2] == UINT64_C(0xffffffffffffff80));
    copy_regs(&r, &before);
    r.x[0] -= 8;
    CHECK(uro_emulate(&v, 0xa9400c02U, URO_READ_ESR, 0x10040, fake, &r) == URO_OK);
    CHECK(r.x[3] == fake);
    copy_regs(&r, &before);
    CHECK(uro_emulate(&v, 0xf8408402U, URO_READ_ESR, r.x[0], fake, &r) == URO_OK);
    CHECK(r.x[0] == 0x10048 && r.x[2] == fake);
    copy_regs(&r, &before);
    CHECK(uro_emulate(&v, 0xf9000002U, URO_READ_ESR, r.x[0], fake, &r) == URO_UNSUPPORTED);
    CHECK(same_regs(&r, &before));
    CHECK(uro_emulate(&v, 0xf9400002U, URO_READ_ESR, 0x10050, fake, &r) == URO_BAD_FAR);
    CHECK(same_regs(&r, &before));
    CHECK(uro_emulate(&v, 0xf9400002U, URO_READ_ESR | 64U, r.x[0], fake, &r) == URO_NOT_MINE);
    CHECK(same_regs(&r, &before));
    r.x[0] = 0x10ffc;
    copy_regs(&before, &r);
    CHECK(uro_emulate(&v, 0xf9400002U, URO_READ_ESR, r.x[0], fake, &r) == URO_BAD_RANGE);
    CHECK(same_regs(&r, &before));
    for (i = 0; i < URO_PAGE_SIZE; ++i) CHECK(page[i] == (uint8_t)(i * 17U + 3U));
#undef CHECK
    return 0;
}
