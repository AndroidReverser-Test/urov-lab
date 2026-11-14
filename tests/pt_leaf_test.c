/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* ARM64 ordinary 4K/16K leaf descriptor fixture, independent of KP headers. */
#define PTE_VALID (UINT64_C(1) << 0)
#define PTE_TYPE_MASK UINT64_C(3)
#define PTE_TYPE_PAGE UINT64_C(3)
#define PTE_USER (UINT64_C(1) << 6)
#define PTE_RDONLY (UINT64_C(1) << 7)
#define PTE_AF (UINT64_C(1) << 10)
#define PTE_DBM (UINT64_C(1) << 51)
#define PTE_CONT (UINT64_C(1) << 52)
#define PTE_UXN (UINT64_C(1) << 54)
#define PTE_DIRTY (UINT64_C(1) << 55)
#define PTE_SPECIAL (UINT64_C(1) << 56)
#define PTE_DEVMAP (UINT64_C(1) << 57)
#define PTE_PROT_NONE (UINT64_C(1) << 58)

static unsigned flushes, unfolds, nr_entries, target, shift, checks;
static int held, fail_unfold;
static uint64_t entries[128], saved[128], flush_address;
static char test_mm;
static void flush_tlb_kernel_page(uint64_t address)
{
    assert(held);
    ++flushes;
    flush_address = address;
}
#include "../module/pt_leaf.h"

#define CHECK(e) do { assert(e); ++checks; } while (0)

static void native_unfold(void *mm, unsigned long address, uint64_t *ptep, struct uz_pte_word pte)
{
    CHECK(held && mm == &test_mm && address == ((uint64_t)target << shift));
    CHECK(ptep == &entries[target] && pte.pte == *ptep && (pte.pte & PTE_CONT));
    ++unfolds;
    if (fail_unfold) return;
    /* Native BBM/flush is owned by this helper. Model its aggregate AF/dirty
     * update to catch callers that CAS a stale, pre-unfold descriptor. */
    for (unsigned i = 0; i < nr_entries; ++i)
        entries[i] = (entries[i] & ~PTE_CONT) | PTE_AF | PTE_DIRTY;
}

static void reset(unsigned page_shift)
{
    shift = page_shift;
    nr_entries = shift == 12 ? 16 : 128;
    for (unsigned i = 0; i < nr_entries; ++i)
        entries[i] = ((UINT64_C(0x800) + i) << shift) |
            PTE_TYPE_PAGE | PTE_USER | PTE_RDONLY | PTE_CONT;
    memcpy(saved, entries, sizeof(saved));
    unfolds = flushes = 0;
    held = 1;
    fail_unfold = 0;
    f_contpte_unfold = native_unfold;
}

static struct uz_pte_op arm_op(uint32_t *armed)
{
    struct uz_pte_op op = {.clear = PTE_USER, .required = PTE_USER | PTE_RDONLY,
        .forbidden = PTE_UXN | PTE_DBM, .mm = &test_mm, .arm = armed, .write = 1};
    return op;
}

int main(void)
{
    for (unsigned page_shift = 12; page_shift <= 14; page_shift += 2) {
        for (unsigned pos = 0; pos < (page_shift == 12 ? 16U : 128U); ++pos) {
            uint32_t armed = 0;
            struct uz_pte_op op = arm_op(&armed), read = {0};
            reset(page_shift);
            target = pos;
            CHECK(!uz_pte_apply(&entries[pos], (unsigned long)pos << shift, &read));
            CHECK(read.value == saved[pos] && !unfolds && !flushes);
            CHECK(uz_pte_apply(&entries[pos], (unsigned long)pos << shift, &op) == 1);
            CHECK(armed == 1 && unfolds == 1 && flushes == 1);
            CHECK(flush_address == (uint64_t)pos << shift);
            for (unsigned i = 0; i < nr_entries; ++i) {
                uint64_t expected = (saved[i] & ~PTE_CONT) | PTE_AF | PTE_DIRTY;
                if (i == pos) expected &= ~PTE_USER;
                CHECK(entries[i] == expected);
            }
            op = (struct uz_pte_op){.set = PTE_USER, .write = 1, .mm = &test_mm};
            CHECK(uz_pte_apply(&entries[pos], (unsigned long)pos << shift, &op) == 1);
            CHECK(unfolds == 1 && flushes == 2 && (entries[pos] & PTE_USER));
        }
    }
    for (unsigned mode = 0; mode < 9; ++mode) {
        uint32_t armed = 0;
        struct uz_pte_op op = arm_op(&armed);
        reset(12);
        target = 2;
        if (mode == 0) f_contpte_unfold = NULL;
        if (mode == 1) fail_unfold = 1;
        if (mode == 2) op.mm = NULL;
        if (mode == 3) entries[target] |= PTE_SPECIAL;
        if (mode == 4) entries[target] |= PTE_DEVMAP;
        if (mode == 5) entries[target] |= PTE_DBM;
        if (mode == 6) entries[target] |= PTE_UXN;
        if (mode == 7) entries[target] &= ~UINT64_C(2); /* block, not leaf */
        if (mode == 8) entries[target] &= ~PTE_RDONLY;
        uint64_t before = entries[target];
        CHECK(uz_pte_apply(&entries[target], (unsigned long)target << shift, &op) == -EOPNOTSUPP);
        CHECK(!armed && !flushes && entries[target] == before);
        CHECK(unfolds == (mode == 1 ? 1U : 0U));
    }
    {
        uint32_t armed = 0;
        struct uz_pte_op op = arm_op(&armed);
        reset(12);
        entries[0] = 0;
        CHECK(uz_pte_apply(entries, 0, &op) == -ENOENT && !armed && !flushes);
        entries[0] = saved[0] & ~PTE_CONT;
        CHECK(uz_pte_apply(entries, 0, &op) == 1 && armed && !unfolds);
        op = (struct uz_pte_op){.clear = PTE_USER, .write = 1};
        CHECK(uz_pte_apply(entries, 0, &op) == 0 && flushes == 1);
    }
    printf("PASS native PTL leaf: %u checks, 4K/16K contiguous groups, AF/dirty preservation, rejection and rollback\n", checks);
    return 0;
}
