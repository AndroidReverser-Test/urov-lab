/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef UROV_Z_PT_ACCESS_H
#define UROV_Z_PT_ACCESS_H

/* Included by backend.c after its MM accessors. No PTE pointer escapes a
 * guard: mmap protection pins the upper tables, and the native helper pins
 * and locks the PTE table. Prefer the complete apply callback on every
 * kernel: it also balances RCU, lockdep and RT locks on newer kernels. */
#include "pt_leaf.h"
#include "mapping_identity.h"
typedef int (*uz_pte_fn)(uint64_t *, unsigned long, void *);
static int (*f_apply_pt)(void *, unsigned long, unsigned long, uz_pte_fn, void *);
static uint64_t *(*f_map_pt_lock)(void *, uint64_t *, unsigned long, void **);
static void (*f_pt_unlock)(void *);
static int (*f_mmap_tryread)(void *);
static _Bool (*f_mmap_tryread_bool)(void *);
static int g_apply_pt_create;
static unsigned g_pt_levels;
static uint64_t g_linear_offset;
static void *g_mmap_writer, *g_mmap_writer_mm;

/* User PGDs on arm64 come from the page/slab allocator, hence the linear
 * map. Translate this known allocation once instead of depending on a
 * KernelPatch-private linear_voffset export. Preserve per-CPU PAR_EL1 and
 * exclude IRQ/preemption for the AT/PAR pair. memstart_addr independently
 * checks the derived PAGE_OFFSET against supported canonical VA widths. */
static int uz_linear_init(const int64_t *memstart)
{
    void *mm = mm_of_task(current);
    uint64_t va, par, saved_par, irq, pa, origin;
    unsigned bits;
    if (!mm || !memstart) return -EOPNOTSUPP;
    va = mm_pgd(mm) | UINT64_C(0xff00000000000000);
    if (va < UINT64_C(0xffff000000000000) || (va & 7U)) return -EOPNOTSUPP;
    __asm__ volatile("mrs %0, daif; msr daifset, #2; mrs %1, par_el1; "
                     "at s1e1r, %3; isb; mrs %2, par_el1; msr par_el1, %1; msr daif, %0"
                     : "=&r"(irq), "=&r"(saved_par), "=&r"(par) : "r"(va) : "memory");
    if (par & 1U) return -EOPNOTSUPP;
    pa = (par & UINT64_C(0x0000fffffffff000)) | (va & 4095U);
    g_linear_offset = va - pa;
    origin = g_linear_offset + (uint64_t)*memstart;
    for (bits = 25; bits <= 48; ++bits)
        if (origin == (UINT64_C(0) - (UINT64_C(1) << bits))) return 0;
    g_linear_offset = 0;
    return -EOPNOTSUPP;
}

static int uz_mm_guard(void *mm)
{
    int held;
    if (__atomic_load_n(&g_mmap_writer, __ATOMIC_ACQUIRE) == current &&
        g_mmap_writer_mm == mm) return 0;
    held = f_mmap_tryread_bool ? f_mmap_tryread_bool(mm) :
                               f_mmap_tryread((char *)mm + g_layout.mmap_lock);
    if (!held) UZ_HEALTH_ADD(mmap_busy);
    return held ? 1 : -EAGAIN;
}

static void uz_mm_unguard(void *mm, int held)
{
    if (held > 0)
        f_mmap_read_unlock(g_read_use_rwsem ? (char *)mm + g_layout.mmap_lock : mm);
}

/* A copied value profile remains usable after mmap_unlock / VMA teardown.
 * Never retain a find_vma result across a helper that may drop its lock. */
static int uz_vma_read_locked(void *mm, uint64_t address, struct uz_vma_view *out)
{
    const char *vma;
    int rc = -ENOENT;
    if (!mm) return rc;
    vma = f_find_vma(mm, (unsigned long)address);
    if (vma) {
        out->start = *(const uint64_t *)(vma + g_layout.vma_start);
        out->end = *(const uint64_t *)(vma + g_layout.vma_end);
        out->flags = *(const uint64_t *)(vma + g_layout.vma_flags);
        out->file = *(const uint64_t *)(vma + g_layout.vma_file);
        out->pgoff = g_layout.vma_pgoff_ok ? *(const uint64_t *)(vma + g_layout.vma_pgoff) : 0;
        if (address >= out->start && address < out->end) rc = 0;
    }
    return rc;
}

static int uz_vma_read(void *mm, uint64_t address, struct uz_vma_view *out)
{
    int held, rc;
    if (!mm) return -ENOENT;
    held = uz_mm_guard(mm);
    if (held < 0) return held;
    rc = uz_vma_read_locked(mm, address, out);
    uz_mm_unguard(mm, held);
    return rc;
}

/* Walk only to PMD, accepting table descriptors at every upper level. The
 * caller holds mmap protection. The kernel, not this walker, maps the PTE. */
static uint64_t *uz_pmd_slot(void *mm, uint64_t address)
{
    uint64_t *table = (uint64_t *)(uintptr_t)mm_pgd(mm);
    unsigned stride = g_page_shift - 3U, level;
    uint64_t mask = (UINT64_C(1) << stride) - 1U;
    uint64_t pa_mask = ((UINT64_C(1) << 48) - 1U) & ~((uint64_t)g_page_size - 1U);

    if (!table || g_pt_levels < 2 || g_pt_levels > 4) return 0;
    for (level = g_pt_levels; level > 2; --level) {
        unsigned shift = g_page_shift + stride * (level - 1U);
        uint64_t entry = __atomic_load_n(&table[(address >> shift) & mask], __ATOMIC_ACQUIRE);
        if ((entry & PTE_TYPE_MASK) != PTE_TYPE_PAGE) return 0;
        table = (uint64_t *)(uintptr_t)((entry & pa_mask) + g_linear_offset);
    }
    return &table[(address >> (g_page_shift + stride)) & mask];
}

/* Caller holds mmap protection for both identity validation and this access.
 * A locked variant avoids recursively trying mmap_lock with a queued writer. */
static int uz_pte_access_locked(void *mm, uint64_t address, struct uz_pte_op *op)
{
    uint64_t *pmd, entry;
    int rc;

    if (!mm) return -ENOENT;
    pmd = uz_pmd_slot(mm, address);
    if (!pmd) return -ENOENT;
    entry = __atomic_load_n(pmd, __ATOMIC_ACQUIRE);
    if ((entry & PTE_TYPE_MASK) != PTE_TYPE_PAGE) return -ENOENT;
    op->result = -ENOENT;
    op->mm = mm;
    if (f_map_pt_lock) {
        void *ptl = 0;
        uint64_t *pte = f_map_pt_lock(mm, pmd, address, &ptl);
        if (!pte) return -ENOENT;
        rc = uz_pte_apply(pte, (unsigned long)address, op);
        f_pt_unlock(ptl);
        /* ARM64 has no highmem PTE mapping to unmap. The helper's RCU
         * section still needs its matching unlock on PREEMPT_RCU. */
        if (f_rcu_unlock) f_rcu_unlock();
    } else {
        /* apply-existing uses the kernel's own map-lock/unmap-unlock pair,
         * including PMD revalidation and RCU on 6.5+ and backports. For 5.4
         * the allocating helper is allowed only after the attached-PMD
         * check above, on kernels without lockless table removal. */
        rc = f_apply_pt(mm, (unsigned long)address, g_page_size, uz_pte_apply, op);
        if (rc >= 0) rc = op->result;
    }
    return rc;
}

static int uz_pte_access(void *mm, uint64_t address, struct uz_pte_op *op)
{
    int held, rc;
    if (!mm) return -ENOENT;
    held = uz_mm_guard(mm);
    if (held < 0) return held;
    rc = uz_pte_access_locked(mm, address, op);
    uz_mm_unguard(mm, held);
    return rc;
}

static int uz_pte_read(void *mm, uint64_t address, uint64_t *value)
{
    struct uz_pte_op op = {0};
    int rc = uz_pte_access(mm, address, &op);
    if (!rc) *value = op.value;
    return rc;
}

#endif
