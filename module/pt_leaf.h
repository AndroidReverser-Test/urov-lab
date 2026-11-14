/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef UROV_Z_PT_LEAF_H
#define UROV_Z_PT_LEAF_H

/* The caller owns the native PTL for the entire operation. The standalone
 * regression supplies the same descriptor bits and a TLBI test double. */
struct uz_pte_word { uint64_t pte; };
typedef void (*uz_contpte_unfold_fn)(void *, unsigned long, uint64_t *, struct uz_pte_word);
static uz_contpte_unfold_fn f_contpte_unfold;

struct uz_pte_op {
    uint64_t set, clear, required, forbidden, value;
    uint32_t *arm;
    void *mm;
    int result, write;
};

static int uz_pte_apply(uint64_t *ptep, unsigned long address, void *data)
{
    struct uz_pte_op *op = data;
    unsigned attempt;
    int unfolded = 0;

    for (attempt = 0; attempt < 8; ++attempt) {
        uint64_t old = __atomic_load_n(ptep, __ATOMIC_ACQUIRE), next;
        if (!(old & PTE_VALID)) return op->result = -ENOENT;
        if ((old & PTE_TYPE_MASK) != PTE_TYPE_PAGE ||
            (old & (PTE_SPECIAL | PTE_DEVMAP | PTE_PROT_NONE)))
            return op->result = -EOPNOTSUPP;
        op->value = old;
        /* Read-only consumers inspect residency/AP bits, not aggregate AF or
         * dirty state. A read must not split a contiguous mapping. */
        if (!op->write) return op->result = 0;
        if ((old & op->required) != op->required || (old & op->forbidden))
            return op->result = -EOPNOTSUPP;
        next = (old | op->set) & ~op->clear;
        if (old != next && (old & PTE_CONT)) {
            /* A single-PTE CAS cannot break a contiguous group. Linux owns
             * the group size, break-before-make, TLBI and AF/dirty merging.
             * Re-read after its conversion, still under the same PTL. */
            if (!f_contpte_unfold || !op->mm || unfolded)
                return op->result = -EOPNOTSUPP;
            f_contpte_unfold(op->mm, address, ptep, (struct uz_pte_word){old});
            unfolded = 1;
            continue;
        }
        /* Publish ownership before a remote CPU can observe the trap. */
        if (op->arm) __atomic_store_n(op->arm, 1, __ATOMIC_RELEASE);
        if (old == next) return op->result = 0;
        /* Hardware AF/DBM updates do not take PTL; preserve those via CAS. */
        if (__atomic_compare_exchange_n(ptep, &old, next, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
            /* Invalidate all ASIDs before releasing PTL. */
            flush_tlb_kernel_page(address);
            return op->result = 1;
        }
    }
    return op->result = -EAGAIN;
}

#endif
