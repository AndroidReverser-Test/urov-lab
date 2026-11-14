/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef UROV_Z_PAGE_INDEX_H
#define UROV_Z_PAGE_INDEX_H

#include <stdint.h>

struct uz_page_key {
    uint64_t base;
    uint32_t slot;
};

/* Published tables are immutable. Descriptor slots never move while readers
 * exist. The control writer builds spare, publishes it, flips/drains the old
 * reader epoch, then reuses the retired table as the next spare. */
struct uz_page_index {
    uint32_t count;
    struct uz_page_key keys[];
};

static inline void uz_index_sort(struct uz_page_index *index)
{
    uint32_t gap, i;
    for (gap = index->count / 2; gap; gap /= 2) {
        for (i = gap; i < index->count; ++i) {
            uint64_t base = index->keys[i].base;
            uint32_t slot = index->keys[i].slot, j = i;
            while (j >= gap && index->keys[j - gap].base > base) {
                index->keys[j].base = index->keys[j - gap].base;
                index->keys[j].slot = index->keys[j - gap].slot;
                j -= gap;
            }
            index->keys[j].base = base;
            index->keys[j].slot = slot;
        }
    }
}

static inline uint32_t uz_index_find(const struct uz_page_index *index, uint64_t base)
{
    uint32_t lo = 0, hi = index ? index->count : 0;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (base < index->keys[mid].base) hi = mid;
        else if (base > index->keys[mid].base) lo = mid + 1;
        else return index->keys[mid].slot;
    }
    return ~(uint32_t)0;
}

static inline struct uz_page_index *uz_index_publish(struct uz_page_index **published,
                                                      struct uz_page_index *next)
{
    return __atomic_exchange_n(published, next, __ATOMIC_ACQ_REL);
}

#endif
