/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef UROV_Z_BUFFER_BUDGET_H
#define UROV_Z_BUFFER_BUDGET_H

#include <stdint.h>
#include <stddef.h>

/* All operations require the caller's short lock. Reservation precedes the
 * sleeping allocator, so simultaneous allocations cannot exceed the limit.
 * This accounts for page-rounded overlay buffers, not allocator metadata,
 * KCLF allocations or GUP references transferred to native callers. */
#define UZ_BUFFER_SLOTS 32U
struct uz_buffer_record { void *ptr; uint64_t bytes; };
struct uz_buffer_budget {
    uint64_t limit, used, peak, denied;
    struct uz_buffer_record records[UZ_BUFFER_SLOTS];
};

static inline int uz_buffer_reserve(struct uz_buffer_budget *b, uint64_t bytes,
                                     uint64_t alignment)
{
    unsigned i;
    if (!bytes || !alignment || (alignment & (alignment - 1U)) ||
        bytes > (~UINT64_C(0)) - (alignment - 1U)) goto denied;
    bytes = (bytes + alignment - 1U) & ~(alignment - 1U);
    if (b->used > b->limit || bytes > b->limit - b->used) goto denied;
    for (i = 0; i < UZ_BUFFER_SLOTS; ++i) {
        if (b->records[i].bytes) continue;
        b->records[i].bytes = bytes;
        b->records[i].ptr = NULL;
        b->used += bytes;
        if (b->peak < b->used) b->peak = b->used;
        return (int)i;
    }
denied:
    if (b->denied != (~UINT64_C(0))) ++b->denied;
    return -1;
}

static inline void uz_buffer_cancel(struct uz_buffer_budget *b, unsigned slot)
{
    if (slot >= UZ_BUFFER_SLOTS || !b->records[slot].bytes) return;
    b->used -= b->records[slot].bytes;
    b->records[slot].bytes = 0;
    b->records[slot].ptr = NULL;
}

static inline int uz_buffer_find(const struct uz_buffer_budget *b, const void *ptr)
{
    unsigned i;
    if (!ptr) return -1;
    for (i = 0; i < UZ_BUFFER_SLOTS; ++i)
        if (b->records[i].bytes && b->records[i].ptr == ptr) return (int)i;
    return -1;
}
#endif
