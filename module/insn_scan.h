/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef UROV_Z_INSN_SCAN_H
#define UROV_Z_INSN_SCAN_H

#include <stdint.h>

/* One exception-local block, never a cache across faults or mapping changes.
 * Both supported page sizes are multiples of this power-of-two block size. */
#define UZ_INSN_BLOCK_BYTES 512U
struct uz_insn_cursor {
    uint64_t first, end;
    uint32_t words[UZ_INSN_BLOCK_BYTES / 4U];
};
typedef int (*uz_insn_fetch_fn)(void *context, uint64_t pc, void *out, unsigned bytes);

static inline void uz_insn_cursor_reset(struct uz_insn_cursor *cursor)
{
    cursor->first = cursor->end = 0;
}

/* Fill only through the requested PC, then consume in reverse order. A failed
 * bulk copy may have touched the buffer: publish no part of it. Retry exactly
 * the requested word so an unreadable lower address cannot hide a nearer
 * CLREX/exception/exclusive instruction. No allocation or sleeping here. */
static inline int uz_insn_back_read(struct uz_insn_cursor *cursor, uint64_t pc,
                                    uint32_t *out, uz_insn_fetch_fn fetch, void *context)
{
    uint64_t first;
    unsigned bytes;

    if ((pc & 3U) || pc + 4U < pc) return -1;
    if (pc >= cursor->first && pc < cursor->end) {
        *out = cursor->words[(pc - cursor->first) / 4U];
        return 0;
    }
    first = pc & ~((uint64_t)UZ_INSN_BLOCK_BYTES - 1U);
    bytes = (unsigned)(pc - first) + 4U;
    uz_insn_cursor_reset(cursor);
    if (fetch(context, first, cursor->words, bytes)) {
        if (bytes == 4U || fetch(context, pc, cursor->words, 4U)) return -1;
        first = pc;
    }
    cursor->first = first;
    cursor->end = pc + 4U;
    *out = cursor->words[(pc - first) / 4U];
    return 0;
}

#endif
