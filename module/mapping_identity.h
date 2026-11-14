/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef UROV_Z_MAPPING_IDENTITY_H
#define UROV_Z_MAPPING_IDENTITY_H

#include <stdint.h>

struct uz_vma_view { uint64_t start, end, flags, file, pgoff; };

/* Accept VMA splits/moves only when they still name the registered file
 * page. A captured fault profile must also be compared with a fresh VMA
 * under mmap protection; the captured pointer itself is never retained. */
static inline int uz_mapping_matches(const struct uz_vma_view *v, uint64_t page,
                                      unsigned shift, uint64_t file, uint64_t file_page,
                                      uint64_t original_start, uint64_t original_end,
                                      int have_pgoff)
{
    uint64_t offset, bytes;
    if (shift != 12U && shift != 14U) return 0;
    bytes = UINT64_C(1) << shift;
    if (!file || v->file != file || ((v->start | v->end) & (bytes - 1U)) ||
        page < v->start || page >= v->end ||
        (page & (bytes - 1U)) || v->end - page < bytes) return 0;
    if (!have_pgoff) return v->start == original_start && v->end == original_end;
    offset = (page - v->start) >> shift;
    return v->pgoff <= (~UINT64_C(0)) - offset && v->pgoff + offset == file_page;
}
#endif
