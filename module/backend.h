/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef UROV_Z_BACKEND_H
#define UROV_Z_BACKEND_H

#include "abi.h"

struct uz_status {
    uint64_t hits;
    uint64_t replays;
    uint64_t failures;
    uint64_t llsc;
    uint32_t active;
    uint32_t armed;
    uint32_t hooks;
    uint32_t core_checks;
    uint32_t degraded;
    uint32_t fpsimd;      /* native FPSIMD helpers available */
    uint32_t overlay_len; /* page-0 overlay bytes, 0 when inactive */
    uint32_t abi;
    uint32_t page_count;  /* pages in the active session */
    uint32_t page_shift;  /* base page shift (12 or 14) */
    uint32_t caps;        /* UROV_Z_CAP_* */
};

/* Installs the PAGE_AP data-abort path and authenticated control channel.
 * Required argument: key=<32 hex digits>. Optional: verbose, max_pages=N,
 * max_kb=N, btf=/absolute/path/to/exact-build.uzbtf. */
long urov_z_backend_init(const char *args);
long urov_z_backend_exit(void);
long urov_z_status_get(struct uz_status *out);
long urov_z_copy_to_user(void *dst, const void *src, unsigned long len);

#endif
