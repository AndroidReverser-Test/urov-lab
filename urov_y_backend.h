/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef UROV_Y_BACKEND_H
#define UROV_Y_BACKEND_H

#include "urov_y_abi.h"

struct uy_status {
    uint64_t hits;
    uint64_t replays;
    uint64_t failures;
    uint64_t llsc;
    uint32_t active;
    uint32_t sites;
    uint32_t armed;
    uint32_t hooks;
    uint32_t core_checks;
    uint32_t imm;
    uint32_t mode;
    uint32_t degraded;
    uint32_t fpsimd;      /* native FPSIMD helpers available */
    uint32_t overlay_len; /* page-0 overlay bytes, 0 when inactive */
    uint32_t abi;
    uint32_t page_count;  /* pages in the active session */
    uint32_t page_shift;  /* base page shift (12 or 14) */
    uint32_t caps;        /* UROV_Y_CAP_* */
};

/* Installs the reader-site traps (BRK, PAGE_UXN and/or PAGE_AP mode), the
 * authenticated prctl channel and the mapping lifecycle gates. The argument
 * string must contain key=<32 hex digits>; "verbose" enables printk,
 * "max_pages=N" and "max_kb=N" lower the runtime quota.
 * "btf=/path" supplies detached layout data for the running build. */
long urov_y_backend_init(const char *args);
long urov_y_backend_exit(void);
long urov_y_status_get(struct uy_status *out);
long urov_y_copy_to_user(void *dst, const void *src, unsigned long len);

#endif
