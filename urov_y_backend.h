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
    uint32_t overlay_len; /* active overlay bytes, 0 when inactive */
    uint32_t abi;
};

/* Installs the reader-site traps (BRK, PAGE_UXN and/or PAGE_AP mode), the
 * authenticated prctl channel and the mapping lifecycle gates. The argument
 * string must contain key=<32 hex digits>; "verbose" enables printk. */
long urov_y_backend_init(const char *args);
long urov_y_backend_exit(void);
void urov_y_status_get(struct uy_status *out);
long urov_y_copy_to_user(void *dst, const void *src, unsigned long len);
/* Drop a session whose owner process is gone (sleepable control context). */
void urov_y_reap(void);

#endif
