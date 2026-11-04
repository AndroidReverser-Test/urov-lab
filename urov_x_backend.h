/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef UROV_X_BACKEND_H
#define UROV_X_BACKEND_H

#include "urov_x_abi.h"

struct ux_status {
    uint64_t hits;
    uint64_t failures;
    uint32_t active;
    uint32_t sites;
    uint32_t hooks;
    uint32_t core_checks;
};

/* Installs the EL0 data-abort hook and the authenticated prctl channel. The
 * argument string must contain key=<32 hex digits>; "verbose" enables printk. */
long urov_x_backend_init(const char *args);
long urov_x_backend_exit(void);
void urov_x_status_get(struct ux_status *out);

#endif
