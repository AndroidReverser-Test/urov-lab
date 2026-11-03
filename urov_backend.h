/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef UROV_BACKEND_H
#define UROV_BACKEND_H

#include "urov_abi.h"

struct urov_backend_status {
    uint64_t caps;
    uint64_t generation;
    uint64_t hits;
    uint64_t failures;
    uint32_t active;
    uint32_t hooks;
    uint32_t core_checks;
    int32_t last_error;
};

/* Installs the resident backend into the running kernel: the EL0 data-abort
 * entry hook, the notify-syscall control channel and the mapping gates. */
long urov_backend_init(const char *args);
long urov_backend_exit(void);
void urov_backend_get_status(struct urov_backend_status *out);

#endif
