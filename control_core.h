/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef UROV_CONTROL_CORE_H
#define UROV_CONTROL_CORE_H

#include "urov_abi.h"

/* Caller owns storage, serializes control operations and has already
 * authenticated the caller. Only value can also be read concurrently
 * (with an acquire load). No pointer or kernel object is retained here. */
struct urov_control_record {
    uint64_t id, registration_id, address, initial_value, flags;
    uint64_t value, generation;
    uint64_t last_set_id, last_set_expected, last_set_value;
    uint32_t offset, state;
    int32_t error;
};
_Static_assert(__builtin_offsetof(struct urov_control_record, value) % 8 == 0,
               "published value must be eight-byte aligned");
_Static_assert(__alignof__(struct urov_control_record) >= 8,
               "control record requires eight-byte alignment");

enum urov_control_action {
    UROV_CTL_REPLIED = 0,
    UROV_CTL_REGISTER = 1,
    UROV_CTL_DEACTIVATE = 2
};

/* Initialize an unpublished record using the caller's new, nonzero id. */
void urov_record_begin(struct urov_control_record *r, uint64_t id, const struct urov_request *q);
void urov_record_report(struct urov_request *q, const struct urov_control_record *r,
                        uint64_t hits, uint64_t failures);

/* r == NULL means there is no published session. owner describes the
 * relationship to r; the caller supplies trusted capabilities and counters.
 * A positive result requests a platform operation, not a wire success code.
 * REGISTER still requires platform address, permission, and identity checks.
 * DEACTIVATE leaves the record intact until restoration actually succeeds. */
int urov_control_decide(struct urov_request *q, struct urov_control_record *r, int owner,
                        uint64_t caps, uint64_t hits, uint64_t failures);
int urov_control_selftest(unsigned int *checks);

#endif
