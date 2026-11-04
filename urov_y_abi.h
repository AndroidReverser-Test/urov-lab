/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * UROV-Y: the site-trap variant of the ARM64 user read overlay.
 *
 * Difference from UROV-X (see ELIMINATION_DESIGN.md):
 *
 *   - the protected page is NEVER made unreadable.  Every data load of it,
 *     from any PC, completes natively in EL0.  There is no data abort, no
 *     EL1 exception return and therefore no local exclusive-monitor
 *     invalidation caused by the overlay;
 *   - the fake value is delivered by trapping the *reader instruction*: the
 *     registered site's machine instruction is replaced by BRK for the
 *     session and emulated in EL1, so the page itself keeps a single
 *     consistent data view;
 *   - the trap honours an optional business-caller window (return address
 *     PC range).  A plain call of the same site routine from unrelated code
 *     is emulated with the original bytes, i.e. it returns exactly what the
 *     mapping contains.
 *
 * The wire ABI is a superset of the authenticated UROV-X channel: the prctl
 * selector words and the request MAC key are derived from a per-load secret.
 */
#ifndef UROV_Y_ABI_H
#define UROV_Y_ABI_H

#include "urov_x_abi.h"

#define UROV_Y_NAME "urov-y"
#define UROV_Y_ABI_VERSION 4U
#define UROV_Y_PAGE 4096U
#define UROV_Y_FAKE_MAX 32U
#define UROV_Y_MAX_SITES 4U
#define UROV_Y_MAX_CALLERS 4U

enum urov_y_op {
    UROV_Y_QUERY = 1,
    UROV_Y_REGISTER = 2,
    UROV_Y_SET = 3,
    UROV_Y_STATUS = 4,
    UROV_Y_DEACTIVATE = 5,
};

enum urov_y_state {
    UROV_Y_INACTIVE = 0,
    UROV_Y_ACTIVE = 1,
};

/* 240 bytes, no pointers, no implicit padding, fixed little-endian layout. */
struct urov_y_request {
    uint32_t size;
    uint16_t version;
    uint16_t op;
    uint64_t request_id;
    uint64_t session;
    uint64_t address;             /* page-aligned target page, read-only RX */
    uint64_t expected_generation;
    uint64_t value;
    uint32_t offset;              /* overlay byte offset inside the page */
    uint32_t length;              /* 8, 16, 24 or 32 (0 means 8) */
    uint64_t value_hi[3];
    uint32_t site_count;          /* 1..UROV_Y_MAX_SITES */
    uint32_t caller_count;        /* 0..UROV_Y_MAX_CALLERS */
    uint64_t sites[UROV_Y_MAX_SITES];        /* reader instruction PCs */
    uint64_t caller_start[UROV_Y_MAX_CALLERS];
    uint64_t caller_end[UROV_Y_MAX_CALLERS];
    uint64_t generation;
    uint32_t state;
    int32_t last_error;
    uint64_t hits;                /* fake-serving traps */
    uint64_t replays;             /* transparent traps (foreign caller) */
    uint64_t failures;
    uint64_t reserved;
    uint64_t mac;
};

_Static_assert(sizeof(struct urov_y_request) == 240U, "UROV-Y wire ABI");
#define UROV_Y_MAC_BYTES (sizeof(struct urov_y_request) - sizeof(uint64_t))

static inline uint64_t urov_y_request_mac(const uint64_t mack[2],
                                          const struct urov_y_request *q)
{
    return urov_x_siphash(mack, (const uint8_t *)q, (unsigned)UROV_Y_MAC_BYTES);
}

#endif
