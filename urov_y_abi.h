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
 *     consistent data view;  the second mode instead makes the site page
 *     EL0 execute-never in the leaf PTE (UXN) and emulates the instruction
 *     from an instruction abort, so the code bytes themselves are never
 *     modified and no page is ever private-dirty;  the third mode leaves
 *     the site instruction and the instruction-fetch path completely alone,
 *     clears only EL0 data permission (AP[1]) on the target page, and
 *     emulates the resulting data abort.  It additionally bridges the
 *     immediate LDXR/load/STXR pattern so an ordinary local exclusive
 *     monitor sequence still observes a successful store, matching native
 *     execution for the one side effect a synchronous read trap has; the
 *     bridge is armed only when the LDXR's result is still in its target
 *     register, so a branch that skips the LDXR leaves the STXR native and
 *     failing as it would without the module;
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
#define UROV_Y_ABI_VERSION 7U
#define UROV_Y_PAGE 4096U
#define UROV_Y_FAKE_MAX 32U
/* Largest overlay: one whole target page.  A longer function call (memcpy,
 * memcmp, strlen, a zlib pass ...) reads the registered page in chunks; every
 * chunk that lands in the window is served from this image, so the function
 * sees a consistently modified page instead of the 32-byte prefix the older
 * ABI could carry.  Requests with length > UROV_Y_FAKE_MAX must point
 * `fake_addr` at that many readable bytes; the shorter legacy form keeps using
 * value/value_hi. */
#define UROV_Y_FAKE_PAGE 4096U
#define UROV_Y_MAX_SITES 4U
#define UROV_Y_MAX_CALLERS 4U

/* How the registered reader instruction is trapped.
 *
 * SITE_BRK replaces the 4-byte instruction with BRK on a private COW page.
 * PAGE_UXN leaves every byte of the code page untouched and instead clears
 * EL0 execute permission in the leaf PTE: a fetch faults, the fault handler
 * emulates the instruction, and the page keeps one pristine data view (clean,
 * file-backed, no COW).  PAGE_UXN requires the site instruction to sit in a
 * page whose executed instruction stream is limited to the site load plus
 * RET/BR/BL/NOP/BTI.
 *
 * PAGE_AP touches neither the code page nor instruction fetch.  It clears
 * EL0 data permission (AP[1]) on the *target* page in the leaf PTE only, so
 * every EL0 data read of that page takes a permission abort while fetch of
 * the same or any other page stays native.  The data abort is emulated with
 * the same fake/caller-window rules; a directly adjacent LDXR/STXR pair is
 * completed by the handler only if the LDXR actually executed (the value it
 * loaded is still in its destination register), so the local exclusive
 * monitor sequence that noticed the older data-page trap no longer reports a
 * failed store while a branch-skipped LDXR still fails natively. */
#define UROV_Y_MODE_SITE_BRK 1U
#define UROV_Y_MODE_PAGE_UXN 2U
#define UROV_Y_MODE_PAGE_AP 3U

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

/* 256 bytes, no implicit padding, fixed little-endian layout.  `fake_addr` is
 * a plain user virtual address read by the module during REGISTER/SET, never
 * dereferenced later and never echoed back. */
struct urov_y_request {
    uint32_t size;
    uint16_t version;
    uint16_t op;
    uint64_t request_id;
    uint64_t session;
    uint64_t address;             /* page-aligned target: one page in a private
                                   * file-backed RX VMA (normal .text) or the
                                   * dedicated one-page MAP_SHARED RX alias */
    uint64_t expected_generation;
    uint64_t value;
    uint32_t offset;              /* overlay byte offset inside the page */
    uint32_t length;              /* 8..UROV_Y_FAKE_PAGE, multiple of 8 */
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
    uint32_t mode;                /* UROV_Y_MODE_*; 0 means SITE_BRK */
    uint32_t flags;               /* must be zero */
    uint64_t fake_addr;           /* overlay image, required when length > 32 */
    uint64_t reserved;            /* must be zero */
    uint64_t mac;
};

_Static_assert(sizeof(struct urov_y_request) == 256U, "UROV-Y wire ABI");
#define UROV_Y_MAC_BYTES (sizeof(struct urov_y_request) - sizeof(uint64_t))

static inline uint64_t urov_y_request_mac(const uint64_t mack[2],
                                          const struct urov_y_request *q)
{
    return urov_x_siphash(mack, (const uint8_t *)q, (unsigned)UROV_Y_MAC_BYTES);
}

#endif
