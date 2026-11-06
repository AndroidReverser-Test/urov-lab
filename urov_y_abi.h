/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * UROV-Y: the site-trap variant of the ARM64 user read overlay.
 *
 * Difference from UROV-X (see ELIMINATION_DESIGN.md):
 *
 *   - SITE_BRK and PAGE_UXN trap registered reader instructions. Reads
 *     of the target page from other sites execute natively in EL0;
 *   - PAGE_AP traps data reads on the target page while its original
 *     instructions keep executing natively. Emulation changes registers,
 *     not memory, and an exception may lose the exclusive reservation;
 *   - the trap honours an optional business-caller window (return address
 *     PC range).  A plain call of the same site routine from unrelated code
 *     is emulated with the original bytes, i.e. it returns exactly what the
 *     mapping contains.
 *
 * ABI v8 adds an arbitrary-length array of page descriptors to one session.
 * Every page carries its own whole-page image, so an N-page CRC pass reads
 * the fake view of every changed page in one traversal.  PAGE_AP is the only
 * mode that accepts the array (SITE_BRK/PAGE_UXN remain one-page); the
 * multiple-structure loads (LD1/LD2/LD3/LD4) and loads that cross a page
 * boundary are served by the same PAGE_AP data-trap path. QUERY reports the
 * running base page shift; use it to size and align descriptors and images.
 *
 * The wire ABI is a superset of the authenticated UROV-X channel: the prctl
 * selector words and the request MAC key are derived from a per-load secret.
 */
#ifndef UROV_Y_ABI_H
#define UROV_Y_ABI_H

#include "urov_x_abi.h"

#define UROV_Y_NAME "urov-y"
#define UROV_Y_ABI_VERSION 8U
#define UROV_Y_PAGE 4096U /* fixed size used by older 4 KiB clients */
#define UROV_Y_PAGE_SHIFT 12U
#define UROV_Y_MAX_PAGE 16384U
#define UROV_Y_FAKE_MAX 32U
/* Largest overlay: one whole target page.  A longer function call (memcpy,
 * memcmp, strlen, a zlib pass ...) reads the registered pages in chunks; every
 * chunk that lands in an image is served from that image, so the function
 * sees a consistently modified view instead of the 32-byte prefix the older
 * ABI could carry.  Requests with length > UROV_Y_FAKE_MAX must point
 * `fake_addr` at that many readable bytes; the shorter legacy form keeps using
 * value/value_hi. UROV_Y_FAKE_PAGE is the legacy 4 KiB convenience size;
 * clients should use QUERY to learn the running page size. */
#define UROV_Y_FAKE_PAGE 4096U
#define UROV_Y_MAX_SITES 4U
#define UROV_Y_MAX_CALLERS 4U
/* Upper bound of the runtime page quota.  A load argument may lower it. */
#define UROV_Y_MAX_PAGES 4096U
#define UROV_Y_PAGE_DESC_SIZE 32U

/* How the registered reader instruction is trapped.
 *
 * SITE_BRK replaces the 4-byte instruction with BRK on a private COW page.
 * PAGE_UXN leaves every byte of the code page untouched and instead clears
 * EL0 execute permission in the leaf PTE: a fetch faults, the fault handler
 * emulates the instruction, and the page keeps one pristine data view (clean,
 * file-backed, no COW).  PAGE_UXN requires the site instruction to sit in a
 * page whose executed instruction stream is limited to the site load plus
 * RET X30, NOP and BTI hints on an unguarded page.
 *
 * PAGE_AP touches neither the code page nor instruction fetch.  It clears
 * EL0 data permission (AP[1]) on the *target* pages in the leaf PTE only, so
 * every EL0 data read of those pages takes a permission abort while fetch of
 * the same or any other page stays native.  The data abort is emulated with
 * the same fake/caller-window rules. Stores are never emulated; the exception
 * may cause a following STXR to fail. This mode supports the v8 page array,
 * LD1/LD2/LD3/LD4 and loads that cross a page boundary. */
#define UROV_Y_MODE_SITE_BRK 1U
#define UROV_Y_MODE_PAGE_UXN 2U
#define UROV_Y_MODE_PAGE_AP 3U

enum urov_y_op {
    UROV_Y_QUERY = 1,
    UROV_Y_REGISTER = 2,
    UROV_Y_SET = 3,
    UROV_Y_STATUS = 4,
    UROV_Y_DEACTIVATE = 5,
    /* v8: replace the image of one page inside an active session.  The page
     * number is carried in the low 32 bits of `reserved`; `offset`, `length`
     * and `fake_addr` describe the new SRC_USER window (length 0 or page size
     * means the whole page).  A SRC_FILE page is re-read from its backing
     * file instead and ignores the window fields. */
    UROV_Y_SET_PAGE = 6,
};

enum urov_y_state {
    UROV_Y_INACTIVE = 0,
    UROV_Y_ACTIVE = 1,
};

/* Per-page image source (struct uy_page_desc.flags).  Exactly one bit must
 * be set.  SRC_USER copies the caller's window/image; SRC_FILE reads the
 * whole page from the VMA's backing file, which is what hides an in-memory
 * inline patch behind the original file bytes. */
#define UROV_Y_PAGE_SRC_USER 0x00000001U
#define UROV_Y_PAGE_SRC_FILE 0x00000002U

/* Historical REGISTER flag. A replay snapshot is now kept for every page,
 * including for readers that race arming or restoration. */
#define UROV_Y_F_REPLAY_SNAPSHOT UINT64_C(1)

/* QUERY reports the supported subset in `session_flags`; STATUS mirrors it. */
#define UROV_Y_CAP_MULTI 0x00000001U
#define UROV_Y_CAP_LD1 0x00000002U
#define UROV_Y_CAP_LD2 0x00000004U
#define UROV_Y_CAP_LD3 0x00000008U
#define UROV_Y_CAP_LD4 0x00000010U
#define UROV_Y_CAP_CROSS 0x00000020U
#define UROV_Y_CAP_SRC_FILE 0x00000040U
#define UROV_Y_CAP_16K 0x00000080U
#define UROV_Y_CAP_SITE_BRK 0x00000100U
#define UROV_Y_CAP_PAGE_UXN 0x00000200U
#define UROV_Y_CAP_PAGE_AP 0x00000400U

#define UROV_Y_CAPS (UROV_Y_CAP_MULTI | UROV_Y_CAP_LD1 | UROV_Y_CAP_LD2 | \
                     UROV_Y_CAP_LD3 | UROV_Y_CAP_LD4 | UROV_Y_CAP_CROSS | \
                     UROV_Y_CAP_SRC_FILE)

/* One page descriptor, laid out behind `pages_addr` as an array of
 * `page_stride` bytes.  `fake_len == 0` is the whole page; otherwise the
 * window must be a multiple of 8 and fit inside the page.  SRC_USER keeps
 * `fake_addr` readable for the duration of the control call only; the module
 * copies it immediately and never dereferences it again. */
struct uy_page_desc {
    uint64_t base;       /* page-aligned user virtual address */
    uint64_t fake_addr;  /* SRC_USER image/window; 0 for SRC_FILE */
    uint32_t fake_off;   /* window offset inside the page */
    uint32_t fake_len;   /* window length; 0 == whole page */
    uint32_t flags;      /* UROV_Y_PAGE_SRC_USER / UROV_Y_PAGE_SRC_FILE */
    uint32_t reserved;   /* must be zero */
};

_Static_assert(sizeof(struct uy_page_desc) == UROV_Y_PAGE_DESC_SIZE,
               "UROV-Y page descriptor size");

/* 288 bytes, no implicit padding, fixed little-endian layout.  `fake_addr` is
 * a plain user virtual address read by the module during REGISTER/SET, never
 * dereferenced later and never echoed back.
 *
 * v7 compatibility: `page_count == 0` selects the old single-page request.
 * Its `address`, `offset`, `length`, `value`, `value_hi` and `fake_addr`
 * fields keep their v7 meaning.  v8 multi-page requests set page_count,
 * page_stride and pages_addr; `address`/`offset`/`length`/`value*` are then
 * response-only mirrors of page 0.
 *
 * Response conventions (the request side must leave these zero):
 *   QUERY:    page_count = max_pages, page_stride = page_shift,
 *             session_flags = supported UROV_Y_CAP_* bits, reserved = 0.
 *   STATUS:   page_count = registered pages, page_stride = descriptor size
 *             (page shift when inactive),
 *             reserved low 32 bits = number of pages still ARMED,
 *             session_flags = supported UROV_Y_CAP_* bits.
 *   SET_PAGE: reserved low 32 bits = target page index. */
struct urov_y_request {
    uint32_t size;
    uint16_t version;
    uint16_t op;
    uint64_t request_id;
    uint64_t session;
    uint64_t address;             /* v7: page-aligned target.  v8: ignored */
    uint64_t expected_generation;
    uint64_t value;
    uint32_t offset;              /* v7: overlay byte offset inside the page */
    uint32_t length;              /* 8..(1 << page_shift), multiple of 8 */
    uint64_t value_hi[3];
    uint32_t site_count;          /* AP mode allows 0 */
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
    uint64_t fake_addr;           /* v7: overlay image, required when length > 32 */
    uint64_t reserved;            /* v7: must be zero; SET_PAGE: page index */
    /* ---- v8 ---- */
    uint32_t page_count;          /* 1..max_pages, or 0 for the v7 form */
    uint32_t page_stride;         /* must be UROV_Y_PAGE_DESC_SIZE */
    uint64_t pages_addr;          /* user array of struct uy_page_desc */
    uint64_t session_flags;       /* UROV_Y_F_REPLAY_SNAPSHOT */
    uint64_t reserved2;           /* must be zero */
    uint64_t mac;
};

_Static_assert(sizeof(struct urov_y_request) == 288U, "UROV-Y wire ABI");
#define UROV_Y_MAC_BYTES (sizeof(struct urov_y_request) - sizeof(uint64_t))

static inline uint64_t urov_y_request_mac(const uint64_t mack[2],
                                          const struct urov_y_request *q)
{
    return urov_x_siphash(mack, (const uint8_t *)q, (unsigned)UROV_Y_MAC_BYTES);
}

#endif
