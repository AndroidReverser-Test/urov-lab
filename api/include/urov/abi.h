/* SPDX-License-Identifier: GPL-2.0-or-later */
/* PAGE_AP / all-callers control ABI. See DESIGN.md for field semantics. */
#ifndef UROV_Z_ABI_H
#define UROV_Z_ABI_H

#include "auth.h"
#include <stddef.h>

#ifdef __cplusplus
#define UROV_ABI_ASSERT static_assert
#else
#define UROV_ABI_ASSERT _Static_assert
#endif

#define UROV_Z_NAME "urov-z"
#define UROV_Z_ABI_VERSION 1U
#define UROV_Z_PRCTL_MAGIC UINT64_C(0x42414c5a564f5255)
#define UROV_Z_PAGE 4096U
#define UROV_Z_PAGE_SHIFT 12U
#define UROV_Z_MAX_PAGE 16384U
#define UROV_Z_FAKE_MAX 32U

#define UROV_Z_FAKE_PAGE 4096U

#define UROV_Z_MAX_PAGES 4096U
#define UROV_Z_PAGE_DESC_SIZE 32U

enum urov_z_op {
    UROV_Z_QUERY = 1,
    UROV_Z_REGISTER = 2,
    UROV_Z_SET = 3,
    UROV_Z_STATUS = 4,
    UROV_Z_DEACTIVATE = 5,

    UROV_Z_SET_PAGE = 6,
};

enum urov_z_state {
    UROV_Z_INACTIVE = 0,
    UROV_Z_ACTIVE = 1,
};

#define UROV_Z_PAGE_SRC_USER 0x00000001U
#define UROV_Z_CAP_MULTI 0x00000001U
#define UROV_Z_CAP_LD1 0x00000002U
#define UROV_Z_CAP_LD2 0x00000004U
#define UROV_Z_CAP_LD3 0x00000008U
#define UROV_Z_CAP_LD4 0x00000010U
#define UROV_Z_CAP_CROSS 0x00000020U
#define UROV_Z_CAP_16K 0x00000080U
#define UROV_Z_CAP_PAGE_AP 0x00000400U
#define UROV_Z_CAP_REMOTE_VM 0x00000800U
#define UROV_Z_CAP_READV 0x00001000U
#define UROV_Z_CAP_GUP 0x00002000U
#define UROV_Z_CAP_STEP 0x00004000U
#define UROV_Z_CAP_FORK_SNAPSHOT 0x00008000U

#define UROV_Z_CAPS (UROV_Z_CAP_MULTI | UROV_Z_CAP_LD1 | UROV_Z_CAP_LD2 | \
                     UROV_Z_CAP_LD3 | UROV_Z_CAP_LD4 | UROV_Z_CAP_CROSS)

struct uz_page_desc {
    uint64_t base;
    uint64_t fake_addr;
    uint32_t fake_off;
    uint32_t fake_len;
    uint32_t flags;
    uint32_t reserved;
};

UROV_ABI_ASSERT(sizeof(struct uz_page_desc) == UROV_Z_PAGE_DESC_SIZE,
               "UROV-Z page descriptor size");

struct urov_z_request {
    uint32_t size;
    uint16_t version;
    uint16_t op;
    uint64_t request_id;          /* echoed client correlation value; not a nonce */
    uint64_t session;
    uint64_t address;
    uint64_t expected_generation;
    uint64_t value;
    uint32_t offset;
    uint32_t length;
    uint64_t value_hi[3];
    uint64_t generation;
    uint32_t state;
    int32_t last_error;
    uint64_t hits;
    uint64_t replays;
    uint64_t failures;
    uint64_t flags;
    uint64_t fake_addr;
    uint64_t reserved;

    uint32_t page_count;
    uint32_t page_stride;
    uint64_t pages_addr;
    uint64_t session_flags;
    uint64_t reserved2;
    uint64_t mac;
};

UROV_ABI_ASSERT(sizeof(struct urov_z_request) == 184U, "UROV-Z wire ABI");
UROV_ABI_ASSERT(offsetof(struct urov_z_request, mac) == 176U, "UROV-Z MAC offset");
#undef UROV_ABI_ASSERT
#define UROV_Z_MAC_BYTES (sizeof(struct urov_z_request) - sizeof(uint64_t))

static inline uint64_t urov_z_request_mac(const uint64_t mack[2],
                                          const struct urov_z_request *q)
{
    return uz_siphash(mack, (const uint8_t *)q, (unsigned)UROV_Z_MAC_BYTES);
}

#endif
