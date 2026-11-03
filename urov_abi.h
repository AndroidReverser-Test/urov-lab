/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef UROV_ABI_H
#define UROV_ABI_H

/* No pointers, longs, implicit padding, or build-specific kernel types. */
#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

#define UROV_ABI_VERSION 1U
#define UROV_PAGE_BYTES 4096U
#define UROV_MODULE_NAME "urov-lab"
#define UROV_F_RAW_XOM 1ULL
#define UROV_CAP_GPR 1ULL
#define UROV_CAP_PAIR 2ULL
#define UROV_CAP_MM_GATES 4ULL
#define UROV_CAP_EPAN 8ULL
#define UROV_CAP_RAW_XOM 16ULL
#define UROV_CAP_READY 32ULL

enum urov_op { UROV_QUERY = 1, UROV_REGISTER, UROV_SET, UROV_STATUS, UROV_DEACTIVATE };
enum urov_state { UROV_INACTIVE, UROV_ACTIVE, UROV_RETAINED };
enum urov_backend_call { UROV_BACKEND_PROBE, UROV_BACKEND_USER, UROV_BACKEND_DRAIN };

struct urov_request {
    uint32_t size;
    uint16_t version, op;
    uint64_t flags, request_id, session, address, expected_generation, value;
    uint32_t offset, reserved0;
    uint64_t caps, generation, hits, failures;
    uint32_t state;
    int32_t last_error;
    uint64_t reserved[3];
};
_Static_assert(sizeof(struct urov_request) == 128, "UROV wire ABI");

/* Permanent KP v2 bridge; KPMs must import both symbols strongly. */
unsigned int kpm_lifecycle_v2(void);
long kp_urov_backend_v1(unsigned int call, void *request, unsigned long size);
long urov_backend_v1(unsigned int call, void *request, unsigned long size);
#endif
