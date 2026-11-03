/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef UROV_ABI_H
#define UROV_ABI_H

/* No pointers, longs, implicit padding, or build-specific kernel types. */
#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

#define UROV_ABI_VERSION 2U
#define UROV_PAGE_BYTES 4096U
#define UROV_FAKE_MAX 32U
#define UROV_MODULE_NAME "urov-lab"

/* Control channel: the standalone KPM hooks this syscall. A request is
 *   long r = syscall(UROV_NOTIFY_NR, (long)UROV_NOTIFY_MAGIC,
 *                    (long)cmd, &request, (long)sizeof(request));
 * with cmd == request.op. Real kcmp callers do not carry the magic and are
 * forwarded to the native handler unchanged.
 *
 *   QUERY      report caps/state/session/generation
 *   REGISTER   register the caller's page-aligned sealed RX page:
 *              address, offset (overlay byte offset in the page),
 *              length (8/16/24/32, 0 means the legacy 8) and up to 32 fake
 *              bytes in value/value_hi[]
 *   SET        publish new fake bytes of the session's registered length;
 *              session, length and expected_generation must match
 *   STATUS     report generation, hits, failures, length and the current
 *              fake bytes
 *   DEACTIVATE restore the page and release the session (idempotent)
 *
 * Fake bytes are little-endian: value holds bytes 0..7, value_hi[0] bytes
 * 8..15, value_hi[1] bytes 16..23 and value_hi[2] bytes 24..31.
 * The fault path rewrites only general-purpose register loads; writes and
 * unsupported instructions keep failing closed with SIGSEGV. */
#define UROV_NOTIFY_NR 272
#define UROV_NOTIFY_MAGIC 0x55524f5653595343ULL /* "UROVSYSC" */
enum urov_notify_cmd {
    UROV_NOTIFY_QUERY = 1,
    UROV_NOTIFY_REGISTER = 2,
    UROV_NOTIFY_SET = 3,
    UROV_NOTIFY_STATUS = 4,
    UROV_NOTIFY_DEACTIVATE = 5,
};
#define UROV_F_RAW_XOM 1ULL
#define UROV_CAP_GPR 1ULL
#define UROV_CAP_PAIR 2ULL
#define UROV_CAP_MM_GATES 4ULL
#define UROV_CAP_EPAN 8ULL
#define UROV_CAP_RAW_XOM 16ULL
#define UROV_CAP_READY 32ULL
#define UROV_CAP_TASK_WORK 64ULL
#define UROV_CAP_RESIDENT 128ULL
#define UROV_CAP_MODEL_CORE 256ULL
#define UROV_CAP_FAKE16 512ULL
#define UROV_CAP_FAKE32 1024ULL

enum urov_op { UROV_QUERY = 1, UROV_REGISTER, UROV_SET, UROV_STATUS, UROV_DEACTIVATE };
enum urov_state { UROV_INACTIVE, UROV_ACTIVE, UROV_RETAINED };
enum urov_backend_call { UROV_BACKEND_PROBE, UROV_BACKEND_USER, UROV_BACKEND_DRAIN };

struct urov_request {
    uint32_t size;
    uint16_t version, op;
    uint64_t flags, request_id, session, address, expected_generation, value;
    uint32_t offset;
    union {
        uint32_t length;    /* fake byte count: 0 (= 8 legacy), 8, 16, 24, 32 */
        uint32_t reserved0; /* historical name; zero is the legacy encoding */
    };
    uint64_t caps, generation, hits, failures;
    uint32_t state;
    int32_t last_error;
    union {
        uint64_t value_hi[3]; /* fake bytes 8..15, 16..23, 24..31 */
        uint64_t reserved[3]; /* historical zero-check view of the same bytes */
    };
};
_Static_assert(sizeof(struct urov_request) == 128, "UROV wire ABI");

/* Proposed deferred-control envelope exercised by tests/resident_model.c.
 * The shipped ctl0 continues to use the 128-byte urov_request above. */
#define UROV_COMPLETED 0x55524f56U
struct urov_submit {
    struct urov_request request;
    int32_t result;
    uint32_t completed;
};
_Static_assert(sizeof(struct urov_submit) == 136, "UROV standalone envelope");

/* Historical built-in backend interface; not imported by standalone KPM. */
unsigned int kpm_lifecycle_v2(void);
long kp_urov_backend_v1(unsigned int call, void *request, unsigned long size);
long urov_backend_v1(unsigned int call, void *request, unsigned long size);
#endif
