/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef UY_FIXTURE_CONTROL_H
#define UY_FIXTURE_CONTROL_H

#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "../../urov_y_abi.h"

struct uy_ctx {
    struct urov_x_keys keys;
};

static inline int uy_init_key(struct uy_ctx *ctx, const char *hex)
{
    uint8_t key[16];
    unsigned len = hex ? (unsigned)strlen(hex) : 0U;
    memset(ctx, 0, sizeof(*ctx));
    if (urov_x_parse_key(hex, len, key)) return -1;
    urov_x_derive(key, &ctx->keys);
    memset(key, 0, sizeof(key));
    return 0;
}

static inline struct urov_y_request uy_req(unsigned op)
{
    struct urov_y_request q;
    memset(&q, 0, sizeof(q));
    q.size = (uint32_t)sizeof(q);
    q.version = UROV_Y_ABI_VERSION;
    q.op = (uint16_t)op;
    q.request_id = UINT64_C(0x55524f56594c4142);
    return q;
}

static inline long uy_control(const struct uy_ctx *ctx, unsigned op, struct urov_y_request *q)
{
    q->size = (uint32_t)sizeof(*q);
    q->version = UROV_Y_ABI_VERSION;
    q->op = (uint16_t)op;
    q->mac = urov_y_request_mac(ctx->keys.mac, q);
    return syscall(__NR_prctl, (long)ctx->keys.option, (long)UROV_Y_PRCTL_MAGIC,
                   (long)op, q, (long)sizeof(*q));
}

static inline int uy_register_pages(const struct uy_ctx *ctx, const struct uy_page_desc *desc,
                                    uint32_t count, uint64_t caller_start, uint64_t caller_end,
                                    struct urov_y_request *out)
{
    struct urov_y_request q = uy_req(UROV_Y_REGISTER);
    q.mode = UROV_Y_MODE_PAGE_AP;
    q.page_count = count;
    q.page_stride = (uint32_t)sizeof(*desc);
    q.pages_addr = (uintptr_t)desc;
    q.caller_count = caller_start ? 1 : 0;
    q.caller_start[0] = caller_start;
    q.caller_end[0] = caller_end;
    int rc = (int)uy_control(ctx, UROV_Y_REGISTER, &q);
    *out = q;
    return rc;
}

static inline int uy_deactivate(const struct uy_ctx *ctx)
{
    struct urov_y_request q = uy_req(UROV_Y_DEACTIVATE);
    q.session = 1;
    return (int)uy_control(ctx, UROV_Y_DEACTIVATE, &q);
}

#endif
