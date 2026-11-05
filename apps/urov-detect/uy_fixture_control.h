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
    return syscall(__NR_prctl, (long)ctx->keys.option, (long)ctx->keys.magic,
                   (long)op, q, (long)sizeof(*q));
}

#endif
