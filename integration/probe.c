/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "shared.h"
__attribute__((constructor)) static void probe_init(void)
{
    struct test_context *ctx = test_find_context();
    if (!ctx || !ctx->overlaid) return;
    ctx->probe_crc = ctx->direct_crc();
    ctx->probe_result = ctx->target(3, 4);
    ctx->probe_constructors++;
}
