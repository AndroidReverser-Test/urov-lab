/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "shared.h"
__attribute__((constructor)) static void probe_init(void)
{
    struct test_context *ctx = test_find_context();
    if (!ctx || !ctx->overlaid) return;
    ctx->probe_crc = ctx->direct_crc();
    ctx->probe_ok = 0;
    for (unsigned i = 0; i < TEST_TARGETS; ++i)
        if (ctx->targets[i](3 + (int)i, 4 + 2 * (int)i) == test_expected(i, 1)) ctx->probe_ok++;
    __atomic_add_fetch(&ctx->probe_constructors, 1, __ATOMIC_RELEASE);
}
