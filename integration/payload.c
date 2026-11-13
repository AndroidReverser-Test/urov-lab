/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "shared.h"
#include <urov/urov.h>
#include <dobby.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
static struct test_context *ctx;
static struct urov_client client;
static test_target original[TEST_TARGETS];
static void *pages[TEST_TARGETS];
static unsigned char *snapshots;
static size_t page_size;
static unsigned installed;
#define REPLACEMENT(i) static int replacement_##i(int a, int b) { \
    int result = original[i](a + 10, b * 3); \
    __atomic_store_n(&ctx->original_result[i], result, __ATOMIC_RELAXED); \
    return result + 1000; }
REPLACEMENT(0) REPLACEMENT(1) REPLACEMENT(2) REPLACEMENT(3) REPLACEMENT(4)
REPLACEMENT(5) REPLACEMENT(6) REPLACEMENT(7) REPLACEMENT(8) REPLACEMENT(9)
static const test_target replacements[TEST_TARGETS] = {
    replacement_0, replacement_1, replacement_2, replacement_3, replacement_4,
    replacement_5, replacement_6, replacement_7, replacement_8, replacement_9
};
static int unhook(void)
{
    int failure = 0;
    for (int i = TEST_TARGETS - 1; i >= 0; --i) {
        if (!(installed & (1U << i))) continue;
        int rc = DobbyDestroy((void *)ctx->targets[i]);
        if (rc) { failure = rc; continue; }
        installed &= ~(1U << i);
    }
    ctx->hooked = __builtin_popcount(installed);
    if (!installed) { free(snapshots); snapshots = NULL; }
    return failure;
}
static int action(int command)
{
    struct urov_status st;
    int rc;
    switch (command) {
    case INSPECT:
        rc = urov_get_status(&client, &st);
        if (!rc) {
            ctx->overlay_hits = st.hits;
            ctx->overlay_failures = st.failures;
            ctx->armed = st.armed_pages;
            ctx->registered_pages = st.page_count;
            ctx->overlaid = st.state == UROV_Z_ACTIVE;
        }
        return rc;
    case HOOK:
        if (installed || ctx->overlaid) return -EBUSY;
        snapshots = malloc(TEST_TARGETS * page_size);
        if (!snapshots) return -ENOMEM;
        /* Snapshot ALL pages before the first Dobby mutation. */
        for (unsigned i = 0; i < TEST_TARGETS; ++i)
            memcpy(snapshots + i * page_size, pages[i], page_size);
        dobby_set_near_trampoline(true);
        for (unsigned i = 0; i < TEST_TARGETS; ++i) {
            rc = DobbyHook((void *)ctx->targets[i], (void *)replacements[i], (void **)&original[i]);
            if (rc) { int rollback = unhook(); return rollback ? rollback : rc; }
            installed |= 1U << i;
            ctx->hooked = __builtin_popcount(installed);
            uint32_t first;
            memcpy(&first, (void *)ctx->targets[i], sizeof(first));
            if ((first & 0xfc000000U) != 0x14000000U ||
                !memcmp(snapshots + i * page_size, pages[i], page_size)) {
                int rollback = unhook();
                return rollback ? rollback : -EOPNOTSUPP;
            }
            /* The forwarding trampoline must be outside EVERY covered page. */
            intptr_t delta = (intptr_t)((int32_t)(first << 6) >> 4);
            uintptr_t destination = (uintptr_t)ctx->targets[i] + delta;
            for (unsigned j = 0; j < TEST_TARGETS; ++j) {
                if ((destination & ~(page_size - 1)) == (uintptr_t)pages[j]) {
                    int rollback = unhook();
                    return rollback ? rollback : -EOPNOTSUPP;
                }
            }
        }
        return 0;
    case OVERLAY: {
        if (ctx->hooked != TEST_TARGETS || ctx->overlaid || !snapshots) return -EINVAL;
        struct urov_page descriptors[TEST_TARGETS];
        for (unsigned i = 0; i < TEST_TARGETS; ++i)
            descriptors[i] = (struct urov_page){pages[i], snapshots + i * page_size, 0, (uint32_t)page_size};
        rc = urov_register_pages(&client, descriptors, TEST_TARGETS, &st);
        if (!rc) ctx->overlaid = 1;
        /* Copy-out errors can follow a committed operation. Reconcile before
         * cleanup, and do not unhook if the registration outcome is unknown. */
        int inspect_rc = action(INSPECT);
        if (inspect_rc) ctx->overlaid = 1;
        return rc ? rc : inspect_rc;
    }
    case DEACTIVATE:
        rc = urov_deactivate(&client);
        if (!rc) ctx->overlaid = 0;
        return rc;
    case UNHOOK:
        if (ctx->overlaid) return -EBUSY;
        return unhook();
    default: return -EINVAL;
    }
}
__attribute__((constructor)) static void payload_init(void)
{
    ctx = test_find_context();
    if (!ctx || __atomic_load_n(&ctx->action, __ATOMIC_ACQUIRE)) return;
    if (urov_client_init(&client, UROV_TEST_KEY)) return;
    page_size = (size_t)sysconf(_SC_PAGESIZE);
    if (page_size != 4096 && page_size != 16384) return;
    for (unsigned i = 0; i < TEST_TARGETS; ++i) {
        uintptr_t address = (uintptr_t)ctx->targets[i];
        if ((address & (page_size - 1)) + 64 > page_size) return;
        pages[i] = (void *)(address & ~(page_size - 1));
        for (unsigned j = 0; j < i; ++j) if (pages[i] == pages[j]) return;
    }
    ctx->cookie = PAYLOAD_COOKIE;
    ctx->constructors++;
    __atomic_store_n(&ctx->action, action, __ATOMIC_RELEASE);
}
