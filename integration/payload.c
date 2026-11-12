/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "shared.h"
#include <urov/urov.h>
#include <dobby.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

static struct test_context *ctx;
static struct urov_client client;
static int (*original)(int, int);
static void *page;
static unsigned char *snapshot;
static size_t page_size;

static int replacement(int a, int b)
{
    int result = original(a + 10, b * 3);
    ctx->original_result = result;
    return result + 1000;
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
        }
        return rc;
    case HOOK:
        if (ctx->hooked || ctx->overlaid) return -EBUSY;
        snapshot = malloc(page_size);
        if (!snapshot) return -ENOMEM;
        memcpy(snapshot, page, page_size);
        /* A far LDR-literal jump reads its destination out of the covered
         * page and would receive the original bytes too. Force a B immediate
         * to Dobby's nearby forwarding trampoline outside this page. */
        dobby_set_near_trampoline(true);
        rc = DobbyHook((void *)ctx->target, (void *)replacement, (void **)&original);
        if (rc) { free(snapshot); snapshot = NULL; return rc; }
        uint32_t first;
        memcpy(&first, (const void *)ctx->target, sizeof(first));
        if ((first & 0xfc000000U) != 0x14000000U) {
            DobbyDestroy((void *)ctx->target);
            free(snapshot);
            snapshot = NULL;
            return -EOPNOTSUPP;
        }
        ctx->hooked = 1;
        /* A hook must have changed real text, independent of return checks. */
        return memcmp(snapshot, page, page_size) ? 0 : -EIO;
    case OVERLAY: {
        if (!ctx->hooked || ctx->overlaid || !snapshot) return -EINVAL;
        struct urov_page descriptor = {page, snapshot, 0, (uint32_t)page_size};
        rc = urov_register_pages(&client, &descriptor, 1, &st);
        if (!rc) ctx->overlaid = 1;
        return rc;
    }
    case DEACTIVATE:
        rc = urov_deactivate(&client);
        if (!rc) ctx->overlaid = 0;
        return rc;
    case UNHOOK:
        if (ctx->overlaid) return -EBUSY;
        if (!ctx->hooked) return 0;
        rc = DobbyDestroy((void *)ctx->target);
        if (!rc) {
            ctx->hooked = 0;
            free(snapshot);
            snapshot = NULL;
        }
        return rc;
    default: return -EINVAL;
    }
}

__attribute__((constructor)) static void payload_init(void)
{
    ctx = test_find_context();
    if (!ctx || ctx->action) return;
    int rc = urov_client_init(&client, ctx->key);
    if (rc) return;
    page_size = (size_t)sysconf(_SC_PAGESIZE);
    if ((page_size != 4096 && page_size != 16384) ||
        ((uintptr_t)ctx->target & (page_size - 1)) + 64 > page_size) return;
    page = (void *)((uintptr_t)ctx->target & ~(page_size - 1));
    ctx->cookie = PAYLOAD_COOKIE;
    ctx->constructors++;
    /* Constructors only publish the test entry. The runner waits for KCLF
     * DONE before asking the cooperative App thread to patch/register. */
    __atomic_store_n(&ctx->action, action, __ATOMIC_RELEASE);
}
