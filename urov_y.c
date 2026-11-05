/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Loadable entry points for UROV-Y, the site-trap read-overlay variant.
 *
 * Load with a secret shared out of band:
 *   kpm load urov-y.kpm "key=<32 hex digits>"
 *
 * The module derives the prctl selector words, the request MAC key and the BRK
 * immediate from the secret. It installs the BRK site trap and silently ignores
 * every control request that does not carry a valid MAC.
 */
#include <compiler.h>
#include <kallsyms.h>
#include <kpmodule.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include "urov_y_abi.h"
#include "urov_y_backend.h"

KPM_NAME("urov-y");
KPM_VERSION("2.1.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("UROV-Y");
KPM_DESCRIPTION("Reader-site trap ARM64 user read overlay: BRK, UXN page trap or AP[1] data trap");
KPM_INFO(context, "sleepable-v2", 32);

typedef long (*copy_fn)(void *, const void *, unsigned long);
static copy_fn copy_out;

static int str_eq(const char *a, const char *b)
{
    if (!a || !b) return 0;
    while (*a && *a == *b) { ++a; ++b; }
    return *a == *b;
}

static long urov_y_init(const char *args, const char *event, void *reserved)
{
    (void)event;
    (void)reserved;
    if (!kallsyms_lookup_name) return -ENOSYS;
    copy_out = (copy_fn)kallsyms_lookup_name("copy_to_user_nofault");
    if (!copy_out) return -EOPNOTSUPP;
    return urov_y_backend_init(args);
}

static long urov_y_control(const char *args, char __user *out, int len)
{
    struct uy_status st;
    char message[256];
    const char *mode;
    int n;

    if (!out || len < 1) return -EINVAL;
    if (str_eq(args, "reap")) {
        urov_y_reap();
        return 0;
    }
    if (!str_eq(args, "status") && !str_eq(args, "selftest")) return -EINVAL;
    urov_y_status_get(&st);
    mode = st.mode == UROV_Y_MODE_PAGE_UXN ? "page-trap" :
           st.mode == UROV_Y_MODE_PAGE_AP ? "data-ap" : "site-trap";
    n = snprintf(message, sizeof(message),
                 "mode=%s state=%s sites=%u armed=%u hits=%llu replays=%llu "
                 "failures=%llu llsc=%llu degraded=%u imm=%x hooks=0x%x core_checks=%u\n",
                 mode, st.active ? "active" : "inactive", st.sites, st.armed,
                 (unsigned long long)st.hits, (unsigned long long)st.replays,
                 (unsigned long long)st.failures, (unsigned long long)st.llsc,
                 st.degraded, st.imm, st.hooks, st.core_checks);
    if (n < 0 || n >= (int)sizeof(message)) return -EOVERFLOW;
    if (len <= n) return -ENOSPC;
    return copy_out(out, message, (size_t)n + 1) ? -EFAULT : 0;
}

static long urov_y_exit(void *reserved)
{
    (void)reserved;
    return urov_y_backend_exit();
}

KPM_INIT(urov_y_init);
KPM_CTL0(urov_y_control);
KPM_EXIT(urov_y_exit);
