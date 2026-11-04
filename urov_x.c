/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Loadable entry points for UROV-X, the covert read-overlay variant.
 *
 * Load with a secret that the client shares out of band:
 *   kpm load urov-x.kpm "key=<32 hex digits>"
 *
 * The module derives the prctl selector words and the request MAC key from the
 * secret, installs an EL0 data-abort hook and silently ignores every control
 * request that does not carry a valid MAC.
 */
#include <compiler.h>
#include <kallsyms.h>
#include <kpmodule.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include "urov_x_abi.h"
#include "urov_x_backend.h"

KPM_NAME("urov-x");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("UROV-X");
KPM_DESCRIPTION("Read-site-bound ARM64 user read overlay with an authenticated, covert control channel");
KPM_INFO(context, "sleepable-v2", 32);

typedef long (*copy_fn)(void *, const void *, unsigned long);
static copy_fn copy_out;

static int str_eq(const char *a, const char *b)
{
    if (!a || !b) return 0;
    while (*a && *a == *b) { ++a; ++b; }
    return *a == *b;
}

static long urov_x_init(const char *args, const char *event, void *reserved)
{
    (void)event;
    (void)reserved;
    if (!kallsyms_lookup_name) return -ENOSYS;
    copy_out = (copy_fn)kallsyms_lookup_name("copy_to_user_nofault");
    if (!copy_out) return -EOPNOTSUPP;
    return urov_x_backend_init(args);
}

static long urov_x_control(const char *args, char __user *out, int len)
{
    struct ux_status st;
    char message[192];
    int n;

    if (!out || len < 1) return -EINVAL;
    if (!str_eq(args, "status") && !str_eq(args, "selftest")) return -EINVAL;
    urov_x_status_get(&st);
    n = snprintf(message, sizeof(message),
                 "mode=site-bound state=%s sites=%u hits=%llu failures=%llu hooks=0x%x core_checks=%u\n",
                 st.active ? "active" : "inactive", st.sites,
                 (unsigned long long)st.hits, (unsigned long long)st.failures,
                 st.hooks, st.core_checks);
    if (n < 0 || n >= (int)sizeof(message)) return -EOVERFLOW;
    if (len <= n) return -ENOSPC;
    return copy_out(out, message, (size_t)n + 1) ? -EFAULT : 0;
}

static long urov_x_exit(void *reserved)
{
    (void)reserved;
    return urov_x_backend_exit();
}

KPM_INIT(urov_x_init);
KPM_CTL0(urov_x_control);
KPM_EXIT(urov_x_exit);
