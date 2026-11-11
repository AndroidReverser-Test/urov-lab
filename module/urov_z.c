/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include "abi.h"
#include "backend.h"

KPM_NAME("urov-z");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("UROV-Z");
KPM_DESCRIPTION("ARM64 PAGE_AP all-callers code-page read overlay");
KPM_INFO(context, "sleepable-v2", 32);

static long module_init(const char *args, const char *event, void *reserved)
{
    (void)event;
    (void)reserved;
    return urov_z_backend_init(args);
}

static long module_control(const char *args, char __user *out, int len)
{
    struct uz_status st;
    char message[320];
    int n;
    long ret;

    if (!args || (strcmp(args, "status") && strcmp(args, "selftest"))) return -EINVAL;
    if (!out || len < 1) return -EINVAL;
    ret = urov_z_status_get(&st);
    if (ret) return ret;
    n = snprintf(message, sizeof(message),
        "mode=PAGE_AP callers=all state=%s pages=%u armed=%u hits=%llu "
        "replays=%llu failures=%llu llsc=%llu degraded=%u hooks=0x%x "
        "core_checks=%u abi=%u fpsimd=%u shift=%u caps=0x%x\n",
        st.active ? "active" : "inactive", st.page_count, st.armed,
        (unsigned long long)st.hits, (unsigned long long)st.replays,
        (unsigned long long)st.failures, (unsigned long long)st.llsc,
        st.degraded, st.hooks, st.core_checks, st.abi, st.fpsimd, st.page_shift, st.caps);
    if (n < 0 || n >= (int)sizeof(message)) return -EOVERFLOW;
    if (len <= n) return -ENOSPC;
    return urov_z_copy_to_user(out, message, (unsigned long)n + 1);
}

static long module_exit(void *reserved)
{
    (void)reserved;
    return urov_z_backend_exit();
}

KPM_INIT(module_init);
KPM_CTL0(module_control);
KPM_EXIT(module_exit);
