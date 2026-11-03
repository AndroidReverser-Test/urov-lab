/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/errno.h>
#include "urov_abi.h"

KPM_NAME(UROV_MODULE_NAME);
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("UROV-LAB");
KPM_DESCRIPTION("Self-mm A64 read overlay; requires native UROV backend and KP lifecycle v2");
KPM_CONTEXT("sleepable-v2");
static int initialized;

static int equal(const char *a, const char *b)
{
    if (!a || !b) return 0;
    while (*a && *a == *b) { ++a; ++b; }
    return *a == *b;
}
static long urov_init(const char *args, const char *event, void *reserved)
{
    (void)event; (void)reserved;
    if (args && *args) return -EINVAL;
    if (kpm_lifecycle_v2() != 2) return -EOPNOTSUPP;
    if (kp_urov_backend_v1(UROV_BACKEND_PROBE, 0, 0) != UROV_ABI_VERSION) return -EOPNOTSUPP;
    initialized = 1;
    return 0;
}
static long urov_control(const char *args, char __user *out, int len)
{
    /* The output buffer is an explicitly documented in/out binary request.
     * Native code copies it once and never keeps its address after return. */
    if (!equal(args, "request")) return -EINVAL;
    if (!out || len != sizeof(struct urov_request)) return -EINVAL;
    return kp_urov_backend_v1(UROV_BACKEND_USER, out, (unsigned long)len);
}
static long urov_exit(void *reserved)
{
    (void)reserved;
    if (!initialized) return 0;
    return kp_urov_backend_v1(UROV_BACKEND_DRAIN, 0, 0);
}
KPM_INIT(urov_init);
KPM_CTL0(urov_control);
KPM_EXIT(urov_exit);
