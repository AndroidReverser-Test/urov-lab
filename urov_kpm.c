/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Loadable entry points for the standalone UROV-LAB kernel module.
 *
 * The decoder/emulator, the EL0 data-abort backend and the notify-syscall
 * control channel are all linked into this KPM (see urov_backend.c); nothing
 * outside the module has to be patched, rebuilt or loaded to use the overlay.
 */
#include <compiler.h>
#include <kallsyms.h>
#include <kpmodule.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include "urov_abi.h"
#include "urov_backend.h"

KPM_NAME(UROV_MODULE_NAME);
KPM_VERSION("2.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("UROV-LAB");
KPM_DESCRIPTION("Standalone ARM64 user read-overlay: resident fault backend and notify syscall");
KPM_INFO(context, "sleepable-v2", 32);

typedef long (*copy_fn)(void *, const void *, unsigned long);
static copy_fn copy_out;

static int str_eq(const char *a, const char *b)
{
    if (!a || !b) return 0;
    while (*a && *a == *b) { ++a; ++b; }
    return *a == *b;
}

static long urov_init(const char *args, const char *event, void *reserved)
{
    long ret;
    (void)event;
    (void)reserved;
    if (!kallsyms_lookup_name) return -ENOSYS;
    copy_out = (copy_fn)kallsyms_lookup_name("copy_to_user_nofault");
    if (!copy_out) return -EOPNOTSUPP;
    ret = urov_backend_init(args);
    return ret;
}

static long urov_control(const char *args, char __user *out, int len)
{
    struct urov_backend_status st;
    char message[256];
    int n;

    if (!out || len < 1) return -EINVAL;
    if (!str_eq(args, "status") && !str_eq(args, "selftest")) return -EINVAL;
    urov_backend_get_status(&st);
    n = snprintf(message, sizeof(message),
                 "mode=standalone-resident caps=0x%llx state=%s hooks=0x%x core_checks=%u gen=%llu hits=%llu failures=%llu notify_nr=%d notify_magic=0x%llx\n",
                 (unsigned long long)st.caps, st.active ? "active" : "inactive", st.hooks,
                 st.core_checks, (unsigned long long)st.generation,
                 (unsigned long long)st.hits, (unsigned long long)st.failures,
                 UROV_NOTIFY_NR, (unsigned long long)UROV_NOTIFY_MAGIC);
    if (n < 0 || n >= (int)sizeof(message)) return -EOVERFLOW;
    if (len <= n) return -ENOSPC;
    return copy_out(out, message, (size_t)n + 1) ? -EFAULT : 0;
}

static long urov_exit(void *reserved)
{
    (void)reserved;
    return urov_backend_exit();
}

KPM_INIT(urov_init);
KPM_CTL0(urov_control);
KPM_EXIT(urov_exit);
