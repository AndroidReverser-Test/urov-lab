/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Loadable entry points for UROV-Y, the site-trap read-overlay variant.
 *
 * Load with a secret shared out of band:
 *   kpm load urov-y.kpm "key=<32 hex digits>"
 *
 * The prctl magic is fixed. The module derives the option word, request MAC
 * key and BRK immediate from the secret and ignores requests with invalid MACs.
 */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include "urov_y_abi.h"
#include "urov_y_backend.h"

KPM_NAME("urov-y");
KPM_VERSION("2.24.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("UROV-Y");
KPM_DESCRIPTION("Reader-site trap ARM64 user read overlay: BRK, UXN or AP[1] trap; linear pre-window proof, permissive native step, paired exclusives");
KPM_INFO(context, "sleepable-v2", 32);

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
    return urov_y_backend_init(args);
}

static long urov_y_control(const char *args, char __user *out, int len)
{
    struct uy_status st;
    char message[256];
    const char *mode;
    int n;
    long ret;

    if (!out || len < 1) return -EINVAL;
    if (!str_eq(args, "status") && !str_eq(args, "selftest")) return -EINVAL;
    ret = urov_y_status_get(&st);
    if (ret) return ret;
    mode = st.mode == UROV_Y_MODE_PAGE_UXN ? "page-trap" :
           st.mode == UROV_Y_MODE_PAGE_AP ? "data-ap" : "site-trap";
    n = snprintf(message, sizeof(message),
                 "mode=%s state=%s sites=%u armed=%u hits=%llu replays=%llu "
                 "failures=%llu llsc=%llu degraded=%u imm=%x hooks=0x%x "
                 "core_checks=%u abi=%u fpsimd=%u flen=%u pages=%u shift=%u caps=0x%x\n",
                 mode, st.active ? "active" : "inactive", st.sites, st.armed,
                 (unsigned long long)st.hits, (unsigned long long)st.replays,
                 (unsigned long long)st.failures, (unsigned long long)st.llsc,
                 st.degraded, st.imm, st.hooks, st.core_checks, st.abi,
                 st.fpsimd, st.overlay_len, st.page_count, st.page_shift, st.caps);
    if (n < 0 || n >= (int)sizeof(message)) return -EOVERFLOW;
    if (len <= n) return -ENOSPC;
    return urov_y_copy_to_user(out, message, (size_t)n + 1);
}

static long urov_y_exit(void *reserved)
{
    (void)reserved;
    return urov_y_backend_exit();
}

KPM_INIT(urov_y_init);
KPM_CTL0(urov_y_control);
KPM_EXIT(urov_y_exit);

