/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include "abi.h"
#include "backend.h"
#include "kclf/embedded.h"

KPM_NAME("urov-z");
KPM_VERSION("1.2.2");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("UROV-Z");
KPM_DESCRIPTION("ARM64 code-page read overlay with integrated KCLF loader");
KPM_INFO(context, "sleepable-v2", 32);

static int overlay_started;
static int loader_started;

static long module_init(const char *args, const char *event, void *reserved)
{
    long ret;
    (void)event;
    (void)reserved;
    /* The backend shares its verified BTF and runs KCLF's fallible preflight
     * before publishing any hooks. Start overlay hooks first so subsequent
     * loader work always has its internal accessor available. */
    ret = urov_z_backend_init(args);
    if (ret) return ret;
    overlay_started = 1;
    ret = urov_kclf_init();
    if (!ret) loader_started = 1;
    /* The host invokes exit on init failure; flags also make that path safe
     * when argument validation failed before either subsystem was started. */
    return ret;
}

static long module_control(const char *args, char __user *out, int len)
{
    struct uz_status st;
    char message[640];
    int n;
    long ret;

    if (!out || len < 1) return -EINVAL;
    if (args && !strncmp(args, "kclf", 4) &&
        (!args[4] || args[4] == ',' || args[4] == ' '))
        return urov_kclf_control(args[4] ? args + 5 : "help", out, len);
    if (args && !strcmp(args, "perf")) {
        struct uz_perf perf;

        ret = urov_z_perf_get(&perf);
        if (ret) return ret;
        n = snprintf(message, sizeof(message),
            "diagnostics=%u code_valid=%u code_complete=%u loads=%llu "
            "llsc_prepares=%llu map_declines=%llu scan_calls=%llu scan_words=%llu "
            "insn_fetches=%llu insn_nofault=%llu identity_lookups=%llu "
            "identity_compares=%llu single_page=%llu cache_hits=%llu cache_misses=%llu "
            "cache_invalidations=%llu cache_bytes=%llu\n",
            perf.enabled, perf.code_valid, perf.code_complete,
            (unsigned long long)perf.loads, (unsigned long long)perf.llsc_prepares,
            (unsigned long long)perf.map_declines, (unsigned long long)perf.scan_calls,
            (unsigned long long)perf.scan_words, (unsigned long long)perf.insn_fetches,
            (unsigned long long)perf.insn_nofault, (unsigned long long)perf.identity_lookups,
            (unsigned long long)perf.identity_compares, (unsigned long long)perf.single_page,
            (unsigned long long)perf.cache_hits, (unsigned long long)perf.cache_misses,
            (unsigned long long)perf.cache_invalidations, (unsigned long long)perf.cache_bytes);
        goto copy;
    }
    if (!args || (strcmp(args, "status") && strcmp(args, "selftest"))) return -EINVAL;
    ret = urov_z_status_get(&st);
    if (ret) return ret;
    n = snprintf(message, sizeof(message),
        "mode=PAGE_AP callers=all state=%s pages=%u armed=%u hits=%llu "
        "replays=%llu failures=%llu llsc=%llu degraded=%u hooks=0x%x "
        "core_checks=%u abi=%u fpsimd=%u shift=%u caps=0x%x loader=kclf-1.5.7\n",
        st.active ? "active" : "inactive", st.page_count, st.armed,
        (unsigned long long)st.hits, (unsigned long long)st.replays,
        (unsigned long long)st.failures, (unsigned long long)st.llsc,
        st.degraded, st.hooks, st.core_checks, st.abi, st.fpsimd, st.page_shift, st.caps);
copy:
    if (n < 0 || n >= (int)sizeof(message)) return -EOVERFLOW;
    if (len <= n) return -ENOSPC;
    return urov_z_copy_to_user(out, message, (unsigned long)n + 1);
}

static long module_exit(void *reserved)
{
    long ret = 0, overlay_ret = 0;
    (void)reserved;
    if (loader_started) {
        ret = urov_kclf_exit();
        if (!ret) loader_started = 0;
    }
    /* Stock hosts free module text even on error: never skip detaching the
     * other subsystem. This is not a proof of safe trampoline retirement. */
    if (overlay_started) {
        overlay_ret = urov_z_backend_exit();
        if (!overlay_ret) overlay_started = 0;
    }
    return ret ? ret : overlay_ret;
}

KPM_INIT(module_init);
KPM_CTL0(module_control);
KPM_EXIT(module_exit);
