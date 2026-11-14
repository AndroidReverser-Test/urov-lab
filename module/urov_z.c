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
KPM_VERSION("1.2.5");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("UROV-Z");
KPM_DESCRIPTION("ARM64 code-page read overlay with optional KCLF loader");
KPM_INFO(context, "sleepable-v2", 32);

static int overlay_started;
#if UROV_Z_WITH_KCLF
static int loader_started;
#endif

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
#if UROV_Z_WITH_KCLF
    if (urov_z_loader_enabled()) {
        ret = urov_kclf_init();
        if (!ret) loader_started = 1;
    }
#endif
    /* The host invokes exit on init failure; flags also make that path safe
     * when argument validation failed before either subsystem was started. */
    return ret;
}

static long module_control(const char *args, char __user *out, int len)
{
    struct uz_status st;
    char message[1280];
    int n;
    long ret;

    if (!out || len < 1) return -EINVAL;
    if (args && !strncmp(args, "kclf", 4) &&
        (!args[4] || args[4] == ',' || args[4] == ' ')) {
#if UROV_Z_WITH_KCLF
        if (!loader_started) return -EOPNOTSUPP;
        return urov_kclf_control(args[4] ? args + 5 : "help", out, len);
#else
        return -EOPNOTSUPP;
#endif
    }
    if (args && !strcmp(args, "health")) {
        struct uz_health h;
        ret = urov_z_health_get(&h);
        if (ret) return ret;
        n = snprintf(message, sizeof(message),
            "mmap_busy=%llu fault_retries=%llu rearm_attempts=%llu rearm_ok=%llu "
            "rearm_busy=%llu rearm_missing=%llu rearm_rejected=%llu rearm_identity=%llu "
            "retired_writes=%llu readv_slots_full=%llu gup_alloc_failures=%llu last_rearm_error=%d\n",
            (unsigned long long)h.mmap_busy, (unsigned long long)h.fault_retries,
            (unsigned long long)h.rearm_attempts, (unsigned long long)h.rearm_ok,
            (unsigned long long)h.rearm_busy, (unsigned long long)h.rearm_missing,
            (unsigned long long)h.rearm_rejected, (unsigned long long)h.rearm_identity,
            (unsigned long long)h.retired_writes, (unsigned long long)h.readv_slots_full,
            (unsigned long long)h.gup_alloc_failures, h.last_rearm_error);
        goto copy;
    }
    if (args && !strcmp(args, "memory")) {
        struct uz_memory m;
        ret = urov_z_memory_get(&m);
        if (ret) return ret;
        n = snprintf(message, sizeof(message),
            "scope=overlay-buffers limit=%llu used=%llu peak=%llu denied=%llu "
            "page_buffers=%u fork_copies=%u shadow_slots=%u shadow_used=%u\n",
            (unsigned long long)m.limit, (unsigned long long)m.used,
            (unsigned long long)m.peak, (unsigned long long)m.denied,
            m.page_buffers, m.fork_copies, m.shadow_slots, m.shadow_used);
        goto copy;
    }
    if (args && !strcmp(args, "compat")) {
        struct uz_compat_info c;
        ret = urov_z_compat_get(&c);
        if (ret) return ret;
        n = snprintf(message, sizeof(message),
            "btf=%s fault=%s/%u remote=%s/%u fast=%s fpsimd=%s "
            "public_checks_strict=%u public_checks_fallback=%u public_checks_rejected=%u "
            "foll_btf=0x%x foll_version=0x%x foll_unavailable=0x%x "
            "GET=0x%x PIN=0x%x LONGTERM=0x%x FAST_ONLY=0x%x FORCE=0x%x loader=%u "
            "refault_atomic=0 hot_unload=0\n",
            c.btf_source, c.fault_entry, c.fault_args, c.remote_entry, c.remote_args,
            c.fast_entry, c.fp_entry, c.public_abi_strict, c.public_abi_fallback,
            c.public_abi_rejected, c.foll_btf, c.foll_version, c.foll_unavailable,
            c.foll_get, c.foll_pin, c.foll_longterm, c.foll_fast_only, c.foll_force,
            c.loader_enabled);
        goto copy;
    }
    if (args && !strcmp(args, "perf")) {
        struct uz_perf perf;

        ret = urov_z_perf_get(&perf);
        if (ret) return ret;
        n = snprintf(message, sizeof(message),
            "diagnostics=%u code_valid=%u code_complete=%u loads=%llu "
            "llsc_prepares=%llu map_declines=%llu scan_calls=%llu scan_words=%llu "
            "insn_fetches=%llu insn_nofault=%llu identity_lookups=%llu "
            "identity_compares=%llu single_page=%llu cache_hits=%llu cache_misses=%llu "
            "cache_invalidations=%llu cache_bytes=%llu "
            "image_locks=%llu image_contended=%llu image_spins=%llu "
            "image_wait_max_ticks=%llu image_hold_max_ticks=%llu clock_hz=%llu\n",
            perf.enabled, perf.code_valid, perf.code_complete,
            (unsigned long long)perf.loads, (unsigned long long)perf.llsc_prepares,
            (unsigned long long)perf.map_declines, (unsigned long long)perf.scan_calls,
            (unsigned long long)perf.scan_words, (unsigned long long)perf.insn_fetches,
            (unsigned long long)perf.insn_nofault, (unsigned long long)perf.identity_lookups,
            (unsigned long long)perf.identity_compares, (unsigned long long)perf.single_page,
            (unsigned long long)perf.cache_hits, (unsigned long long)perf.cache_misses,
            (unsigned long long)perf.cache_invalidations, (unsigned long long)perf.cache_bytes,
            (unsigned long long)perf.image_locks, (unsigned long long)perf.image_contended,
            (unsigned long long)perf.image_spins, (unsigned long long)perf.image_wait_max,
            (unsigned long long)perf.image_hold_max, (unsigned long long)perf.clock_hz);
        goto copy;
    }
    if (args && (!strncmp(args, "buffer_kb=", 10) || !strncmp(args, "fork_copies=", 12))) {
        ret = urov_z_set_resources(args);
        if (ret) return ret;
    } else if (args && !strncmp(args, "writes=", 7)) {
        if (strcmp(args + 7, "rx") && strcmp(args + 7, "experimental")) return -EINVAL;
        ret = urov_z_set_writes(!strcmp(args + 7, "experimental"));
        if (ret) return ret;
    } else if (!args || (strcmp(args, "status") && strcmp(args, "selftest"))) return -EINVAL;
    ret = urov_z_status_get(&st);
    if (ret) return ret;
    n = snprintf(message, sizeof(message),
        "mode=PAGE_AP callers=all writes=%s ptl=%s contpte=%u readv_refs=%s state=%s pages=%u armed=%u hits=%llu "
        "replays=%llu failures=%llu llsc=%llu degraded=%u hooks=0x%x "
        "core_checks=%u abi=%u fpsimd=%u shift=%u caps=0x%x loader=%s\n",
        st.experimental_writes ? "experimental" : "rx",
        st.native_ptl == 2 ? "map-lock-rcu" : st.native_ptl == 3 ? "apply-checked" : "apply-existing",
        st.contpte, st.readv_refs == 2 ? "PIN" : st.readv_refs == 1 ? "GET" : "none",
        st.active ? "active" : "inactive", st.page_count, st.armed,
        (unsigned long long)st.hits, (unsigned long long)st.replays,
        (unsigned long long)st.failures, (unsigned long long)st.llsc,
        st.degraded, st.hooks, st.core_checks, st.abi, st.fpsimd, st.page_shift, st.caps,
        st.loader_enabled ? "kclf-1.5.7" : "off");
copy:
    if (n < 0 || n >= (int)sizeof(message)) return -EOVERFLOW;
    if (len <= n) return -ENOSPC;
    return urov_z_copy_to_user(out, message, (unsigned long)n + 1);
}

static long module_exit(void *reserved)
{
    long ret = 0, overlay_ret = 0;
    (void)reserved;
#if UROV_Z_WITH_KCLF
    if (loader_started) {
        ret = urov_kclf_exit();
        if (!ret) loader_started = 0;
    }
#endif
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
