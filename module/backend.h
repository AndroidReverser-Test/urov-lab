/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef UROV_Z_BACKEND_H
#define UROV_Z_BACKEND_H

#include "abi.h"

#ifndef UROV_Z_WITH_KCLF
#define UROV_Z_WITH_KCLF 1
#endif

struct uz_status {
    uint64_t hits;
    uint64_t replays;
    uint64_t failures;
    uint64_t llsc;
    uint32_t active;
    uint32_t armed;
    uint32_t hooks;
    uint32_t core_checks;
    uint32_t degraded;
    uint32_t fpsimd;      /* native FPSIMD helpers available */
    uint32_t overlay_len; /* page-0 overlay bytes, 0 when inactive */
    uint32_t abi;
    uint32_t page_count;  /* pages in the active session */
    uint32_t page_shift;  /* base page shift (12 or 14) */
    uint32_t caps;        /* UROV_Z_CAP_* */
    uint32_t experimental_writes;
    uint32_t native_ptl;  /* 1: apply-existing; 2: map-lock + RCU; 3: apply-checked */
    uint32_t contpte;     /* verified native contiguous-PTE unfolding helper */
    uint32_t readv_refs;  /* 0: unavailable; 1: GET; 2: PIN */
    uint32_t loader_enabled;
};

struct uz_perf {
    uint64_t loads, llsc_prepares, map_declines, scan_calls, scan_words;
    uint64_t insn_fetches, insn_nofault, identity_lookups, identity_compares;
    uint64_t single_page;
    uint64_t cache_hits, cache_misses, cache_invalidations, cache_bytes;
    uint64_t image_locks, image_contended, image_spins;
    uint64_t image_wait_max, image_hold_max, clock_hz;
    uint32_t enabled, code_valid, code_complete;
};

struct uz_health {
    uint64_t mmap_busy, fault_retries;
    uint64_t rearm_attempts, rearm_ok, rearm_busy, rearm_missing, rearm_rejected, rearm_identity;
    uint64_t retired_writes, readv_slots_full, gup_alloc_failures;
    int32_t last_rearm_error;
};

struct uz_memory {
    uint64_t limit, used, peak, denied;
    uint32_t page_buffers, shadow_slots, shadow_used, fork_copies;
};

struct uz_compat_info {
    const char *btf_source, *fault_entry, *remote_entry, *fast_entry, *fp_entry;
    uint32_t public_abi_strict, public_abi_fallback, public_abi_rejected;
    uint32_t foll_btf, foll_version, foll_unavailable;
    uint32_t foll_get, foll_pin, foll_longterm, foll_fast_only, foll_force;
    uint32_t fault_args, remote_args, loader_enabled;
};

/* Installs the PAGE_AP data-abort path and authenticated control channel.
 * Required argument: key=<32 hex digits>. Optional: verbose, max_pages=N,
 * max_kb=N, buffer_kb=N (overlay-owned buffer budget), fork_copies=0..4,
 * loader=on|off, writes=rx|experimental (default rx),
 * btf=/absolute/path/to/exact-build.uzbtf. */
long urov_z_backend_init(const char *args);
long urov_z_backend_exit(void);
long urov_z_status_get(struct uz_status *out);
long urov_z_set_writes(int experimental);
long urov_z_set_resources(const char *args);
long urov_z_perf_get(struct uz_perf *out);
long urov_z_health_get(struct uz_health *out);
long urov_z_memory_get(struct uz_memory *out);
long urov_z_compat_get(struct uz_compat_info *out);
int urov_z_loader_enabled(void);
long urov_z_copy_to_user(void *dst, const void *src, unsigned long len);

#endif
