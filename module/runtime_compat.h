/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef UROV_Z_RUNTIME_COMPAT_H
#define UROV_Z_RUNTIME_COMPAT_H

#include <stdint.h>

enum uz_remote_gup_entry {
    UZ_REMOTE_NONE, UZ_REMOTE_SHARED, UZ_REMOTE_PIN, UZ_REMOTE_GET
};

struct uz_remote_gup_choice {
    enum uz_remote_gup_entry entry;
    int argc, get_refs;
};

/* Arguments are zero unless both the symbol and its complete ABI exist.
 * PIN evidence includes symbols, BTF functions and a BTF FOLL_PIN flag.
 * In particular, a broken PIN ABI must never fall back to GET accounting. */
static inline struct uz_remote_gup_choice uz_remote_gup_select(int shared, int pin,
                                                              int get, int pin_evidence)
{
    struct uz_remote_gup_choice c = {UZ_REMOTE_NONE, 0, 0};
    if (pin_evidence) {
        if (shared) c = (struct uz_remote_gup_choice){UZ_REMOTE_SHARED, shared, 0};
        else if (pin) c = (struct uz_remote_gup_choice){UZ_REMOTE_PIN, pin, 0};
    } else if (get) {
        c = (struct uz_remote_gup_choice){shared ? UZ_REMOTE_SHARED : UZ_REMOTE_GET,
                                         shared ? shared : get, 1};
    }
    return c;
}

struct uz_page_allocator {
    void *(*policy)(unsigned gfp, unsigned order);
    void *(*node)(unsigned gfp, unsigned order, int nid, void *mask);
    void *(*first_online)(void);
    int node_id_offset;
};

static inline int uz_page_allocator_ready(const struct uz_page_allocator *a)
{
    return a->policy || (a->node && a->first_online && a->node_id_offset >= 0);
}

static inline void *uz_alloc_order0(const struct uz_page_allocator *a)
{
    void *pgdat;
    int nid;

    /* Zero GFP mask: nonblocking, no reclaim. This is not GFP_ATOMIC. */
    if (a->policy) return a->policy(0, 0);
    if (!uz_page_allocator_ready(a) || !(pgdat = a->first_online())) return 0;
    nid = __atomic_load_n((int *)((char *)pgdat + a->node_id_offset), __ATOMIC_RELAXED);
    return nid < 0 ? 0 : a->node(0, 0, nid, 0);
}

/* An AArch64 int return is in W0, without an X0 sign-extension guarantee.
 * Also bound a successful copy by the requested int length before touching
 * the destination of access_remote_vm / __access_remote_vm. */
static inline unsigned uz_access_vm_result(uint64_t result, uint64_t requested)
{
    int32_t copied = (int32_t)(uint32_t)result;
    int32_t count = (int32_t)(uint32_t)requested;

    return copied > 0 && count > 0 && copied <= count ? (unsigned)copied : 0;
}

#endif
